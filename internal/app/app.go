// Package app wires ingresses, the sticky balancer and backends into one process.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/LDPet/vpnpa/internal/atomicfile"
	"github.com/LDPet/vpnpa/internal/backend"
	"github.com/LDPet/vpnpa/internal/balance/sticky"
	"github.com/LDPet/vpnpa/internal/config"
	"github.com/LDPet/vpnpa/internal/ingress"

	_ "github.com/LDPet/vpnpa/internal/backend/amneziawg"
	_ "github.com/LDPet/vpnpa/internal/backend/socks5"
	_ "github.com/LDPet/vpnpa/internal/ingress/http"
	_ "github.com/LDPet/vpnpa/internal/ingress/socks5"
)

// Options controls one daemon process.
type Options struct {
	File       config.File
	ConfigPath string
	StateDir   string
	Logger     *slog.Logger
	// Signals enables SIGINT, SIGTERM and SIGHUP. Tests cancel ctx instead.
	Signals bool
}

// App is the running daemon.
type App struct {
	opt Options

	mu       sync.Mutex
	managed  map[string]*managed
	order    []backend.Backend
	balancer *sticky.Sticky
	pub      atomic.Pointer[published]
}

type published struct {
	listen string
	http   string
}

type managed struct {
	b   backend.Backend
	uri string
}

// New prepares an app. Call Run to start listeners.
func New(opt Options) *App {
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.DiscardHandler)
	}
	return &App{opt: opt, managed: map[string]*managed{}}
}

// Run brings every backend up, serves both ingresses and probes until ctx
// is done. SIGHUP reloads the config file without bouncing an unchanged backend.
func (a *App) Run(ctx context.Context) error {
	if err := a.boot(ctx); err != nil {
		return err
	}
	defer a.shutdown()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	a.mu.Lock()
	listen := a.opt.File.Listen
	httpListen := a.opt.File.HTTPListen
	balType := a.opt.File.Balancer.Type
	checkEvery := a.opt.File.Balancer.CheckInterval.Std().String()
	failN := a.opt.File.Balancer.FailThreshold
	recoverN := a.opt.File.Balancer.RecoverThreshold
	a.mu.Unlock()

	errCh := make(chan error, 3)
	go func() { errCh <- a.serve(runCtx, "socks5", listen) }()
	go func() { errCh <- a.serve(runCtx, "http", httpListen) }()
	go func() {
		a.balancer.Run(runCtx)
		errCh <- nil
	}()

	sigCh := make(chan os.Signal, 1)
	if a.opt.Signals {
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		defer signal.Stop(sigCh)
	}

	a.opt.Logger.Info("старт",
		"listen", listen,
		"http_listen", httpListen,
		"ingress", "socks5,http",
		"balancer", balType,
		"check_interval", checkEvery,
		"fail_threshold", failN,
		"recover_threshold", recoverN,
	)
	a.logBackends()

	for {
		select {
		case <-ctx.Done():
			cancel()
			a.opt.Logger.Info("остановка")
			return nil
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				if err := a.Reload(runCtx); err != nil {
					a.opt.Logger.Warn("ошибка перечитывания конфига", "err", err)
				}
			default:
				cancel()
				a.opt.Logger.Info("остановка")
				return nil
			}
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				cancel()
				return err
			}
		}
	}
}

func (a *App) boot(ctx context.Context) error {
	list, err := a.upAll(ctx, a.opt.File.Backends, nil)
	if err != nil {
		return err
	}
	a.order = list
	a.publish()
	a.balancer = sticky.New(list, a.stickyOptions())
	return nil
}

func (a *App) publish() {
	a.pub.Store(&published{listen: a.opt.File.Listen, http: a.opt.File.HTTPListen})
}

func (a *App) stickyOptions() sticky.Options {
	b := a.opt.File.Balancer
	return sticky.Options{
		CheckInterval:    b.CheckInterval.Std(),
		CheckTimeout:     b.CheckTimeout.Std(),
		FailThreshold:    b.FailThreshold,
		RecoverThreshold: b.RecoverThreshold,
		RestartInterval:  b.RestartInterval.Std(),
		CheckURLs:        append([]string(nil), b.CheckURLs...),
		EgressURL:        b.EgressURL,
		EgressInterval:   b.EgressInterval.Std(),
		PreferPath:       a.preferPath(),
		Logger:           a.opt.Logger,
		OnStatus:         a.writeStatus,
	}
}

func (a *App) serve(ctx context.Context, typ, addr string) error {
	in, err := ingress.New(typ, addr, a.opt.Logger)
	if err != nil {
		return err
	}
	return in.Serve(ctx, a.balancer)
}

// Reload rereads the config. A backend with the same id and uri is left running.
func (a *App) Reload(ctx context.Context) error {
	if a.opt.ConfigPath == "" {
		return fmt.Errorf("reload: config path is empty")
	}
	f, err := config.Load(a.opt.ConfigPath)
	if err != nil {
		return err
	}
	a.mu.Lock()
	list, err := a.upAll(ctx, f.Backends, a.managed)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	a.dropMissing(ctx, f.Backends)
	a.opt.File = f
	a.order = list
	a.publish()
	bal := a.balancer
	a.mu.Unlock()
	if bal != nil {
		bal.SetBackends(list)
	}
	a.opt.Logger.Info("конфиг перечитан")
	a.logBackends()
	return nil
}

func (a *App) upAll(ctx context.Context, specs []config.Backend, prev map[string]*managed) ([]backend.Backend, error) {
	var list []backend.Backend
	next := map[string]*managed{}
	for _, spec := range specs {
		if prev != nil {
			if old, ok := prev[spec.ID]; ok && old.uri == spec.URI {
				next[spec.ID] = old
				list = append(list, old.b)
				continue
			}
		}
		if prev != nil {
			if old, ok := prev[spec.ID]; ok {
				_ = old.b.Down(ctx)
				delete(prev, spec.ID)
			}
		}
		b, err := backend.New(backend.Config{
			ID:       spec.ID,
			Type:     spec.Type,
			Priority: spec.Priority,
			URI:      spec.URI,
		}, backend.Deps{Logger: a.opt.Logger, StateDir: a.opt.StateDir})
		if err != nil {
			return nil, fmt.Errorf("backend %s: %w", spec.ID, err)
		}
		if err := b.Up(ctx); err != nil {
			a.opt.Logger.Warn("ошибка поднятия бэкенда", "backend", spec.ID, "err", err)
		}
		next[spec.ID] = &managed{b: b, uri: spec.URI}
		list = append(list, b)
	}
	if prev == nil {
		a.managed = next
	} else {
		for id, m := range next {
			a.managed[id] = m
		}
	}
	return list, nil
}

func (a *App) dropMissing(ctx context.Context, specs []config.Backend) {
	keep := map[string]struct{}{}
	for _, spec := range specs {
		keep[spec.ID] = struct{}{}
	}
	for id, m := range a.managed {
		if _, ok := keep[id]; ok {
			continue
		}
		_ = m.b.Down(ctx)
		delete(a.managed, id)
	}
}

func (a *App) shutdown() {
	ctx := context.Background()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, m := range a.managed {
		_ = m.b.Down(ctx)
	}
}

func (a *App) logBackends() {
	a.mu.Lock()
	order := append([]backend.Backend(nil), a.order...)
	a.mu.Unlock()
	for _, b := range order {
		a.opt.Logger.Info("бэкенд", "backend", b.ID(), "priority", b.Priority(), "endpoint", backend.EndpointOf(b))
	}
}

func (a *App) writeStatus(st sticky.Status) {
	if a.opt.StateDir == "" {
		return
	}
	if p := a.pub.Load(); p != nil {
		st.Listen = p.listen
		st.HTTPListen = p.http
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	raw = append(raw, '\n')
	path := filepath.Join(a.opt.StateDir, "status.json")
	if err := atomicfile.Write(path, raw, 0o644); err != nil {
		a.opt.Logger.Warn("не записан status", "err", err)
	}
}

func (a *App) preferPath() string {
	if a.opt.StateDir == "" {
		return ""
	}
	return filepath.Join(a.opt.StateDir, "prefer")
}
