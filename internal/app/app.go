// Package app собирает входы, sticky-балансировщик и бэкенды в один процесс.
//
// SIGHUP перечитывает конфиг. Бэкенд с тем же id и тем же URI не получает
// Down/Up: балансировщик держит тот же указатель, здоровье и текущий выбор
// переживают перезагрузку. Смена URI подменяет внутренность, не указатель.
// Удаление id из файла останавливает бэкенд.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
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

	// Пустой импорт вызывает init и регистрирует фабрики. Без этих строк
	// backend.New и ingress.New не знают типов. app.New реестр не смотрит.
	_ "github.com/LDPet/vpnpa/internal/backend/amneziawg"
	_ "github.com/LDPet/vpnpa/internal/backend/socks5"
	_ "github.com/LDPet/vpnpa/internal/ingress/http"
	_ "github.com/LDPet/vpnpa/internal/ingress/socks5"
)

// Options задаёт один процесс демона.
type Options struct {
	File       config.File
	ConfigPath string
	// StateDir — каталог status.json, prefer и ключей API. Пустой путь
	// отключает запись статуса и переиспользование ключей.
	StateDir string
	Logger   *slog.Logger
	// Signals включает SIGINT, SIGTERM и SIGHUP. Тесты вместо этого отменяют ctx.
	Signals bool
}

// App — работающий демон: два входа, один балансировщик и набор бэкендов.
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
	tr  *tracked
	uri string
	typ string
}

// tracked — объект, который держит балансировщик. Указатель на него живёт,
// пока id есть в конфиге, поэтому здоровье и текущий выбор переживают SIGHUP.
// Приоритет меняется на месте. Новый URI подменяет inner через swap
// (старый Down, новый уже поднят). Неизменный URI не получает ни Down, ни Up.
type tracked struct {
	id string

	mu    sync.RWMutex
	inner backend.Backend
	prio  int
}

func newTracked(id string, prio int, inner backend.Backend) *tracked {
	return &tracked{id: id, inner: inner, prio: prio}
}

func (t *tracked) ID() string { return t.id }

func (t *tracked) Priority() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.prio
}

func (t *tracked) setPriority(p int) {
	t.mu.Lock()
	t.prio = p
	t.mu.Unlock()
}

func (t *tracked) Up(ctx context.Context) error {
	t.mu.RLock()
	b := t.inner
	t.mu.RUnlock()
	return b.Up(ctx)
}

func (t *tracked) Down(ctx context.Context) error {
	t.mu.RLock()
	b := t.inner
	t.mu.RUnlock()
	return b.Down(ctx)
}

func (t *tracked) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	t.mu.RLock()
	b := t.inner
	t.mu.RUnlock()
	return b.DialContext(ctx, network, address)
}

func (t *tracked) Endpoint() string {
	t.mu.RLock()
	b := t.inner
	t.mu.RUnlock()
	return backend.EndpointOf(b)
}

var _ backend.Backend = (*tracked)(nil)

// swap подменяет туннель внутри того же указателя. Dial либо ещё на старом
// inner, либо уже на новом: оба захвата под одним мьютексом. Старый гасится
// после публикации нового, чтобы не было окна без устройства у текущего id.
func (t *tracked) swap(ctx context.Context, next backend.Backend) {
	t.mu.Lock()
	old := t.inner
	t.inner = next
	t.mu.Unlock()
	if old != nil && old != next {
		_ = old.Down(ctx)
	}
}

// New готовит приложение. Слушатели и бэкенды поднимает Run.
func New(opt Options) *App {
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.DiscardHandler)
	}
	return &App{opt: opt, managed: map[string]*managed{}}
}

// Run поднимает бэкенды, слушает SOCKS5 и HTTP CONNECT и гоняет пробы, пока
// ctx не закончится. SIGINT и SIGTERM останавливают процесс. SIGHUP вызывает
// Reload: неизменный бэкенд не переподнимается.
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
	var wg sync.WaitGroup
	start := func(fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- fn()
		}()
	}
	start(func() error { return a.serve(runCtx, "socks5", listen) })
	start(func() error { return a.serve(runCtx, "http", httpListen) })
	start(func() error {
		a.balancer.Run(runCtx)
		return nil
	})

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

	var runErr error
loop:
	for {
		select {
		case <-ctx.Done():
			a.opt.Logger.Info("остановка")
			break loop
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				if err := a.Reload(runCtx); err != nil {
					a.opt.Logger.Warn("ошибка перечитывания конфига", "err", err)
				}
			default:
				a.opt.Logger.Info("остановка")
				break loop
			}
		case err := <-errCh:
			if err == nil || errors.Is(err, context.Canceled) {
				if ctx.Err() != nil || runCtx.Err() != nil {
					continue
				}
			}
			runErr = err
			break loop
		}
	}
	cancel()
	wg.Wait()
	return runErr
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

// Reload перечитывает файл конфига.
// Тот же id и тот же URI остаются поднятыми. Тот же id с другим URI получает
// новый inner, указатель для балансировщика не меняется. id, которого больше
// нет в файле, останавливается. Ошибка разбора файла не трогает уже работающее:
// upAll при ошибке создания гасит только то, что успел поднять в этой попытке.
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

// upAll приводит набор бэкендов к specs.
// Совпадение id, URI и типа — оставить tracked, обновить только приоритет.
// Совпадение id при другом URI — поднять новый и swap в старый tracked.
// Новый id — новый tracked, у sticky он начинает с alive=false.
// Смена URI оставляет тот же указатель, поэтому прежнее alive не сбрасывается,
// даже если Up нового inner не удался. Ошибка Up только логируется, бэкенд
// остаётся в списке. Неудачная проба переводит в неживые лишь уже живой id.
// Удачные пробы до порога восстановления делают новый id живым.
// Ошибка New откатывает уже поднятые в этой попытке.
func (a *App) upAll(ctx context.Context, specs []config.Backend, prev map[string]*managed) ([]backend.Backend, error) {
	type item struct {
		spec  config.Backend
		keep  *tracked
		fresh backend.Backend
	}
	items := make([]item, 0, len(specs))
	var fresh []backend.Backend
	abort := func(err error) ([]backend.Backend, error) {
		for _, b := range fresh {
			_ = b.Down(ctx)
		}
		return nil, err
	}
	for _, spec := range specs {
		if prev != nil {
			if old, ok := prev[spec.ID]; ok && old.uri == spec.URI && old.typ == spec.Type {
				items = append(items, item{spec: spec, keep: old.tr})
				continue
			}
		}
		b, err := backend.New(backend.Config{
			ID:       spec.ID,
			Type:     spec.Type,
			Priority: spec.Priority,
			URI:      spec.URI,
		}, backend.Deps{Logger: a.opt.Logger, StateDir: a.opt.StateDir})
		if err != nil {
			return abort(fmt.Errorf("backend %s: %w", spec.ID, err))
		}
		if err := b.Up(ctx); err != nil {
			a.opt.Logger.Warn("ошибка поднятия бэкенда", "backend", spec.ID, "err", err)
		}
		fresh = append(fresh, b)
		items = append(items, item{spec: spec, fresh: b})
	}

	next := make(map[string]*managed, len(items))
	list := make([]backend.Backend, 0, len(items))
	for _, it := range items {
		if it.keep != nil {
			it.keep.setPriority(it.spec.Priority)
			next[it.spec.ID] = &managed{tr: it.keep, uri: it.spec.URI, typ: it.spec.Type}
			list = append(list, it.keep)
			continue
		}
		var tr *tracked
		if prev != nil {
			if old, ok := prev[it.spec.ID]; ok {
				tr = old.tr
				tr.setPriority(it.spec.Priority)
				tr.swap(ctx, it.fresh)
			}
		}
		if tr == nil {
			tr = newTracked(it.spec.ID, it.spec.Priority, it.fresh)
		}
		next[it.spec.ID] = &managed{tr: tr, uri: it.spec.URI, typ: it.spec.Type}
		list = append(list, tr)
	}
	if prev == nil {
		a.managed = next
	} else {
		for id, m := range next {
			prev[id] = m
		}
	}
	return list, nil
}

// dropMissing останавливает id, которых нет в новом файле, и убирает их
// из карты. Балансировщик получит укороченный список отдельно, через SetBackends.
func (a *App) dropMissing(ctx context.Context, specs []config.Backend) {
	keep := map[string]struct{}{}
	for _, spec := range specs {
		keep[spec.ID] = struct{}{}
	}
	for id, m := range a.managed {
		if _, ok := keep[id]; ok {
			continue
		}
		_ = m.tr.Down(ctx)
		delete(a.managed, id)
	}
}

func (a *App) shutdown() {
	ctx := context.Background()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, m := range a.managed {
		_ = m.tr.Down(ctx)
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

// writeStatus атомарно переписывает status.json. Обрыв не должен оставить
// обрезанный файл, который `vpnpa status` прочитает как состояние.
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
	if err := atomicfile.Write(path, raw, 0o600); err != nil {
		a.opt.Logger.Warn("не записан status", "err", err)
	}
}

func (a *App) preferPath() string {
	if a.opt.StateDir == "" {
		return ""
	}
	return filepath.Join(a.opt.StateDir, "prefer")
}
