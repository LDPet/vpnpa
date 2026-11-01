package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LDPet/vpnpa/internal/backend"
	"github.com/LDPet/vpnpa/internal/balance/sticky"
	"github.com/LDPet/vpnpa/internal/config"
)

type fakeBE struct {
	id    string
	prio  int
	mu    sync.Mutex
	ups   int
	downs int
}

func (f *fakeBE) ID() string    { return f.id }
func (f *fakeBE) Priority() int { return f.prio }
func (f *fakeBE) Up(context.Context) error {
	f.mu.Lock()
	f.ups++
	f.mu.Unlock()
	return nil
}
func (f *fakeBE) Down(context.Context) error {
	f.mu.Lock()
	f.downs++
	f.mu.Unlock()
	return nil
}
func (f *fakeBE) DialContext(context.Context, string, string) (net.Conn, error) {
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}

func (f *fakeBE) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ups, f.downs
}

// Три теста reload остаются последовательными: они подменяют общий
// backend.Register("fake") и срез config.KnownTypes. Отдельная фабрика
// на тест потребовала бы другого реестра, то есть смены поведения.
func TestReloadDoesNotBounceUnchangedBackend(t *testing.T) {
	var mu sync.Mutex
	made := map[string]*fakeBE{}
	backend.Register("fake", func(cfg backend.Config, _ backend.Deps) (backend.Backend, error) {
		f := &fakeBE{id: cfg.ID, prio: cfg.Priority}
		mu.Lock()
		made[cfg.URI] = f
		mu.Unlock()
		return f, nil
	})
	prev := config.KnownTypes.Backends
	config.KnownTypes.Backends = append(append([]string{}, prev...), "fake")
	t.Cleanup(func() { config.KnownTypes.Backends = prev })

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	state := filepath.Join(dir, "state")
	socks := freeAddr(t)
	httpAddr := freeAddr(t)
	body := "listen: " + socks + "\nhttp_listen: " + httpAddr + "\nbalancer:\n  type: sticky\n  check_interval: 1h\n  check_timeout: 1s\n  fail_threshold: 3\n  recover_threshold: 1\n  restart_interval: 1h\n  check_urls:\n    - tcp://probe.invalid:9\nbackends:\n  - id: vpn-1\n    type: fake\n    priority: 100\n    uri: fake://same\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	a := New(Options{File: f, ConfigPath: cfgPath, StateDir: state, Signals: false})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- a.Run(ctx) }()
	waitListen(t, socks)

	mu.Lock()
	first := made["fake://same"]
	mu.Unlock()
	ups, downs := first.counts()
	if ups != 1 || downs != 0 {
		t.Fatalf("initial ups=%d downs=%d", ups, downs)
	}
	if err := a.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	ups, downs = first.counts()
	if ups != 1 || downs != 0 {
		t.Fatalf("unchanged backend bounced ups=%d downs=%d", ups, downs)
	}

	changed := "listen: " + socks + "\nhttp_listen: " + httpAddr + "\nbalancer:\n  type: sticky\n  check_interval: 1h\n  check_timeout: 1s\n  fail_threshold: 3\n  recover_threshold: 1\n  restart_interval: 1h\n  check_urls:\n    - tcp://probe.invalid:9\nbackends:\n  - id: vpn-1\n    type: fake\n    priority: 100\n    uri: fake://other\n"
	if err := os.WriteFile(cfgPath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, downs = first.counts()
	if downs != 1 {
		t.Fatalf("old backend downs=%d", downs)
	}
	mu.Lock()
	second := made["fake://other"]
	mu.Unlock()
	ups, _ = second.counts()
	if ups != 1 {
		t.Fatalf("new backend ups=%d", ups)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop")
	}
}

func TestReloadKeepsSelectionAndStopsRemoved(t *testing.T) {
	var mu sync.Mutex
	made := map[string]*fakeBE{}
	backend.Register("fake", func(cfg backend.Config, _ backend.Deps) (backend.Backend, error) {
		f := &fakeBE{id: cfg.ID, prio: cfg.Priority}
		mu.Lock()
		made[cfg.URI] = f
		mu.Unlock()
		return f, nil
	})
	prev := config.KnownTypes.Backends
	config.KnownTypes.Backends = append(append([]string{}, prev...), "fake")
	t.Cleanup(func() { config.KnownTypes.Backends = prev })

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	state := filepath.Join(dir, "state")
	socks := freeAddr(t)
	httpAddr := freeAddr(t)
	write := func(backends string) {
		t.Helper()
		body := yamlBackends(socks, httpAddr, backends)
		if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("  - id: vpn-1\n    type: fake\n    priority: 100\n    uri: fake://same\n")
	f, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	a := New(Options{File: f, ConfigPath: cfgPath, StateDir: state, Signals: false})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- a.Run(ctx) }()
	waitListen(t, socks)
	waitStatus(t, filepath.Join(state, "status.json"), `"current": "vpn-1"`)

	mu.Lock()
	first := made["fake://same"]
	mu.Unlock()
	write("  - id: vpn-1\n    type: fake\n    priority: 50\n    uri: fake://same\n  - id: vpn-2\n    type: fake\n    priority: 40\n    uri: fake://new\n")
	if err := a.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	ups, downs := first.counts()
	if ups != 1 || downs != 0 {
		t.Fatalf("unchanged backend bounced ups=%d downs=%d", ups, downs)
	}
	mu.Lock()
	second := made["fake://new"]
	mu.Unlock()
	ups, downs = second.counts()
	if ups != 1 || downs != 0 {
		t.Fatalf("new backend ups=%d downs=%d", ups, downs)
	}
	waitStatus(t, filepath.Join(state, "status.json"), `"current": "vpn-1"`)
	raw, err := os.ReadFile(filepath.Join(state, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"priority": 50`) {
		t.Fatalf("priority not applied: %s", raw)
	}

	write("  - id: vpn-2\n    type: fake\n    priority: 40\n    uri: fake://new\n")
	if err := a.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, downs = first.counts()
	if downs != 1 {
		t.Fatalf("removed backend downs=%d", downs)
	}
	ups, downs = second.counts()
	if ups != 1 || downs != 0 {
		t.Fatalf("kept backend bounced ups=%d downs=%d", ups, downs)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop")
	}
}

func TestReloadFailureKeepsOldBackend(t *testing.T) {
	var mu sync.Mutex
	made := map[string]*fakeBE{}
	backend.Register("fake", func(cfg backend.Config, _ backend.Deps) (backend.Backend, error) {
		if strings.HasSuffix(cfg.URI, "bad") {
			return nil, errors.New("refuse")
		}
		f := &fakeBE{id: cfg.ID, prio: cfg.Priority}
		mu.Lock()
		made[cfg.URI] = f
		mu.Unlock()
		return f, nil
	})
	prev := config.KnownTypes.Backends
	config.KnownTypes.Backends = append(append([]string{}, prev...), "fake")
	t.Cleanup(func() { config.KnownTypes.Backends = prev })

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	state := filepath.Join(dir, "state")
	socks := freeAddr(t)
	httpAddr := freeAddr(t)
	body := yamlBackends(socks, httpAddr, "  - id: vpn-1\n    type: fake\n    priority: 100\n    uri: fake://same\n")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	a := New(Options{File: f, ConfigPath: cfgPath, StateDir: state, Signals: false})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- a.Run(ctx) }()
	waitListen(t, socks)

	bad := yamlBackends(socks, httpAddr, "  - id: vpn-2\n    type: fake\n    priority: 90\n    uri: fake://new\n  - id: vpn-1\n    type: fake\n    priority: 100\n    uri: fake://bad\n")
	if err := os.WriteFile(cfgPath, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Reload(context.Background()); err == nil || strings.Contains(err.Error(), "fake://") {
		t.Fatalf("reload: %v", err)
	}
	mu.Lock()
	first := made["fake://same"]
	newer := made["fake://new"]
	mu.Unlock()
	ups, downs := first.counts()
	if ups != 1 || downs != 0 {
		t.Fatalf("old backend ups=%d downs=%d", ups, downs)
	}
	ups, downs = newer.counts()
	if ups != 1 || downs != 1 {
		t.Fatalf("rolled back backend ups=%d downs=%d", ups, downs)
	}
	waitStatus(t, filepath.Join(state, "status.json"), `"current": "vpn-1"`)
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop")
	}
}

func TestRunReleasesListeners(t *testing.T) {
	t.Parallel()
	socks := freeAddr(t)
	httpAddr := freeAddr(t)
	body := "listen: " + socks + "\nhttp_listen: " + httpAddr + "\nbackends: []\n"
	f, err := config.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	a := New(Options{File: f, Signals: false})
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- a.Run(ctx) }()
	waitListen(t, socks)
	waitListen(t, httpAddr)
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop")
	}
	for _, addr := range []string{socks, httpAddr} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("port %s still held: %v", addr, err)
		}
		_ = ln.Close()
	}
}

func yamlBackends(socks, httpAddr, backends string) string {
	return "listen: " + socks + "\nhttp_listen: " + httpAddr + "\nbalancer:\n  type: sticky\n  check_interval: 1h\n  check_timeout: 1s\n  fail_threshold: 3\n  recover_threshold: 1\n  restart_interval: 1h\n  check_urls:\n    - tcp://probe.invalid:9\nbackends:\n" + backends
}

func waitStatus(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var raw []byte
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path) // #nosec G304 -- тестовый путь
		if err == nil && strings.Contains(string(b), want) {
			return
		}
		raw = b
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("status %q missing %q", raw, want)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func waitListen(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("not listening on %s", addr)
}

func TestReloadPreservesUnchangedLazyState(t *testing.T) {
	backend.Register("lazy-reload-test", func(cfg backend.Config, _ backend.Deps) (backend.Backend, error) {
		return &fakeBE{id: cfg.ID, prio: cfg.Priority}, nil
	})
	ctx := context.Background()
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprintf("active=%v", active), func(t *testing.T) {
			a := New(Options{})
			specs := []config.Backend{{ID: "reserve", Type: "lazy-reload-test", URI: "fake://reserve", Priority: 10, Lazy: true}}
			list, err := a.upAll(ctx, specs, nil)
			if err != nil {
				t.Fatal(err)
			}
			a.balancer = sticky.New(list, sticky.Options{CheckURLs: []string{"tcp://probe.invalid:9"}, RecoverThreshold: 1})
			first := a.managed["reserve"].tr.inner.(*fakeBE)
			if active {
				a.balancer.ProbeNow(ctx)
			}
			ups, downs := first.counts()
			if (active && ups != 1) || (!active && ups != 0) || downs != 0 {
				t.Fatalf("initial: %d %d", ups, downs)
			}
			list, err = a.upAll(ctx, specs, a.managed)
			if err != nil {
				t.Fatal(err)
			}
			a.balancer.SetBackends(list)
			afterUp, afterDown := first.counts()
			if afterUp != ups || afterDown != downs {
				t.Fatalf("unchanged reserve bounced: %d %d", afterUp, afterDown)
			}
			if active && a.balancer.Snapshot().Current != "reserve" {
				t.Fatal("active reserve selection lost")
			}
			if !active && !a.balancer.Snapshot().Backends[0].Waiting {
				t.Fatal("idle reserve no longer waiting")
			}
		})
	}
}

func TestReloadLazyFlagKeepsBackendInstance(t *testing.T) {
	backend.Register("lazy-toggle-test", func(cfg backend.Config, _ backend.Deps) (backend.Backend, error) { return &fakeBE{id: cfg.ID}, nil })
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprintf("active=%v", active), func(t *testing.T) {
			ctx := context.Background()
			a := New(Options{})
			specs := []config.Backend{{ID: "reserve", Type: "lazy-toggle-test", URI: "fake://reserve", Lazy: true}}
			list, err := a.upAll(ctx, specs, nil)
			if err != nil {
				t.Fatal(err)
			}
			a.balancer = sticky.New(list, sticky.Options{CheckURLs: []string{"tcp://probe.invalid:9"}, RecoverThreshold: 1})
			tr := a.managed["reserve"].tr
			be := tr.inner.(*fakeBE)
			if active {
				a.balancer.ProbeNow(ctx)
			}
			beforeUp, beforeDown := be.counts()
			specs[0].Lazy = false
			list, err = a.upAll(ctx, specs, a.managed)
			if err != nil {
				t.Fatal(err)
			}
			a.balancer.SetBackends(list)
			afterUp, afterDown := be.counts()
			if tr != a.managed["reserve"].tr || beforeUp != afterUp || beforeDown != afterDown {
				t.Fatal("flag change replaced or bounced backend")
			}
			a.balancer.ProbeNow(ctx)
			afterUp, afterDown = be.counts()
			if afterUp != 1 || afterDown != 0 {
				t.Fatalf("mode transition: ups=%d downs=%d", afterUp, afterDown)
			}
		})
	}
}

func TestReloadOrdinaryToLazyPreservesOpenConnection(t *testing.T) {
	backend.Register("lazy-drain-test", func(cfg backend.Config, _ backend.Deps) (backend.Backend, error) {
		return &fakeBE{id: cfg.ID, prio: cfg.Priority}, nil
	})
	ctx := context.Background()
	a := New(Options{})
	specs := []config.Backend{{ID: "first", Type: "lazy-drain-test", URI: "fake://first", Priority: 10}, {ID: "second", Type: "lazy-drain-test", URI: "fake://second", Priority: 1}}
	list, err := a.upAll(ctx, specs, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.balancer = sticky.New(list, sticky.Options{CheckURLs: []string{"tcp://probe.invalid:9"}, RecoverThreshold: 1})
	a.balancer.ProbeNow(ctx)
	first := a.managed["first"].tr.inner.(*fakeBE)
	c, err := a.balancer.DialContext(ctx, "tcp", "user.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	specs[0].Lazy = true
	list, err = a.upAll(ctx, specs, a.managed)
	if err != nil {
		t.Fatal(err)
	}
	a.balancer.SetBackends(list)
	a.balancer.ProbeNow(ctx)
	if a.balancer.Snapshot().Current != "second" {
		t.Fatal("ordinary replacement was not selected")
	}
	_, downs := first.counts()
	if downs != 0 {
		t.Fatal("lazy transition closed backend with active connection")
	}
	_ = c.Close()
	_, downs = first.counts()
	if downs != 1 {
		t.Fatalf("backend downs after close: %d", downs)
	}
}

type blockingReloadBE struct {
	*fakeBE
	started chan struct{}
	unblock chan struct{}
}

func (b *blockingReloadBE) Up(ctx context.Context) error {
	close(b.started)
	<-b.unblock
	return b.fakeBE.Up(ctx)
}
func TestReloadWaitsForInFlightModeStart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	b := &blockingReloadBE{fakeBE: &fakeBE{id: "reserve"}, started: make(chan struct{}), unblock: make(chan struct{})}
	backend.Register("blocking-reload-test", func(backend.Config, backend.Deps) (backend.Backend, error) { return b, nil })
	prev := config.KnownTypes.Backends
	config.KnownTypes.Backends = append(append([]string{}, prev...), "blocking-reload-test")
	t.Cleanup(func() { config.KnownTypes.Backends = prev })
	a := New(Options{ConfigPath: cfgPath})
	specs := []config.Backend{{ID: "reserve", Type: "blocking-reload-test", URI: "fake://reserve", Lazy: true}}
	list, err := a.upAll(ctx, specs, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.balancer = sticky.New(list, sticky.Options{CheckURLs: []string{"tcp://probe.invalid:9"}, RecoverThreshold: 1})
	a.managed["reserve"].tr.setLazy(false)
	if err := os.WriteFile(cfgPath, []byte(yamlBackends("127.0.0.1:1080", "127.0.0.1:8080", "")), 0600); err != nil {
		t.Fatal(err)
	}
	doneCycle := make(chan struct{})
	go func() { a.balancer.ProbeNow(ctx); close(doneCycle) }()
	<-b.started
	doneReload := make(chan error, 1)
	go func() { doneReload <- a.Reload(ctx) }()
	select {
	case err := <-doneReload:
		t.Fatalf("reload returned during Up: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(b.unblock)
	select {
	case <-doneCycle:
	case <-time.After(time.Second):
		t.Fatal("cycle stuck")
	}
	select {
	case err := <-doneReload:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("reload stuck")
	}
	ups, downs := b.counts()
	if ups != 1 || downs != 1 {
		t.Fatalf("lifecycle after remove: ups=%d downs=%d", ups, downs)
	}
}
