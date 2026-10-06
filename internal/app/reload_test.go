package app

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/LDPet/vpnpa/internal/backend"
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
