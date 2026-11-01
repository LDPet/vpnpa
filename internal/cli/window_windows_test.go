//go:build windows

package cli

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LDPet/vpnpa/internal/backend"
	"github.com/LDPet/vpnpa/internal/config"
	"github.com/LDPet/vpnpa/internal/paths"
)

type blockingBackend struct {
	id      string
	start   chan struct{}
	release chan struct{}
	created *atomic.Int32
}

func (b *blockingBackend) ID() string    { return b.id }
func (b *blockingBackend) Priority() int { return 100 }
func (b *blockingBackend) Up(ctx context.Context) error {
	if b.id == "first" {
		close(b.start)
		select {
		case <-b.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	b.created.Add(1)
	return nil
}
func (b *blockingBackend) Down(context.Context) error { return nil }
func (b *blockingBackend) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, context.Canceled
}

func TestReloadWaitsForInitialBoot(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var created atomic.Int32
	backend.Register("window-test", func(c backend.Config, _ backend.Deps) (backend.Backend, error) {
		return &blockingBackend{id: c.ID, start: started, release: release, created: &created}, nil
	})
	old := config.KnownTypes.Backends
	config.KnownTypes.Backends = append(append([]string{}, old...), "window-test")
	defer func() { config.KnownTypes.Backends = old }()
	root := t.TempDir()
	layout := paths.Layout{ConfigPath: filepath.Join(root, "config.yaml"), StateDir: filepath.Join(root, "state")}
	if err := os.MkdirAll(layout.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := config.InstallConfig(layout.ConfigPath); err != nil {
		t.Fatal(err)
	}
	f, err := config.Load(layout.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = l1.Close()
		t.Fatal(err)
	}
	f.Listen, f.HTTPListen = l1.Addr().String(), l2.Addr().String()
	_ = l1.Close()
	_ = l2.Close()
	f.Backends = []config.Backend{{ID: "first", Type: "window-test", Priority: 100, URI: "test://first"}}
	if err = config.Save(layout.ConfigPath, f); err != nil {
		t.Fatal(err)
	}
	s := newSession(layout, nil)
	if err = s.up(); err != nil {
		t.Fatal(err)
	}
	defer s.down()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("boot did not start")
	}
	f.Backends = append(f.Backends, config.Backend{ID: "second", Type: "window-test", Priority: 90, URI: "test://second"})
	if err = config.Save(layout.ConfigPath, f); err != nil {
		close(release)
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.reloadConfig() }()
	select {
	case err := <-done:
		close(release)
		t.Fatalf("reload returned before boot: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not finish")
	}
	if n := created.Load(); n != 2 {
		t.Fatalf("created %d backends, expected 2", n)
	}
}

func TestDownCancelsBeforeWaitingForReload(t *testing.T) {
	s := newSession(paths.Layout{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.op.Lock()
	done := make(chan struct{})
	go func() { s.down(); close(done) }()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		s.op.Unlock()
		t.Fatal("down did not cancel the running operation")
	}
	s.op.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("down did not finish")
	}
}
