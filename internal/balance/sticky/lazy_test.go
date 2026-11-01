package sticky

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LDPet/vpnpa/internal/backend"
)

type lazyFake struct{ *fake }

func (*lazyFake) Lazy() bool { return true }

func TestLazyFailoverAndRecovery(t *testing.T) {
	ctx := context.Background()
	opt, _ := testOpts(t)
	opt.FailThreshold = 1
	opt.RecoverThreshold = 1
	main := &fake{id: "main", priority: 1}
	reserve := &lazyFake{&fake{id: "reserve", priority: 100}}
	s := New([]backend.Backend{main, reserve}, opt)
	s.ProbeNow(ctx)
	if got := s.Snapshot().Current; got != "main" {
		t.Fatalf("current = %q", got)
	}
	if reserve.upsN() != 0 || reserve.probeDialsN() != 0 {
		t.Fatal("idle reserve was activated")
	}
	main.mu.Lock()
	main.failProbe = true
	main.mu.Unlock()
	s.ProbeNow(ctx)
	if got := s.Snapshot().Current; got != "reserve" {
		t.Fatalf("failover = %q", got)
	}
	main.mu.Lock()
	main.failProbe = false
	main.mu.Unlock()
	s.ProbeNow(ctx)
	if got := s.Snapshot().Current; got != "main" {
		t.Fatalf("recovery = %q", got)
	}
	if reserve.downsN() != 1 {
		t.Fatalf("reserve downs = %d", reserve.downsN())
	}
	if !s.Snapshot().Backends[1].Waiting {
		t.Fatal("reserve is not waiting")
	}
}

func TestLazyTriesNextAndHonoursPrefer(t *testing.T) {
	ctx := context.Background()
	opt, _ := testOpts(t)
	opt.FailThreshold = 1
	opt.RecoverThreshold = 1
	opt.RestartInterval = time.Hour
	opt.PreferPath = filepath.Join(t.TempDir(), "prefer")
	main := &fake{id: "main", priority: 1, failProbe: true}
	broken := &lazyFake{&fake{id: "broken", priority: 100, failProbe: true}}
	good := &lazyFake{&fake{id: "good", priority: 50}}
	s := New([]backend.Backend{main, broken, good}, opt)
	s.ProbeNow(ctx)
	s.ProbeNow(ctx)
	if got := s.Snapshot().Current; got != "good" {
		t.Fatalf("current = %q", got)
	}
	main.mu.Lock()
	main.failProbe = false
	main.mu.Unlock()
	if err := os.WriteFile(opt.PreferPath, []byte("good"), 0600); err != nil {
		t.Fatal(err)
	}
	s.ProbeNow(ctx)
	if got := s.Snapshot().Current; got != "good" {
		t.Fatalf("preferred current = %q", got)
	}
	if err := os.WriteFile(opt.PreferPath, []byte("auto"), 0600); err != nil {
		t.Fatal(err)
	}
	s.ProbeNow(ctx)
	if got := s.Snapshot().Current; got != "main" {
		t.Fatalf("automatic current = %q", got)
	}
}

func TestLazyWaitsForNormalInitialThresholds(t *testing.T) {
	ctx := context.Background()
	opt, _ := testOpts(t)
	main := &fake{id: "main", priority: 1}
	reserve := &lazyFake{&fake{id: "reserve", priority: 100}}
	s := New([]backend.Backend{main, reserve}, opt)
	s.ProbeNow(ctx)
	if reserve.upsN() != 0 {
		t.Fatal("reserve started while normal recovery was undecided")
	}
	s.ProbeNow(ctx)
	if s.Snapshot().Current != "main" || reserve.upsN() != 0 {
		t.Fatalf("unexpected status: %+v", s.Snapshot())
	}
}

func TestLazyWaitsForAllNormalFailures(t *testing.T) {
	ctx := context.Background()
	opt, _ := testOpts(t)
	main := &fake{id: "main", priority: 1, failProbe: true}
	reserve := &lazyFake{&fake{id: "reserve", priority: 100}}
	s := New([]backend.Backend{main, reserve}, opt)
	s.ProbeNow(ctx)
	s.ProbeNow(ctx)
	if reserve.upsN() != 0 {
		t.Fatal("reserve started before normal fail threshold")
	}
	s.ProbeNow(ctx)
	if reserve.upsN() != 1 {
		t.Fatalf("reserve ups = %d", reserve.upsN())
	}
}

func TestLazyKeepsConnectionsOnNormalRecovery(t *testing.T) {
	ctx := context.Background()
	opt, _ := testOpts(t)
	opt.FailThreshold = 1
	opt.RecoverThreshold = 1
	main := &fake{id: "main", failProbe: true}
	reserve := &lazyFake{&fake{id: "reserve"}}
	s := New([]backend.Backend{main, reserve}, opt)
	s.ProbeNow(ctx)
	conn, err := s.DialContext(ctx, "tcp", "user.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	main.mu.Lock()
	main.failProbe = false
	main.mu.Unlock()
	s.ProbeNow(ctx)
	if reserve.downsN() != 0 {
		t.Fatal("reserve closed with an active connection")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if reserve.downsN() != 1 {
		t.Fatalf("downs after connection closed: %d", reserve.downsN())
	}
}

func TestPreferFailedLazyAllowsFallback(t *testing.T) {
	ctx := context.Background()
	opt, _ := testOpts(t)
	opt.FailThreshold = 1
	opt.RecoverThreshold = 1
	opt.PreferPath = filepath.Join(t.TempDir(), "prefer")
	if err := os.WriteFile(opt.PreferPath, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	main := &fake{id: "main", failProbe: true}
	broken := &lazyFake{&fake{id: "broken", priority: 100, failProbe: true}}
	good := &lazyFake{&fake{id: "good", priority: 1}}
	s := New([]backend.Backend{main, broken, good}, opt)
	s.ProbeNow(ctx)
	s.ProbeNow(ctx)
	if got := s.Snapshot().Current; got != "good" {
		t.Fatalf("fallback = %q", got)
	}
}

func TestLazyReplacementDoesNotInheritHealth(t *testing.T) {
	ctx := context.Background()
	opt, _ := testOpts(t)
	opt.FailThreshold = 1
	opt.RecoverThreshold = 1
	first := &lazyFake{&fake{id: "reserve"}}
	s := New([]backend.Backend{first}, opt)
	s.ProbeNow(ctx)
	replacement := &lazyFake{&fake{id: "reserve"}}
	s.SetBackends([]backend.Backend{replacement})
	if s.Snapshot().Current != "" {
		t.Fatal("unstarted replacement selected")
	}
	s.ProbeNow(ctx)
	if replacement.upsN() != 1 || s.Snapshot().Current != "reserve" {
		t.Fatal("replacement was not activated")
	}
}

type writeHalfConn struct {
	net.Conn
	called bool
}

func (c *writeHalfConn) CloseWrite() error { c.called = true; return nil }

type halfCloseBackend struct {
	*lazyFake
	conn *writeHalfConn
}

func (b *halfCloseBackend) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if addr == probeAddr {
		return b.fake.DialContext(ctx, network, addr)
	}
	a, other := net.Pipe()
	_ = other.Close()
	b.conn = &writeHalfConn{Conn: a}
	return b.conn, nil
}
func TestLazyPreservesCloseWrite(t *testing.T) {
	ctx := context.Background()
	opt, _ := testOpts(t)
	opt.RecoverThreshold = 1
	b := &halfCloseBackend{lazyFake: &lazyFake{&fake{id: "lazy"}}}
	s := New([]backend.Backend{b}, opt)
	s.ProbeNow(ctx)
	c, err := s.DialContext(ctx, "tcp", "user.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	half, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("CloseWrite was lost")
	}
	if err := half.CloseWrite(); err != nil || !b.conn.called {
		t.Fatalf("CloseWrite was not forwarded: %v", err)
	}
}
func TestNormalPartialRecoveryDoesNotBlockNextReserve(t *testing.T) {
	ctx := context.Background()
	opt, _ := testOpts(t)
	opt.FailThreshold = 1
	opt.RecoverThreshold = 2
	main := &fake{id: "main", failProbe: true}
	first := &lazyFake{&fake{id: "first", priority: 2, failProbe: true}}
	second := &lazyFake{&fake{id: "second", priority: 1}}
	s := New([]backend.Backend{main, first, second}, opt)
	s.ProbeNow(ctx)
	main.mu.Lock()
	main.failProbe = false
	main.mu.Unlock()
	s.ProbeNow(ctx)
	if second.upsN() != 1 {
		t.Fatal("partial normal recovery blocked next reserve")
	}
}
func TestPreferredRetryDoesNotDropWorkingReserve(t *testing.T) {
	ctx := context.Background()
	opt, _ := testOpts(t)
	opt.FailThreshold = 1
	opt.RecoverThreshold = 1
	now := time.Now()
	opt.Now = func() time.Time { return now }
	opt.PreferPath = filepath.Join(t.TempDir(), "prefer")
	if err := os.WriteFile(opt.PreferPath, []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	bad := &lazyFake{&fake{id: "bad", priority: 2, failProbe: true}}
	good := &lazyFake{&fake{id: "good", priority: 1}}
	s := New([]backend.Backend{bad, good}, opt)
	s.ProbeNow(ctx)
	s.ProbeNow(ctx)
	if s.Snapshot().Current != "good" {
		t.Fatal("no fallback")
	}
	now = now.Add(opt.RestartInterval)
	s.ProbeNow(ctx)
	if s.Snapshot().Current != "good" || good.downsN() != 0 {
		t.Fatal("working reserve lost while preferred was retried")
	}
	s.ProbeNow(ctx)
	if s.Snapshot().Current != "good" || good.downsN() != 0 {
		t.Fatal("working reserve lost after preferred failed")
	}
}

type blockedModeBackend struct {
	*fake
	lazy    atomic.Bool
	started chan struct{}
	unblock chan struct{}
}

func (b *blockedModeBackend) Lazy() bool { return b.lazy.Load() }
func (b *blockedModeBackend) Up(ctx context.Context) error {
	close(b.started)
	<-b.unblock
	return b.fake.Up(ctx)
}
func TestRemovedBackendDoesNotRemainUpAfterModeTransition(t *testing.T) {
	ctx := context.Background()
	opt, _ := testOpts(t)
	opt.RecoverThreshold = 1
	b := &blockedModeBackend{fake: &fake{id: "changing"}, started: make(chan struct{}), unblock: make(chan struct{})}
	b.lazy.Store(true)
	s := New([]backend.Backend{b}, opt)
	b.lazy.Store(false)
	done := make(chan struct{})
	go func() { s.ProbeNow(ctx); close(done) }()
	<-b.started
	s.SetBackends(nil)
	close(b.unblock)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("probe did not finish")
	}
	if b.upsN() != 1 || b.downsN() != 1 {
		t.Fatalf("stale backend lifecycle: ups=%d downs=%d", b.upsN(), b.downsN())
	}
}
