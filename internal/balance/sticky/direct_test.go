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

type blockingProbe struct {
	*fake
	entered chan struct{}
}

type blockingLazyStart struct {
	*lazyFake
	starts  atomic.Int32
	entered chan struct{}
}

type cancelledStart struct {
	*fake
	starts  atomic.Int32
	entered chan struct{}
}

func (b *cancelledStart) Up(ctx context.Context) error {
	if b.starts.Add(1) == 1 {
		close(b.entered)
		<-ctx.Done()
		return ctx.Err()
	}
	return b.fake.Up(ctx)
}

func TestCancelledOrdinaryStartCanRetry(t *testing.T) {
	opt, _ := testOpts(t)
	b := &cancelledStart{fake: &fake{id: "ordinary"}, entered: make(chan struct{})}
	s := New([]backend.Backend{b}, opt)
	s.health[b.ID()].lazy = true
	s.health[b.ID()].active = false
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.syncModes(ctx) }()
	select {
	case <-b.entered:
	case <-time.After(time.Second):
		t.Fatal("start did not begin")
	}
	cancel()
	<-done
	if !s.health[b.ID()].lazy || s.health[b.ID()].active {
		t.Fatal("cancelled start not marked for retry")
	}
	s.syncModes(context.Background())
	if !s.health[b.ID()].active || b.upsN() != 1 {
		t.Fatal("ordinary start not retried")
	}
}

type cancelledRestart struct {
	*fake
	entered chan struct{}
}

func (b *cancelledRestart) Down(ctx context.Context) error {
	close(b.entered)
	<-ctx.Done()
	return ctx.Err()
}

func TestCancelledRestartCanRetryBeforeInterval(t *testing.T) {
	opt, _ := testOpts(t)
	b := &cancelledRestart{fake: &fake{id: "ordinary"}, entered: make(chan struct{})}
	s := New([]backend.Backend{b}, opt)
	h := s.health[b.ID()]
	h.failStreak = opt.FailThreshold
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.restart(ctx, b) }()
	select {
	case <-b.entered:
	case <-time.After(time.Second):
		t.Fatal("restart did not begin")
	}
	cancel()
	<-done
	if !s.restartWantedLocked(h, b.ID()) {
		t.Fatal("cancelled restart delayed until restart_interval")
	}
}

func (b *blockingLazyStart) Up(ctx context.Context) error {
	if b.starts.Add(1) == 1 {
		close(b.entered)
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func TestCancelledLazyActivationCanRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	opt, _ := testOpts(t)
	opt.PreferPath = filepath.Join(t.TempDir(), "prefer")
	opt.RecoverThreshold = 1
	b := &blockingLazyStart{lazyFake: &lazyFake{&fake{id: "reserve"}}, entered: make(chan struct{})}
	s := New([]backend.Backend{b}, opt)
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case <-b.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("activation did not start")
	}
	if err := os.WriteFile(opt.PreferPath, []byte("direct"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for s.Snapshot().Current != "direct" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Snapshot().Current != "direct" {
		t.Fatal("direct not selected")
	}
	if err := os.WriteFile(opt.PreferPath, []byte("auto"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for s.Snapshot().Current != "reserve" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Snapshot().Current != "reserve" {
		t.Fatalf("reserve failed to retry: %+v", s.Snapshot())
	}
}

func (b *blockingProbe) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestPreferenceSwitchDoesNotWaitForProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opt, _ := testOpts(t)
	opt.PreferPath = filepath.Join(t.TempDir(), "prefer")
	opt.CheckTimeout = 5 * time.Second
	b := &blockingProbe{fake: &fake{id: "main"}, entered: make(chan struct{}, 1)}
	s := New([]backend.Backend{b}, opt)
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case <-b.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("probe did not start")
	}
	setAndWait := func(choice, want string) {
		t.Helper()
		if err := os.WriteFile(opt.PreferPath, []byte(choice), 0600); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if s.Snapshot().Current == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("prefer %s: got %q", choice, s.Snapshot().Current)
	}
	setAndWait("direct", "direct")
	setAndWait("auto", "")
}

func TestAutoStartsLazyWhileOrdinaryProbeIsBlocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	opt, _ := testOpts(t)
	opt.PreferPath = filepath.Join(t.TempDir(), "prefer")
	opt.CheckTimeout = 10 * time.Second
	opt.RecoverThreshold = 1
	if err := os.WriteFile(opt.PreferPath, []byte("direct"), 0600); err != nil {
		t.Fatal(err)
	}
	b := &blockingProbe{fake: &fake{id: "main"}, entered: make(chan struct{}, 1)}
	reserve := &lazyFake{&fake{id: "reserve"}}
	s := New([]backend.Backend{b, reserve}, opt)
	s.health["main"].initialized = true
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case <-b.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("ordinary probe did not start")
	}
	if err := os.WriteFile(opt.PreferPath, []byte("auto"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.Snapshot().Current == "reserve" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("lazy fallback blocked: %+v", s.Snapshot())
}

func TestPreferenceReadIsSerializedWithState(t *testing.T) {
	opt, _ := testOpts(t)
	opt.PreferPath = filepath.Join(t.TempDir(), "prefer")
	if err := os.WriteFile(opt.PreferPath, []byte("direct"), 0600); err != nil {
		t.Fatal(err)
	}
	s := New(nil, opt)
	s.mu.Lock()
	done := make(chan struct{})
	go func() { defer close(done); s.syncPreference() }()
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(opt.PreferPath, []byte("auto"), 0600); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	<-done
	if got := s.Snapshot().Current; got == "direct" {
		t.Fatal("stale direct preference applied after auto")
	}
}

func TestDirectManualOnlyAndExistingConnectionSurvives(t *testing.T) {
	ctx := context.Background()
	opt, _ := testOpts(t)
	opt.RecoverThreshold = 1
	opt.FailThreshold = 1
	opt.PreferPath = filepath.Join(t.TempDir(), "prefer")
	main := &fake{id: "main", priority: 100}
	s := New([]backend.Backend{main}, opt)
	s.ProbeNow(ctx)
	if got := s.Snapshot().Current; got != "main" {
		t.Fatalf("auto current = %q", got)
	}
	if err := os.WriteFile(opt.PreferPath, []byte("direct"), 0600); err != nil {
		t.Fatal(err)
	}
	s.ProbeNow(ctx)
	if got := s.Snapshot().Current; got != "direct" {
		t.Fatalf("direct current = %q", got)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	c, err := s.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	peer := <-accepted
	defer func() { _ = peer.Close() }()
	if err := os.WriteFile(opt.PreferPath, []byte("auto"), 0600); err != nil {
		t.Fatal(err)
	}
	s.ProbeNow(ctx)
	if got := s.Snapshot().Current; got != "main" {
		t.Fatalf("returned current = %q", got)
	}
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := peer.Read(buf); err != nil || string(buf) != "x" {
		t.Fatalf("existing connection: %q %v", buf, err)
	}
	main.mu.Lock()
	main.failProbe = true
	main.mu.Unlock()
	s.ProbeNow(ctx)
	if got := s.Snapshot().Current; got == "direct" {
		t.Fatal("direct selected automatically")
	}
}

func TestDirectNoProbesOrEgressAndSurvivesReload(t *testing.T) {
	ctx := context.Background()
	opt, _ := testOpts(t)
	opt.PreferPath = filepath.Join(t.TempDir(), "prefer")
	if err := os.WriteFile(opt.PreferPath, []byte("direct"), 0600); err != nil {
		t.Fatal(err)
	}
	s := New(nil, opt)
	d := &fake{id: "direct"}
	s.direct = d
	s.ProbeNow(ctx)
	s.probeCurrent(ctx)
	s.refreshEgress(ctx)
	s.SetBackends(nil)
	if got := s.Snapshot().Current; got != "direct" {
		t.Fatalf("reload lost direct: %q", got)
	}
	if d.upsN() != 0 || d.downsN() != 0 || d.probeDialsN() != 0 {
		t.Fatal("direct was probed or restarted")
	}
	st := s.Snapshot().Backends
	if len(st) != 1 || !st[0].Direct || st[0].DNS != "system" {
		t.Fatalf("status = %+v", st)
	}
}
