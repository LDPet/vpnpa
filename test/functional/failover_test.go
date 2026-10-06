// Package functional_test гоняет SOCKS5-вход через sticky на поддельных бэкендах:
// старый поток не рвётся при переключении, два мёртвых бэкенда отдают клиенту ошибку,
// ошибка пользовательского dial сама по себе выбор не меняет.
package functional_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/LDPet/vpnpa/internal/backend"
	"github.com/LDPet/vpnpa/internal/balance/sticky"
	"github.com/LDPet/vpnpa/internal/dialer"
	"github.com/LDPet/vpnpa/internal/ingress/socks5"
	"golang.org/x/net/proxy"
)

const probeAddr = "probe.invalid:9"

type fake struct {
	id       string
	prio     int
	echo     string
	mu       sync.Mutex
	fail     bool
	failUser bool
	downs    int
	users    int
	conns    []net.Conn
}

func (f *fake) ID() string               { return f.id }
func (f *fake) Priority() int            { return f.prio }
func (f *fake) Up(context.Context) error { return nil }
func (f *fake) Down(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.downs++
	for _, c := range f.conns {
		_ = c.Close()
	}
	f.conns = nil
	return nil
}
func (f *fake) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address == probeAddr {
		f.mu.Lock()
		fail := f.fail
		f.mu.Unlock()
		if fail {
			return nil, errors.New("probe failed")
		}
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}
	f.mu.Lock()
	failUser := f.failUser
	f.mu.Unlock()
	if failUser {
		return nil, errors.New("user dial failed")
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, network, f.echo)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.users++
	f.conns = append(f.conns, c)
	f.mu.Unlock()
	return c, nil
}
func (f *fake) setFail(v bool) {
	f.mu.Lock()
	f.fail = v
	f.mu.Unlock()
}
func (f *fake) stats() (users, downs int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.users, f.downs
}

func TestSOCKSFailoverKeepsOldStream(t *testing.T) {
	echo := startEcho(t)
	high := &fake{id: "high", prio: 100, echo: echo}
	low := &fake{id: "low", prio: 50, echo: echo}
	clock := time.Unix(1_700_000_000, 0)
	bal := sticky.New([]backend.Backend{high, low}, sticky.Options{
		CheckTimeout:     time.Second,
		FailThreshold:    3,
		RecoverThreshold: 2,
		RestartInterval:  time.Minute,
		CheckURLs:        []string{"tcp://" + probeAddr},
		EgressURL:        "http://127.0.0.1:1/ip",
		EgressInterval:   time.Hour,
		Now:              func() time.Time { return clock },
		Logger:           slog.New(slog.DiscardHandler),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < 2; i++ {
		bal.ProbeNow(ctx)
	}
	if bal.Snapshot().Current != "high" {
		t.Fatalf("current=%s", bal.Snapshot().Current)
	}

	socksAddr := freeAddr(t)
	go func() { _ = socks5.New(socksAddr, slog.New(slog.DiscardHandler)).Serve(ctx, bal) }()
	waitListen(t, socksAddr)

	conn := dialEcho(t, socksAddr, echo)
	if _, err := conn.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	readN(t, conn, "one")
	if u, _ := low.stats(); u != 0 {
		t.Fatalf("standby saw %d user dials", u)
	}
	if u, _ := high.stats(); u != 1 {
		t.Fatalf("primary dials=%d", u)
	}

	high.setFail(true)
	for i := 0; i < 3; i++ {
		bal.ProbeNow(ctx)
	}
	if bal.Snapshot().Current != "low" {
		t.Fatalf("current=%s", bal.Snapshot().Current)
	}
	if _, downs := high.stats(); downs != 0 {
		t.Fatalf("primary Down at switch, downs=%d", downs)
	}
	if _, err := conn.Write([]byte("still")); err != nil {
		t.Fatal(err)
	}
	readN(t, conn, "still")

	conn2 := dialEcho(t, socksAddr, echo)
	defer func() { _ = conn2.Close() }()
	if _, err := conn2.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	readN(t, conn2, "two")
	if u, _ := low.stats(); u != 1 {
		t.Fatalf("standby dials=%d", u)
	}
	if u, _ := high.stats(); u != 1 {
		t.Fatalf("primary took a new dial, users=%d", u)
	}

	for i := 0; i < 2; i++ {
		bal.ProbeNow(ctx)
	}
	if _, downs := high.stats(); downs != 0 {
		t.Fatalf("Down before restart_interval, downs=%d", downs)
	}
	clock = clock.Add(time.Minute)
	bal.ProbeNow(ctx)
	if _, downs := high.stats(); downs != 1 {
		t.Fatalf("downs=%d after restart_interval", downs)
	}
}

func TestBothDeadSOCKSErrors(t *testing.T) {
	echo := startEcho(t)
	a := &fake{id: "a", prio: 100, echo: echo}
	b := &fake{id: "b", prio: 50, echo: echo}
	bal := sticky.New([]backend.Backend{a, b}, sticky.Options{
		CheckTimeout:     time.Second,
		FailThreshold:    2,
		RecoverThreshold: 1,
		RestartInterval:  time.Hour,
		CheckURLs:        []string{"tcp://" + probeAddr},
		EgressURL:        "http://127.0.0.1:1/ip",
		EgressInterval:   time.Hour,
		Logger:           slog.New(slog.DiscardHandler),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bal.ProbeNow(ctx)
	socksAddr := freeAddr(t)
	go func() { _ = socks5.New(socksAddr, slog.New(slog.DiscardHandler)).Serve(ctx, bal) }()
	waitListen(t, socksAddr)
	a.setFail(true)
	b.setFail(true)
	bal.ProbeNow(ctx)
	bal.ProbeNow(ctx)
	if bal.Snapshot().Current != "" {
		t.Fatalf("current=%s", bal.Snapshot().Current)
	}
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Dial("tcp", echo)
	if err == nil {
		t.Fatal("socks dial succeeded with no healthy backend")
	}
	if !errors.Is(err, dialer.ErrNoHealthyBackend) && err.Error() == "" {
		t.Fatal(err)
	}
	if u, _ := a.stats(); u != 0 {
		t.Fatalf("backend a accepted %d dials with no healthy backend", u)
	}
	if u, _ := b.stats(); u != 0 {
		t.Fatalf("backend b accepted %d dials with no healthy backend", u)
	}
}

func TestUserDialErrorDoesNotMoveTraffic(t *testing.T) {
	echo := startEcho(t)
	high := &fake{id: "high", prio: 100, echo: echo}
	low := &fake{id: "low", prio: 50, echo: echo}
	bal := sticky.New([]backend.Backend{high, low}, sticky.Options{
		CheckTimeout:     time.Second,
		FailThreshold:    3,
		RecoverThreshold: 2,
		RestartInterval:  time.Hour,
		CheckURLs:        []string{"tcp://" + probeAddr},
		EgressURL:        "http://127.0.0.1:1/ip",
		EgressInterval:   time.Hour,
		Logger:           slog.New(slog.DiscardHandler),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < 2; i++ {
		bal.ProbeNow(ctx)
	}
	socksAddr := freeAddr(t)
	go func() { _ = socks5.New(socksAddr, slog.New(slog.DiscardHandler)).Serve(ctx, bal) }()
	waitListen(t, socksAddr)

	high.mu.Lock()
	high.failUser = true
	high.mu.Unlock()
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Dial("tcp", echo); err == nil {
		t.Fatal("expected dial error")
	}
	if bal.Snapshot().Current != "high" {
		t.Fatalf("current=%s", bal.Snapshot().Current)
	}
	if u, _ := low.stats(); u != 0 {
		t.Fatalf("standby saw %d dials after a user error", u)
	}
	high.mu.Lock()
	high.failUser = false
	high.mu.Unlock()
	conn := dialEcho(t, socksAddr, echo)
	if _, err := conn.Write([]byte("still")); err != nil {
		t.Fatal(err)
	}
	readN(t, conn, "still")
	if u, _ := high.stats(); u != 1 {
		t.Fatalf("primary dials=%d", u)
	}
	if u, _ := low.stats(); u != 0 {
		t.Fatalf("standby dials=%d", u)
	}
}

func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func dialEcho(t *testing.T, socksAddr, echo string) net.Conn {
	t.Helper()
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Dial("tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func readN(t *testing.T, c net.Conn, want string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != want {
		t.Fatalf("got %q want %q", buf, want)
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
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("not listening on %s", addr)
}
