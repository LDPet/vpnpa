package socks5

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

type recDial struct {
	addr   string
	remote net.Conn
	err    error
}

func (r *recDial) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	r.addr = address
	if r.err != nil {
		return nil, r.err
	}
	a, b := net.Pipe()
	r.remote = b
	return a, nil
}

func TestHostnameForwarded(t *testing.T) {
	lnAddr := freeAddr(t)
	srv := New(lnAddr, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &recDial{}
	go func() { _ = srv.Serve(ctx, d) }()
	waitListen(t, lnAddr)

	client, err := proxy.SOCKS5("tcp", lnAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.Dial("tcp", "ExAmPle.COM:80")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if d.addr != "ExAmPle.COM:80" {
		t.Fatalf("dialed %q", d.addr)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(d.remote, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("payload %q", buf)
	}
}

func TestDialErrorBecomesClientError(t *testing.T) {
	lnAddr := freeAddr(t)
	srv := New(lnAddr, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &recDial{err: io.EOF}
	go func() { _ = srv.Serve(ctx, d) }()
	waitListen(t, lnAddr)
	client, err := proxy.SOCKS5("tcp", lnAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Dial("tcp", "example.com:80"); err == nil {
		t.Fatal("expected client error")
	}
}

func TestContextClosesBothSides(t *testing.T) {
	lnAddr := freeAddr(t)
	srv := New(lnAddr, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	d := &recDial{}
	go func() { _ = srv.Serve(ctx, d) }()
	waitListen(t, lnAddr)
	client, err := proxy.SOCKS5("tcp", lnAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.Dial("tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("client still open")
	}
	_ = d.remote.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := d.remote.Read(buf); err == nil {
		t.Fatal("remote still open")
	}
}

func TestUDPAssociateNotDialed(t *testing.T) {
	lnAddr := freeAddr(t)
	srv := New(lnAddr, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &recDial{}
	go func() { _ = srv.Serve(ctx, d) }()
	waitListen(t, lnAddr)

	conn, err := net.Dial("tcp", lnAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		t.Fatal(err)
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		t.Fatalf("greeting %v", greet)
	}
	// UDP ASSOCIATE, IPv4 0.0.0.0:0. Команда не CONNECT, dial быть не должно.
	if _, err := conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(conn, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0x07 {
		t.Fatalf("udp associate reply %d", rep[1])
	}
	if d.addr != "" {
		t.Fatalf("udp associate dialed %q", d.addr)
	}
}

func TestUsernamePasswordRejected(t *testing.T) {
	lnAddr := freeAddr(t)
	srv := New(lnAddr, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &recDial{}
	go func() { _ = srv.Serve(ctx, d) }()
	waitListen(t, lnAddr)

	conn, err := net.Dial("tcp", lnAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		t.Fatal(err)
	}
	if greet[0] != 0x05 || greet[1] != 0xff {
		t.Fatalf("auth reply %v", greet)
	}
	if d.addr != "" {
		t.Fatal("auth-only client was dialed")
	}
}

func TestCancelUnblocksIdleConn(t *testing.T) {
	lnAddr := freeAddr(t)
	srv := New(lnAddr, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, &recDial{}) }()
	waitListen(t, lnAddr)
	conn, err := net.Dial("tcp", lnAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve blocked on an idle connection")
	}
}

func TestRejectsNonLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "1.2.3.4:1080", ":1080", "localhost:1080"} {
		t.Run(addr, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := New(addr, slog.New(slog.DiscardHandler)).Serve(ctx, &recDial{})
			if err == nil {
				t.Fatal("non-loopback listen was accepted")
			}
		})
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
	t.Fatalf("listener %s did not come up", addr)
}
