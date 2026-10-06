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
	conn, err := client.Dial("tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if d.addr != "example.com:80" {
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
