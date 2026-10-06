package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
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
	t.Parallel()
	addr := freeAddr(t)
	srv := New(addr, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &recDial{}
	go func() { _ = srv.Serve(ctx, d) }()
	waitListen(t, addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "CONNECT ExAmPle.COM:443 HTTP/1.1\r\nHost: other.example:9\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatalf("status %q", line)
	}
	if d.addr != "ExAmPle.COM:443" {
		t.Fatalf("dialed %q", d.addr)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" {
			break
		}
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(d.remote, buf); err != nil {
		t.Fatal(err)
	}
}

func TestDialErrorIsBadGateway(t *testing.T) {
	t.Parallel()
	addr := freeAddr(t)
	srv := New(addr, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, &recDial{err: io.EOF}) }()
	waitListen(t, addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "HTTP/1.1 502 Bad Gateway\r\n" {
		t.Fatalf("status %q", line)
	}
}

func TestContextClosesBothSides(t *testing.T) {
	t.Parallel()
	addr := freeAddr(t)
	srv := New(addr, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	d := &recDial{}
	go func() { _ = srv.Serve(ctx, d) }()
	waitListen(t, addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	if _, err := br.ReadString('\n'); err != nil {
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

func TestGETDoesNotDial(t *testing.T) {
	t.Parallel()
	addr := freeAddr(t)
	d := &recDial{}
	srv := New(addr, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, d) }()
	waitListen(t, addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "HTTP/1.1 405 Method Not Allowed\r\n" {
		t.Fatalf("status %q", line)
	}
	if d.addr != "" {
		t.Fatalf("dialed %q", d.addr)
	}
}

func TestCancelUnblocksIdleConn(t *testing.T) {
	t.Parallel()
	addr := freeAddr(t)
	srv := New(addr, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, &recDial{}) }()
	waitListen(t, addr)
	conn, err := net.Dial("tcp", addr)
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
	t.Parallel()
	for _, addr := range []string{"0.0.0.0:0", "8.8.8.8:8080", ":8080", "localhost:8080"} {
		t.Run(addr, func(t *testing.T) {
			t.Parallel()
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
