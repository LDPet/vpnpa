// Package http is a localhost HTTP CONNECT ingress.
// The host from the request is dialed unchanged.
package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"github.com/LDPet/vpnpa/internal/dialer"
	"github.com/LDPet/vpnpa/internal/ingress"
	"github.com/LDPet/vpnpa/internal/logx"
)

func init() {
	ingress.Register("http", func(listen string, log *slog.Logger) (ingress.Ingress, error) {
		return New(listen, log), nil
	})
}

// Server accepts HTTP CONNECT and nothing else.
type Server struct {
	Addr string
	Log  *slog.Logger
}

// New returns an HTTP CONNECT ingress.
func New(addr string, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{Addr: addr, Log: log}
}

// Serve accepts until ctx is cancelled and then closes both sides.
func (s *Server) Serve(ctx context.Context, d dialer.Dialer) error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, c, d)
		}()
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn, d dialer.Dialer) {
	id := logx.NewConnID()
	ctx = logx.WithConnID(ctx, id)
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		s.Log.Debug("http connect read", "conn_id", id, "err", err)
		return
	}
	if req.Method != http.MethodConnect {
		_ = reject(conn, http.StatusMethodNotAllowed)
		return
	}
	addr := req.Host
	if req.URL != nil && req.URL.Host != "" {
		addr = req.URL.Host
	}
	if addr == "" {
		_ = reject(conn, http.StatusBadRequest)
		return
	}
	remote, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		_ = reject(conn, http.StatusBadGateway)
		s.Log.Warn("ошибка dial", "conn_id", id, "addr", addr, "err", err)
		return
	}
	defer func() { _ = remote.Close() }()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if n := br.Buffered(); n > 0 {
		peek, err := br.Peek(n)
		if err != nil {
			return
		}
		if _, err := remote.Write(peek); err != nil {
			return
		}
	}
	pipe(ctx, conn, remote)
}

func reject(w io.Writer, code int) error {
	_, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", code, http.StatusText(code))
	return err
}

func pipe(ctx context.Context, a, b net.Conn) {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = a.Close()
			_ = b.Close()
		case <-done:
		}
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
	}()
	wg.Wait()
	close(done)
}
