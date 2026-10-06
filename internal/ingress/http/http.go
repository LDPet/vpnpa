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
	"strings"
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
	ln, err := ingress.Listen(s.Addr)
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
	stopClient := ingress.CloseOnDone(ctx, conn)
	defer stopClient()
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
	// CONNECT carries the authority in the request target. Pass those bytes
	// through; do not prefer a Host header and do not resolve the name.
	addr := connectTarget(req)
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
	stopRemote := ingress.CloseOnDone(ctx, remote)
	defer stopRemote()
	defer func() { _ = remote.Close() }()
	if ctx.Err() != nil {
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if n := br.Buffered(); n > 0 {
		peek, err := br.Peek(n)
		if err != nil {
			return
		}
		if err := writeFull(remote, peek); err != nil {
			return
		}
	}
	pipe(ctx, conn, remote)
}

// connectTarget is the authority the client asked to dial, unchanged.
func connectTarget(req *http.Request) string {
	if req.RequestURI != "" && !strings.HasPrefix(req.RequestURI, "/") {
		return req.RequestURI
	}
	if req.URL != nil && req.URL.Host != "" {
		return req.URL.Host
	}
	return req.Host
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
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
