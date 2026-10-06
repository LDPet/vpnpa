// Package socks5 — локальный вход SOCKS5 CONNECT (RFC 1928).
// Имя назначения пересылается дальше без резолва. Это пакет входа;
// выход через чужой SOCKS5 — internal/backend/socks5.
package socks5

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/LDPet/vpnpa/internal/dialer"
	"github.com/LDPet/vpnpa/internal/ingress"
	"github.com/LDPet/vpnpa/internal/logx"
)

func init() {
	ingress.Register("socks5", func(listen string, log *slog.Logger) (ingress.Ingress, error) {
		return New(listen, log), nil
	})
}

// Server слушает SOCKS5 CONNECT. UDP ASSOCIATE и BIND отклоняются и наружу не звонят.
// Аутентификация только method 0x00 (без пароля): локальный сокет и так на loopback.
type Server struct {
	Addr string
	Log  *slog.Logger
}

// New возвращает вход SOCKS5 на addr. Сокет откроет Serve, и только если addr — loopback.
func New(addr string, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{Addr: addr, Log: log}
}

// Serve принимает соединения, пока ctx не отменён. Отмена закрывает слушатель
// и обе стороны каждого принятого соединения.
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
	if err := handshake(br, conn); err != nil {
		s.Log.Debug("socks5 handshake", "conn_id", id, "err", err)
		return
	}
	addr, err := readConnect(br)
	if err != nil {
		_ = writeReply(conn, 0x07)
		s.Log.Debug("socks5 request", "conn_id", id, "err", err)
		return
	}
	remote, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		_ = writeReply(conn, 0x01)
		s.Log.Warn("ошибка dial", "conn_id", id, "addr", addr, "err", err)
		return
	}
	stopRemote := ingress.CloseOnDone(ctx, remote)
	defer stopRemote()
	defer func() { _ = remote.Close() }()
	if ctx.Err() != nil {
		return
	}
	if err := writeReply(conn, 0x00); err != nil {
		return
	}
	pipe(ctx, conn, remote)
}

// handshake принимает только SOCKS5 и method 0x00. Иного метода нет:
// клиенту уходит 0xFF, имя назначения даже не читается.
func handshake(br *bufio.Reader, w io.Writer) error {
	ver, err := br.ReadByte()
	if err != nil {
		return err
	}
	if ver != 5 {
		return fmt.Errorf("socks version %d", ver)
	}
	n, err := br.ReadByte()
	if err != nil {
		return err
	}
	methods := make([]byte, int(n))
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	for _, m := range methods {
		if m == 0x00 {
			return writeFull(w, []byte{0x05, 0x00})
		}
	}
	_ = writeFull(w, []byte{0x05, 0xff})
	return errors.New("no acceptable socks auth method")
}

// readConnect читает команду CONNECT и собирает host:port.
// Имя (atyp 0x03) возвращается строкой. net.LookupHost здесь не вызывается:
// резолв, если он нужен, делает бэкенд по ту сторону Dialer.
func readConnect(br *bufio.Reader) (string, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return "", err
	}
	if hdr[0] != 5 {
		return "", fmt.Errorf("socks version %d", hdr[0])
	}
	if hdr[1] != 0x01 {
		return "", fmt.Errorf("unsupported socks command %d", hdr[1])
	}
	host, err := readAddr(br, hdr[3])
	if err != nil {
		return "", err
	}
	var port uint16
	if err := binary.Read(br, binary.BigEndian, &port); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func readAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", err
		}
		buf := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	default:
		return "", fmt.Errorf("unsupported atyp %d", atyp)
	}
}

// writeReply отвечает кодом rep. BND.ADDR — нули: клиенту не нужен адрес,
// на котором vpnpa «принял» туннель, его нет.
func writeReply(w io.Writer, rep byte) error {
	return writeFull(w, []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
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

// pipe копирует байты в обе стороны. CloseWrite на половине, которая первой
// дочитала, отдаёт второй стороне EOF, не обрывая её запись.
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
		_ = closeWrite(a)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		_ = closeWrite(b)
	}()
	wg.Wait()
	close(done)
}

func closeWrite(c net.Conn) error {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}
