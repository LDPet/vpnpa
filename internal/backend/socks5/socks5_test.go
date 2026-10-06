package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/LDPet/vpnpa/internal/backend"
)

func TestUpIsTCPAndDownLeavesProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	b, err := New(backend.Config{
		ID: "adguard", Type: "socks5", Priority: 90,
		URI: "socks5://" + ln.Addr().String(),
	}, backend.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- b.Up(context.Background()) }()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if err := <-errCh; err != nil {
		t.Fatalf("up required a socks handshake: %v", err)
	}
	if err := b.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	probe, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal("down closed the foreign proxy")
	}
	_ = probe.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := b.DialContext(ctx, "tcp", "example.test:80"); err == nil {
		t.Fatal("dial after down")
	}
}

func TestDialForwardsHostnameAndHidesPassword(t *testing.T) {
	got := &capture{}
	addr := serveSOCKS(t, "user", "p@ss", got)
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	uri := "socks5://user:p%40ss@" + addr
	b, err := New(backend.Config{
		ID: "adguard", Type: "socks5", Priority: 90, URI: uri,
	}, backend.Deps{Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	if b.Endpoint() != addr || bytes.Contains([]byte(b.Endpoint()), []byte("p@ss")) {
		t.Fatalf("endpoint %q", b.Endpoint())
	}
	if err := b.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn, err := b.DialContext(context.Background(), "tcp", "example.test:80")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	host, atyp, user, pass := got.wait(t)
	if atyp != 0x03 || host != "example.test:80" {
		t.Fatalf("atyp %d host %q", atyp, host)
	}
	if user != "user" || pass != "p@ss" {
		t.Fatal("credentials were not forwarded")
	}
	if err := b.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	text := logs.String()
	for _, secret := range []string{"p@ss", "p%40ss", "socks5://", uri} {
		if bytes.Contains([]byte(text), []byte(secret)) {
			t.Fatalf("log contains %q: %s", secret, text)
		}
	}
	if !bytes.Contains([]byte(text), []byte(addr)) {
		t.Fatalf("log missing endpoint: %s", text)
	}
}

func TestNoAuthAndBadURI(t *testing.T) {
	got := &capture{}
	addr := serveSOCKS(t, "", "", got)
	b, err := New(backend.Config{
		ID: "local", Type: "socks5", Priority: 100,
		URI: "socks5://" + addr,
	}, backend.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn, err := b.DialContext(context.Background(), "tcp", "Example.Test:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	host, atyp, user, _ := got.wait(t)
	if atyp != 0x03 || host != "Example.Test:443" || user != "" {
		t.Fatalf("atyp %d host %q user %q", atyp, host, user)
	}
	if _, err := New(backend.Config{ID: "x", Type: "socks5", URI: "socks5://user:s3cret@127.0.0.1"}, backend.Deps{}); err == nil || bytes.Contains([]byte(err.Error()), []byte("s3cret")) {
		t.Fatalf("bad uri: %v", err)
	}
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	_ = closed.Close()
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	down, err := New(backend.Config{
		ID: "x", Type: "socks5", URI: "socks5://user:s3cret@" + closedAddr,
	}, backend.Deps{Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	err = down.Up(context.Background())
	if err == nil {
		t.Fatal("up dialed a closed port")
	}
	if bytes.Contains([]byte(err.Error()), []byte("s3cret")) || bytes.Contains([]byte(err.Error()), []byte("socks5://")) {
		t.Fatalf("up error leaked: %v", err)
	}
	if bytes.Contains(logs.Bytes(), []byte("s3cret")) || bytes.Contains(logs.Bytes(), []byte("socks5://")) {
		t.Fatalf("log leaked: %s", logs.String())
	}
}

type capture struct {
	mu   sync.Mutex
	atyp byte
	host string
	user string
	pass string
	ok   bool
}

func (c *capture) wait(t *testing.T) (host string, atyp byte, user, pass string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		ok := c.ok
		host, atyp, user, pass = c.host, c.atyp, c.user, c.pass
		c.mu.Unlock()
		if ok {
			return host, atyp, user, pass
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("socks server saw no connect")
	return "", 0, "", ""
}

func serveSOCKS(t *testing.T, user, pass string, got *capture) string {
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
			go handleSOCKS(c, user, pass, got)
		}
	}()
	return ln.Addr().String()
}

func handleSOCKS(c net.Conn, user, pass string, got *capture) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 5 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	var seenUser, seenPass string
	if user == "" {
		if !bytes.Contains(methods, []byte{0x00}) {
			_, _ = c.Write([]byte{0x05, 0xff})
			return
		}
		if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
			return
		}
	} else {
		if !bytes.Contains(methods, []byte{0x02}) {
			_, _ = c.Write([]byte{0x05, 0xff})
			return
		}
		if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
		ah := make([]byte, 2)
		if _, err := io.ReadFull(c, ah); err != nil || ah[0] != 0x01 {
			return
		}
		ub := make([]byte, int(ah[1]))
		if _, err := io.ReadFull(c, ub); err != nil {
			return
		}
		var plen [1]byte
		if _, err := io.ReadFull(c, plen[:]); err != nil {
			return
		}
		pb := make([]byte, int(plen[0]))
		if _, err := io.ReadFull(c, pb); err != nil {
			return
		}
		seenUser, seenPass = string(ub), string(pb)
		if seenUser != user || seenPass != pass {
			_, _ = c.Write([]byte{0x01, 0x01})
			return
		}
		if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[0] != 5 || req[1] != 1 {
		return
	}
	host, err := readHost(c, req[3])
	if err != nil {
		return
	}
	var port uint16
	if err := binary.Read(c, binary.BigEndian, &port); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	got.mu.Lock()
	got.atyp = req[3]
	got.host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	got.user = seenUser
	got.pass = seenPass
	got.ok = true
	got.mu.Unlock()
	_, _ = io.Copy(io.Discard, c)
}

func readHost(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		buf := make([]byte, 4)
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
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	default:
		return "", io.ErrUnexpectedEOF
	}
}
