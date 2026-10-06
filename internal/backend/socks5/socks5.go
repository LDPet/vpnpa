// Package socks5 dials an already-listening SOCKS5 proxy. It does not start
// or stop that process.
package socks5

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"sync"

	"github.com/LDPet/vpnpa/internal/backend"
	"golang.org/x/net/proxy"
)

func init() {
	backend.Register("socks5", func(cfg backend.Config, deps backend.Deps) (backend.Backend, error) {
		return New(cfg, deps)
	})
}

// Backend is an egress through a foreign SOCKS5 proxy.
type Backend struct {
	id       string
	priority int
	host     string
	dialer   proxy.ContextDialer
	log      *slog.Logger

	mu sync.Mutex
	up bool
}

// New parses a socks5 URI. The password is not logged.
func New(cfg backend.Config, deps backend.Deps) (*Backend, error) {
	u, err := url.Parse(cfg.URI)
	if err != nil || u.Scheme != "socks5" || u.Host == "" {
		return nil, fmt.Errorf("socks5 uri: want socks5://host:port")
	}
	var auth *proxy.Auth
	if u.User != nil {
		pass, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: pass}
	}
	d, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{})
	if err != nil {
		return nil, err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("socks5 dialer has no context")
	}
	log := deps.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Backend{
		id:       cfg.ID,
		priority: cfg.Priority,
		host:     u.Host,
		dialer:   cd,
		log:      log,
	}, nil
}

func (b *Backend) ID() string       { return b.id }
func (b *Backend) Priority() int    { return b.priority }
func (b *Backend) Endpoint() string { return b.host }

// Up checks that a TCP connection to the proxy opens. Nothing is spawned.
func (b *Backend) Up(ctx context.Context) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", b.host)
	if err != nil {
		return fmt.Errorf("socks5 %s: %w", b.host, err)
	}
	_ = c.Close()
	b.mu.Lock()
	b.up = true
	b.mu.Unlock()
	b.log.Info("бэкенд поднят", "backend", b.id, "priority", b.priority, "endpoint", b.host)
	return nil
}

// Down drops the local flag. The foreign proxy is left running.
func (b *Backend) Down(context.Context) error {
	b.mu.Lock()
	b.up = false
	b.mu.Unlock()
	b.log.Info("бэкенд остановлен", "backend", b.id, "endpoint", b.host)
	return nil
}

// DialContext sends CONNECT to the proxy. A domain name is forwarded as a name.
func (b *Backend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("socks5 backend: unsupported network %s", network)
	}
	b.mu.Lock()
	up := b.up
	b.mu.Unlock()
	if !up {
		return nil, fmt.Errorf("backend %s is down", b.id)
	}
	return b.dialer.DialContext(ctx, network, address)
}
