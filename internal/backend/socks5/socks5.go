// Package socks5 — выход через уже слушающий чужой SOCKS5.
// Пакет не запускает и не останавливает этот процесс: Up только проверяет TCP,
// Down снимает локальный флаг. Имя назначения уходит в CONNECT как имя,
// резолвер хоста его не видит.
package socks5

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/LDPet/vpnpa/internal/backend"
	"github.com/LDPet/vpnpa/internal/config"
	"golang.org/x/net/proxy"
)

func init() {
	backend.Register("socks5", func(cfg backend.Config, deps backend.Deps) (backend.Backend, error) {
		return New(cfg, deps)
	})
}

// Backend — выход через чужой SOCKS5-прокси.
type Backend struct {
	id       string
	priority int
	host     string
	dialer   proxy.ContextDialer
	log      *slog.Logger

	mu sync.Mutex
	up bool
}

// New разбирает URI socks5://[user:pass@]host:port.
// Пароль и полный URI в лог не попадают. Соединение с прокси здесь не открывается.
func New(cfg backend.Config, deps backend.Deps) (*Backend, error) {
	creds, err := config.ParseSOCKS5URI(cfg.URI)
	if err != nil {
		return nil, fmt.Errorf("socks5 uri: want socks5://host:port")
	}
	var auth *proxy.Auth
	if creds.Auth {
		auth = &proxy.Auth{User: creds.User, Password: creds.Pass}
	}
	// x/net/proxy передаёт host:port в SOCKS5 CONNECT как есть.
	// Имя (atyp 0x03) не резолвится на этой машине.
	d, err := proxy.SOCKS5("tcp", creds.Host, auth, &net.Dialer{})
	if err != nil {
		return nil, fmt.Errorf("socks5 uri: want socks5://host:port")
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
		host:     creds.Host,
		dialer:   cd,
		log:      log,
	}, nil
}

// ID возвращает имя бэкенда из конфига.
func (b *Backend) ID() string { return b.id }

// Priority возвращает приоритет из конфига.
func (b *Backend) Priority() int { return b.priority }

// Endpoint возвращает host:port прокси без userinfo. Это безопасно писать в лог.
func (b *Backend) Endpoint() string { return b.host }

// Up проверяет, что до прокси открывается TCP. Процесс прокси не порождается:
// им владеет кто-то снаружи. Неуспешный Up оставляет бэкенд опущенным.
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

// Down сбрасывает локальный флаг. Чужой прокси продолжает слушать.
func (b *Backend) Down(context.Context) error {
	b.mu.Lock()
	b.up = false
	b.mu.Unlock()
	b.log.Info("бэкенд остановлен", "backend", b.id, "endpoint", b.host)
	return nil
}

// DialContext шлёт SOCKS5 CONNECT на прокси. Доменное имя уходит как имя
// (atyp 0x03), а не как заранее разрешённый IP. Вызов до Up — ошибка.
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
