package amneziawg

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"sync"

	"github.com/LDPet/vpnpa/internal/backend"
	"github.com/LDPet/vpnpa/internal/config"
	"github.com/LDPet/vpnpa/internal/dialer"
)

func init() {
	backend.Register("amneziawg", func(cfg backend.Config, deps backend.Deps) (backend.Backend, error) {
		return New(cfg, deps)
	})
	config.ValidateAmnezia = func(uri string) error {
		_, err := DecodeURI(uri)
		return err
	}
}

// Backend is an in-process AmneziaWG 3.1 client.
type Backend struct {
	id       string
	priority int
	uri      string
	stateDir string
	log      *slog.Logger

	mu       sync.Mutex
	handle   *tunnelHandle
	endpoint string
}

// New validates the URI shape and returns a backend. The tunnel starts on Up.
func New(cfg backend.Config, deps backend.Deps) (*Backend, error) {
	if _, err := DecodeURI(cfg.URI); err != nil {
		return nil, err
	}
	log := deps.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Backend{
		id:       cfg.ID,
		priority: cfg.Priority,
		uri:      cfg.URI,
		stateDir: deps.StateDir,
		log:      log,
	}, nil
}

func (b *Backend) ID() string       { return b.id }
func (b *Backend) Priority() int    { return b.priority }
func (b *Backend) Endpoint() string { return b.endpoint }

// Up resolves vpn:// (and the API, when the link has no tunnel yet) and
// starts a userspace device. An API keypair is reused while the URI is unchanged.
func (b *Backend) Up(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.handle != nil {
		return nil
	}
	tun, err := b.resolve(ctx)
	if err != nil {
		b.log.Warn("битая ссылка", "backend", b.id, "err", err)
		return err
	}
	if TrailersRangeWarning(tun) {
		b.log.Warn("RandomTrailers=on и диапазоны H1–H3: часть пакетов может теряться, значения не изменены",
			"backend", b.id,
			"endpoint", tun.Endpoint,
		)
	}
	handle, err := tunnelStarter(tun, b.log)
	if err != nil {
		b.log.Warn("ошибка поднятия бэкенда", "backend", b.id, "endpoint", tun.Endpoint, "err", err)
		return err
	}
	b.handle = &handle
	b.endpoint = tun.Endpoint
	b.log.Info("бэкенд поднят", "backend", b.id, "priority", b.priority, "endpoint", tun.Endpoint)
	return nil
}

// Down closes the userspace device. It does not remove the saved API key.
func (b *Backend) Down(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.handle == nil {
		return nil
	}
	err := b.handle.close()
	b.handle = nil
	b.log.Info("бэкенд остановлен", "backend", b.id, "endpoint", b.endpoint)
	return err
}

// DialContext forwards to the userspace netstack, which resolves names with
// the DNS servers from the link.
func (b *Backend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	b.mu.Lock()
	h := b.handle
	b.mu.Unlock()
	if h == nil || h.dial == nil {
		return nil, fmt.Errorf("backend %s is down", b.id)
	}
	return h.dial.DialContext(ctx, network, address)
}

func (b *Backend) resolve(ctx context.Context) (Tunnel, error) {
	doc, err := DecodeURI(b.uri)
	if err != nil {
		return Tunnel{}, err
	}
	if endpoint, apiKey, ok := IsAPI(doc); ok {
		keysDir := ""
		if b.stateDir != "" {
			keysDir = filepath.Join(b.stateDir, "keys")
		}
		if keysDir == "" {
			return Tunnel{}, fmt.Errorf("api link requires a state dir")
		}
		kp, err := loadOrCreateKey(keysDir, b.id, b.uri)
		if err != nil {
			return Tunnel{}, err
		}
		cfg, err := fetchAPIConfig(ctx, endpoint, apiKey, kp)
		if err != nil {
			b.log.Warn("ошибка API", "backend", b.id, "err", err)
			return Tunnel{}, err
		}
		return ParseFullConfig(cfg, kp.Private)
	}
	return ParseFullConfig(doc, "")
}

var _ dialer.Dialer = (*Backend)(nil)
var _ backend.Backend = (*Backend)(nil)
