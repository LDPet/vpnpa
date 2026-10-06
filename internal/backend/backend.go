// Package backend is the contract and factory registry for egress tunnels.
// It does not import concrete backends; those register themselves.
package backend

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/LDPet/vpnpa/internal/dialer"
)

// Compile-time check that Backend includes Dialer.
var _ interface {
	dialer.Dialer
} = (Backend)(nil)

// Backend is one egress. It does not know about balancing or SOCKS.
type Backend interface {
	dialer.Dialer
	ID() string
	Priority() int
	Up(ctx context.Context) error
	Down(ctx context.Context) error
}

// Config is the per-backend block from the YAML file.
type Config struct {
	ID       string
	Type     string
	Priority int
	URI      string
}

// Deps are process-wide dependencies handed to a factory.
type Deps struct {
	Logger   *slog.Logger
	StateDir string
}

// Factory builds a backend from config.
type Factory func(cfg Config, deps Deps) (Backend, error)

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

// Register adds a backend type. The ingress type of the same name is a
// different registry, so "socks5" can exist on both sides.
func Register(typ string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	factories[typ] = f
}

// Types returns the registered backend type names.
func Types() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(factories))
	for name := range factories {
		out = append(out, name)
	}
	return out
}

// Known reports whether typ was registered.
func Known(typ string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, ok := factories[typ]
	return ok
}

// New constructs a backend. Unknown types fail here.
func New(cfg Config, deps Deps) (Backend, error) {
	mu.RLock()
	f, ok := factories[cfg.Type]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown backend type %q", cfg.Type)
	}
	if deps.Logger == nil {
		deps.Logger = slog.New(slog.DiscardHandler)
	}
	return f(cfg, deps)
}

// EndpointOf returns a host:port safe to log, when the backend provides one.
func EndpointOf(b Backend) string {
	type endpoint interface {
		Endpoint() string
	}
	if e, ok := b.(endpoint); ok {
		return e.Endpoint()
	}
	return ""
}
