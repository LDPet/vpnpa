// Package ingress is the contract and factory registry for local listeners.
package ingress

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/LDPet/vpnpa/internal/dialer"
)

// Ingress accepts local connections and dials through the provided Dialer.
// It listens only on an address the caller already constrained to loopback.
type Ingress interface {
	Serve(ctx context.Context, dial dialer.Dialer) error
}

// Factory builds an ingress bound to listen.
type Factory func(listen string, log *slog.Logger) (Ingress, error)

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

// Register adds an ingress type. This registry is separate from backends.
func Register(typ string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	factories[typ] = f
}

// Known reports whether typ was registered.
func Known(typ string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, ok := factories[typ]
	return ok
}

// New constructs an ingress.
func New(typ, listen string, log *slog.Logger) (Ingress, error) {
	mu.RLock()
	f, ok := factories[typ]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown ingress type %q", typ)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return f(listen, log)
}
