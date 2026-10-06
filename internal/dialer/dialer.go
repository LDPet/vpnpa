// Package dialer is the shared call contract used by backends, the balancer
// and every ingress.
package dialer

import (
	"context"
	"errors"
	"net"
)

// Dialer opens a connection. Both a backend and the balancer implement it,
// so an ingress cannot tell them apart.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ErrNoHealthyBackend is returned when no backend is currently usable.
// Traffic is never sent out through the host network in that case.
var ErrNoHealthyBackend = errors.New("no healthy backend")
