package sticky

import (
	"context"
	"net"
)

// directBackend uses the host's network and system DNS. It has no lifecycle
// or health checks and is selected only by the explicit preference.
type directBackend struct{}

func (directBackend) ID() string                 { return "direct" }
func (directBackend) Priority() int              { return 0 }
func (directBackend) Up(context.Context) error   { return nil }
func (directBackend) Down(context.Context) error { return nil }
func (directBackend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}
