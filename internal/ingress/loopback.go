package ingress

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// Listen opens a TCP listener on a loopback address. A missing host, a
// hostname, or any non-loopback IP is rejected and nothing is bound.
func Listen(addr string) (net.Listener, error) {
	if err := requireLoopback(addr); err != nil {
		return nil, err
	}
	return net.Listen("tcp", addr)
}

func requireLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("listen %s: port is required", addr)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return fmt.Errorf("listen %s: host must be a loopback address", addr)
	}
	return nil
}

// CloseOnDone closes c when ctx is cancelled. Call the returned stop when the
// handler is finished so a later cancellation does not close a recycled conn.
// A nil conn yields a no-op stop.
func CloseOnDone(ctx context.Context, c net.Conn) func() {
	if c == nil {
		return func() {}
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	return func() { _ = stop() }
}
