package ingress

import (
	"net"
	"testing"
)

func TestListenLoopbackOnly(t *testing.T) {
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()

	for _, addr := range []string{"0.0.0.0:0", "1.2.3.4:1080", ":1080", "localhost:1080", ""} {
		if _, err := Listen(addr); err == nil {
			t.Fatalf("listen accepted %q", addr)
		}
	}

	v6, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("ipv6 loopback unavailable")
	}
	v6addr := v6.Addr().String()
	_ = v6.Close()
	ln, err = Listen(v6addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
}
