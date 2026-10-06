package amneziawg

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/LDPet/vpnpa/internal/backend"
)

func TestUserspaceHandshake(t *testing.T) {
	t.Parallel()
	serverKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	_ = udp.Close()

	tunDev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.66.66.1")},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		1280,
	)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf})
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\nh1=1\nh2=2\nh3=3\nh4=4\npublic_key=%s\nallowed_ip=10.66.66.2/32\n",
		mustHex(t, serverKey.Private), port, mustHex(t, clientKey.Public))
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		t.Fatal(err)
	}
	defer dev.Close()
	ln, err := tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP("10.66.66.1"), Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "peer-ok")
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	text := fmt.Sprintf("[Interface]\nAddress = 10.66.66.2/32\nDNS = 1.1.1.1\nPrivateKey = %s\nMTU = 1280\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 5\n",
		clientKey.Private, serverKey.Public, port)
	uri := EncodeURI(envWithLast(t, map[string]any{"config": text, "hostName": "127.0.0.1", "port": port}, "1.1.1.1", "1.0.0.1"))
	b, err := New(backend.Config{ID: "hs", Type: "amneziawg", Priority: 1, URI: uri}, backend.Deps{
		Logger:   slog.New(slog.DiscardHandler),
		StateDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Down(t.Context()) }()

	ctx := t.Context()
	var last error
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		c, err := b.DialContext(ctx, "tcp", "10.66.66.1:8080")
		if err != nil {
			last = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.WriteString(c, "GET / HTTP/1.0\r\nHost: 10.66.66.1\r\n\r\n")
		body, err := io.ReadAll(c)
		_ = c.Close()
		if err == nil && strings.Contains(string(body), "peer-ok") {
			return
		}
		last = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal(last)
}

func mustHex(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}
