//go:build e2e

// Package e2e_test поднимает два userspace-пира AmneziaWG и гоняет собранный
// бинарник: failover, SIGHUP и выдачу конфига через API. Сборка с тегом e2e.
package e2e_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/net/proxy"

	"github.com/LDPet/vpnpa/internal/backend/amneziawg"
	"github.com/LDPet/vpnpa/internal/config"
)

func TestE2EFailoverAndSignal(t *testing.T) {
	peer1 := startPeer(t, "peer-1")
	peer2 := startPeer(t, "peer-2")
	bin := buildBinary(t)
	socks, httpAddr := freeTCP(t), freeTCP(t)
	state := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	writeConfig(t, cfgPath, socks, httpAddr, []config.Backend{
		{ID: "vpn-1", Type: "amneziawg", Priority: 100, URI: peer1.clientURI},
		{ID: "vpn-2", Type: "amneziawg", Priority: 90, URI: peer2.clientURI},
	})
	cmd, logs := startVPN(t, bin, cfgPath, state)
	waitListen(t, socks, logs)
	waitWho(t, socks, "peer-1", logs)

	peer1.stop()
	waitWho(t, socks, "peer-2", logs)

	stopAndRelease(t, cmd, socks, logs)
}

func TestE2EAPIConfig(t *testing.T) {
	peer := startPeer(t, "peer-api")
	// Прямая ссылка клиента заменяется API, который отдаёт тот же туннель,
	// узнав присланный публичный ключ.
	api := httptestAPI(t, peer)
	bin := buildBinary(t)
	socks, httpAddr := freeTCP(t), freeTCP(t)
	state := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	uri := amneziawg.EncodeURI(mustJSON(map[string]string{
		"api_endpoint": api.URL,
		"api_key":      "local-test-key",
	}))
	writeConfig(t, cfgPath, socks, httpAddr, []config.Backend{
		{ID: "api-1", Type: "amneziawg", Priority: 100, URI: uri},
	})
	cmd, logs := startVPN(t, bin, cfgPath, state)
	waitListen(t, socks, logs)
	waitWho(t, socks, "peer-api", logs)
	stopAndRelease(t, cmd, socks, logs)
}

type peer struct {
	name      string
	clientURI string
	dev       *device.Device
	srv       *http.Server
	port      int
	serverPub string
	stop      func()
}

func startPeer(t *testing.T, name string) *peer {
	t.Helper()
	serverKey, err := amneziawg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := amneziawg.GenerateKeyPair()
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
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: func(format string, args ...any) {
		log.Printf("awg %s: "+format, append([]any{name}, args...)...)
	}}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\nh1=1\nh2=2\nh3=3\nh4=4\npublic_key=%s\nallowed_ip=10.66.66.2/32\n",
		keyHex(t, serverKey.Private), port, keyHex(t, clientKey.Public))
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		t.Fatal(err)
	}
	ln, err := tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP("10.66.66.1"), Port: 8080})
	if err != nil {
		dev.Close()
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/generate_204", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/who", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, name)
	})
	mux.HandleFunc("/ip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "203.0.113.50")
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()

	p := &peer{
		name:      name,
		dev:       dev,
		srv:       srv,
		port:      port,
		serverPub: serverKey.Public,
		clientURI: clientURI(clientKey.Private, serverKey.Public, port),
	}
	var once sync.Once
	p.stop = func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
			dev.Close()
		})
	}
	t.Cleanup(p.stop)
	return p
}

func clientURI(priv, serverPub string, port int) string {
	text := fmt.Sprintf(`[Interface]
Address = 10.66.66.2/32
DNS = 1.1.1.1
PrivateKey = %s
MTU = 1280
H1 = 1
H2 = 2
H3 = 3
H4 = 4
[Peer]
PublicKey = %s
Endpoint = 127.0.0.1:%d
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 5
`, priv, serverPub, port)
	last, _ := json.Marshal(map[string]any{
		"config":   text,
		"hostName": "127.0.0.1",
		"port":     port,
	})
	env, _ := json.Marshal(map[string]any{
		"dns1": "1.1.1.1",
		"dns2": "1.0.0.1",
		"containers": []any{
			map[string]any{
				"container": "amnezia-awg",
				"awg":       map[string]any{"last_config": string(last)},
			},
		},
	})
	return amneziawg.EncodeURI(env)
}

func httptestAPI(t *testing.T, p *peer) *httpServer {
	t.Helper()
	srv := &http.Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Api-Key local-test-key" {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		var body struct {
			PublicKey string `json:"public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		if err := p.dev.IpcSet("public_key=" + keyHex(t, body.PublicKey) + "\nallowed_ip=10.66.66.2/32\n"); err != nil {
			http.Error(w, "peer", http.StatusInternalServerError)
			return
		}
		uri := clientURI("$WIREGUARD_CLIENT_PRIVATE_KEY", p.serverPub, p.port)
		_ = json.NewEncoder(w).Encode(map[string]string{"config": uri})
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.Handler = mux
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return &httpServer{URL: "http://" + ln.Addr().String()}
}

type httpServer struct{ URL string }

func writeConfig(t *testing.T, path, socks, httpAddr string, backends []config.Backend) {
	t.Helper()
	f := config.File{
		Listen:     socks,
		HTTPListen: httpAddr,
		Balancer: config.Balancer{
			Type:             "sticky",
			CheckInterval:    config.Duration(300 * time.Millisecond),
			CheckTimeout:     config.Duration(3 * time.Second),
			FailThreshold:    2,
			RecoverThreshold: 1,
			RestartInterval:  config.Duration(10 * time.Minute),
			CheckURLs:        []string{"http://10.66.66.1:8080/generate_204"},
			EgressURL:        "http://10.66.66.1:8080/ip",
			EgressInterval:   config.Duration(time.Hour),
		},
		Backends: backends,
		Log:      config.Log{Level: "info", Format: "text"},
	}
	if err := config.Save(path, f); err != nil {
		t.Fatal(err)
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "vpnpa")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/vpnpa")
	cmd.Dir = moduleRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func startVPN(t *testing.T, bin, cfg, state string) (*exec.Cmd, *lockedBuf) {
	t.Helper()
	logs := &lockedBuf{}
	cmd := exec.Command(bin, "--config", cfg, "--state-dir", state, "--log-level", "info", "run")
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var waitOnce sync.Once
	waitCmd := func() {
		waitOnce.Do(func() {
			if cmd.ProcessState == nil && cmd.Process != nil {
				_ = cmd.Wait()
			}
		})
	}
	t.Cleanup(func() {
		if cmd.Process != nil && cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
		}
		waitCmd()
	})
	cmd.Cancel = func() error { waitCmd(); return nil }
	return cmd, logs
}

func waitWho(t *testing.T, socks, want string, logs *lockedBuf) {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		body, err := who(socks)
		if err == nil && strings.Contains(body, want) {
			return
		}
		last = err
		if err == nil {
			last = fmt.Errorf("body %q", body)
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("who %s: %v\nlogs:\n%s", want, last, logs.String())
}

func who(socks string) (string, error) {
	d, err := proxy.SOCKS5("tcp", socks, nil, proxy.Direct)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return "", fmt.Errorf("socks dialer has no context")
	}
	c, err := cd.DialContext(ctx, "tcp", "10.66.66.1:8080")
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := io.WriteString(c, "GET /who HTTP/1.0\r\nHost: 10.66.66.1\r\n\r\n"); err != nil {
		return "", err
	}
	raw, err := io.ReadAll(c)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func stopAndRelease(t *testing.T, cmd *exec.Cmd, socks string, logs *lockedBuf) {
	t.Helper()
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		if cmd.Cancel != nil {
			_ = cmd.Cancel()
		}
		close(done)
	}()
	select {
	case <-time.After(10 * time.Second):
		t.Fatalf("process ignored SIGINT\n%s", logs.String())
	case <-done:
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ln, err := net.Listen("tcp", socks)
		if err == nil {
			_ = ln.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("port %s still busy", socks)
}

func waitListen(t *testing.T, addr string, logs *lockedBuf) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("vpnpa did not listen on %s\n%s", addr, logs.String())
}

func freeTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func keyHex(t *testing.T, b64 string) string {
	t.Helper()
	if m := len(b64) % 4; m != 0 {
		b64 += strings.Repeat("=", 4-m)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
