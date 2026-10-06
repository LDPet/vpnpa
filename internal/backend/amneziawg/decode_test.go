package amneziawg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LDPet/vpnpa/internal/backend"
)

func TestDecodeQCompressAndRawJSON(t *testing.T) {
	body := []byte(`{"dns1":"1.1.1.1","ok":true}`)
	got, err := DecodeURI(EncodeURI(body))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), body) {
		t.Fatalf("qCompress roundtrip %s", got)
	}
	raw, err := DecodeURI(EncodeRawJSON(body))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(raw), body) {
		t.Fatalf("raw json roundtrip %s", raw)
	}
	if _, err := DecodeURI("https://example"); err == nil {
		t.Fatal("accepted a non vpn uri")
	}
}

func TestParsePlaceholdersAndUAPI(t *testing.T) {
	priv := bytes.Repeat([]byte{0x11}, 32)
	pub := bytes.Repeat([]byte{0x22}, 32)
	psk := bytes.Repeat([]byte{0x33}, 32)
	hpk := bytes.Repeat([]byte{0x44}, 32)
	doc := fullDoc(t, base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(psk), base64.StdEncoding.EncodeToString(hpk), true)
	tun, err := ParseFullConfig(doc, "")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := tun.PrivateKeyHex, hex.EncodeToString(priv); got != want {
		t.Fatalf("private %s", got)
	}
	if got, want := tun.PublicKeyHex, hex.EncodeToString(pub); got != want {
		t.Fatalf("public %s", got)
	}
	if got, want := tun.PresharedHex, hex.EncodeToString(psk); got != want {
		t.Fatalf("psk %s", got)
	}
	if got, want := tun.HeaderProtectionKeyHex, hex.EncodeToString(hpk); got != want {
		t.Fatalf("hpk %s", got)
	}
	if len(tun.DNS) != 2 || tun.DNS[0].String() != "1.1.1.1" || tun.DNS[1].String() != "8.8.8.8" {
		t.Fatalf("dns %#v", tun.DNS)
	}
	if tun.Endpoint != "203.0.113.10:51820" {
		t.Fatalf("endpoint %s", tun.Endpoint)
	}
	if tun.MTU != 1280 || tun.JC != "4" || tun.H1 != "1-2" || tun.RandomTrailers != "true" {
		t.Fatalf("fields %+v", tun)
	}
	uapi := BuildUAPI(tun)
	for _, needle := range []string{
		"private_key=" + hex.EncodeToString(priv),
		"public_key=" + hex.EncodeToString(pub),
		"preshared_key=" + hex.EncodeToString(psk),
		"header_protection_key=" + hex.EncodeToString(hpk),
		"jc=4",
		"h1=1-2",
		"h2=3-4",
		"h3=5-6",
		"h4=7-8",
		"content_padding_addition=10-20",
		"rekey_after_time=20-30",
		"rekey_timeout=5",
		"reject_after_time=100-120",
		"keepalive_timeout=10",
		"max_handshake_attempts=5",
		"random_trailers=true",
		"disable_cookies=false",
		"endpoint=203.0.113.10:51820",
		"persistent_keepalive_interval=25",
		"allowed_ip=0.0.0.0/0",
	} {
		if !strings.Contains(uapi, needle) {
			t.Errorf("uapi missing %s\n%s", needle, uapi)
		}
	}
	if strings.Contains(uapi, base64.StdEncoding.EncodeToString(priv)) {
		t.Fatal("uapi kept a base64 key")
	}
	red := RedactUAPI(uapi)
	if strings.Contains(red, hex.EncodeToString(priv)) || strings.Contains(red, hex.EncodeToString(psk)) {
		t.Fatalf("redaction leaked a key:\n%s", red)
	}
	if !TrailersRangeWarning(tun) {
		t.Fatal("expected trailer warning")
	}
}

func TestDecodeStdBase64WhitespaceAndLength(t *testing.T) {
	body := []byte("\n{\"dns1\":\"1.1.1.1\",\"ok\":true}\n")
	comp := qCompress(body)
	std := base64.StdEncoding.EncodeToString(comp)
	got, err := DecodeURI("vpn://" + std)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(`{"dns1":"1.1.1.1","ok":true}`)) {
		t.Fatalf("whitespace qCompress %s", got)
	}
	bad := append([]byte(nil), comp...)
	bad[3] ^= 0x7f
	if _, err := DecodeURI("vpn://" + base64.RawURLEncoding.EncodeToString(bad)); err == nil {
		t.Fatal("accepted qCompress with a mismatched length")
	}
}

func TestLastConfigSuppliesMissingFields(t *testing.T) {
	priv := bytes.Repeat([]byte{0x11}, 32)
	pub := bytes.Repeat([]byte{0x22}, 32)
	psk := bytes.Repeat([]byte{0x33}, 32)
	hpkText := bytes.Repeat([]byte{0x44}, 32)
	hpkJSON := bytes.Repeat([]byte{0x55}, 32)
	last := map[string]any{
		"config":                 "[Interface]\nAddress = 10.8.1.3/32\nAddress = fd00::3/128\nDNS = 1.1.1.1\nDNS = 8.8.8.8\nPrivateKey = " + base64.StdEncoding.EncodeToString(priv) + "\nHeaderProtectionKey = " + base64.StdEncoding.EncodeToString(hpkText) + "\nAllowedIPs = \n[Peer]\nPublicKey = " + base64.StdEncoding.EncodeToString(pub) + "\n",
		"hostName":               "203.0.113.9",
		"port":                   4242,
		"Jc":                     7,
		"H1":                     "1-2",
		"H2":                     "3-4",
		"H3":                     "5-6",
		"PresharedKey":           base64.StdEncoding.EncodeToString(psk),
		"HeaderProtectionKey":    hex.EncodeToString(hpkJSON),
		"ContentPaddingAddition": "10-20",
		"RandomTrailers":         "on",
		"allowed_ips":            []any{"10.9.0.0/16", "::/0"},
		"mtu":                    "1400",
	}
	tun, err := ParseFullConfig(envWithLast(t, last, "9.9.9.9", "8.8.4.4"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(tun.Addresses) != 2 || tun.Addresses[0].String() != "10.8.1.3" || tun.Addresses[1].String() != "fd00::3" {
		t.Fatalf("addrs %#v", tun.Addresses)
	}
	if len(tun.DNS) != 2 || tun.DNS[0].String() != "1.1.1.1" || tun.DNS[1].String() != "8.8.8.8" {
		t.Fatalf("dns %#v", tun.DNS)
	}
	if tun.HeaderProtectionKeyHex != hex.EncodeToString(hpkText) {
		t.Fatalf("text header key lost: %s", tun.HeaderProtectionKeyHex)
	}
	if tun.PresharedHex != hex.EncodeToString(psk) || tun.JC != "7" || tun.MTU != 1400 || tun.Endpoint != "203.0.113.9:4242" {
		t.Fatalf("%+v", tun)
	}
	if len(tun.AllowedIPs) != 2 || tun.AllowedIPs[0] != "10.9.0.0/16" || tun.AllowedIPs[1] != "::/0" {
		t.Fatalf("allowed %v", tun.AllowedIPs)
	}
	if tun.H1 != "1-2" || tun.RandomTrailers != "true" || tun.ContentPaddingAddition != "10-20" {
		t.Fatalf("rewritten %+v", tun)
	}
	uapi := BuildUAPI(tun)
	if !strings.Contains(uapi, "header_protection_key="+hex.EncodeToString(hpkText)) {
		t.Fatalf("uapi missing header key\n%s", uapi)
	}

	last["config"] = "[Interface]\nAddress = 10.8.1.3/32\nPrivateKey = " + base64.StdEncoding.EncodeToString(priv) + "\n[Peer]\nPublicKey = " + base64.StdEncoding.EncodeToString(pub) + "\n"
	tun, err = ParseFullConfig(envWithLast(t, last, "9.9.9.9", ""), "")
	if err != nil {
		t.Fatal(err)
	}
	if tun.HeaderProtectionKeyHex != hex.EncodeToString(hpkJSON) {
		t.Fatalf("json header key %s", tun.HeaderProtectionKeyHex)
	}
	if len(tun.DNS) != 1 || tun.DNS[0].String() != "9.9.9.9" {
		t.Fatalf("dns fallback %#v", tun.DNS)
	}
}

func TestDialDoesNotCallAPI(t *testing.T) {
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		pub := bytes.Repeat([]byte{0x22}, 32)
		last := map[string]any{
			"config": "[Interface]\nAddress = 10.8.1.3/32\nPrivateKey = $WIREGUARD_CLIENT_PRIVATE_KEY\n[Peer]\nPublicKey = " + base64.StdEncoding.EncodeToString(pub) + "\nEndpoint = 203.0.113.10:51820\n",
		}
		raw, _ := json.Marshal(map[string]string{"config": EncodeURI(envWithLast(t, last, "1.1.1.1", ""))})
		_, _ = w.Write(raw)
	}))
	defer srv.Close()
	orig := tunnelStarter
	tunnelStarter = func(Tunnel, *slog.Logger) (tunnelHandle, error) {
		return tunnelHandle{dial: &noopDial{}, close: func() error { return nil }}, nil
	}
	t.Cleanup(func() { tunnelStarter = orig })
	api := EncodeURI(mustJSON(map[string]string{"api_endpoint": srv.URL, "api_key": "k"}))
	b := newTestBackend(t, "dial-api", api, t.TempDir(), nil)
	if err := b.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.DialContext(t.Context(), "tcp", "example.com:443"); err == nil {
		t.Fatal("expected dial error")
	}
	if posts != 1 {
		t.Fatalf("dial issued API calls: %d", posts)
	}
}

func TestStoredKeyModeRepaired(t *testing.T) {
	dir := t.TempDir()
	kp, err := loadOrCreateKey(dir, "id1", "vpn://same")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id1")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	again, err := loadOrCreateKey(dir, "id1", "vpn://same")
	if err != nil {
		t.Fatal(err)
	}
	if again.Public != kp.Public {
		t.Fatal("tightening mode rotated the key")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}

func TestDeviceLoggerQuietAndNoPacketDump(t *testing.T) {
	var buf bytes.Buffer
	info := slog.New(slog.NewTextHandler(&buf, nil))
	quiet := deviceLogger(info)
	quiet.Verbosef("handshake %s", "ok")
	quiet.Errorf("device error")
	if buf.Len() != 0 {
		t.Fatalf("info logger wrote %s", buf.String())
	}
	dbg := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	lg := deviceLogger(dbg)
	lg.Verbosef("%s - Sending handshake initiation", "peer(abcd)")
	if !strings.Contains(buf.String(), "handshake") {
		t.Fatalf("debug dropped handshake: %s", buf.String())
	}
	buf.Reset()
	lg.Verbosef("packet %x", bytes.Repeat([]byte{0xab}, 16))
	lg.Errorf("dump %s", "aa bb cc dd ee ff 00 11 22")
	if buf.Len() != 0 {
		t.Fatalf("logged packet bytes:\n%s", buf.String())
	}
}

func TestObfuscationFilledFromLastConfig(t *testing.T) {
	priv := bytes.Repeat([]byte{0x11}, 32)
	pub := bytes.Repeat([]byte{0x22}, 32)
	last := map[string]any{
		"config":   "[Interface]\nAddress = 10.8.1.3/32\nPrivateKey = " + base64.StdEncoding.EncodeToString(priv) + "\n[Peer]\nPublicKey = " + base64.StdEncoding.EncodeToString(pub) + "\n",
		"hostName": "203.0.113.9",
		"port":     4242,
		"Jc":       "7",
		"mtu":      "1400",
	}
	doc := envWithLast(t, last, "9.9.9.9", "8.8.4.4")
	tun, err := ParseFullConfig(doc, "")
	if err != nil {
		t.Fatal(err)
	}
	if tun.JC != "7" || tun.MTU != 1400 || tun.Endpoint != "203.0.113.9:4242" {
		t.Fatalf("%+v", tun)
	}
	if len(tun.DNS) != 2 || tun.DNS[0].String() != "9.9.9.9" {
		t.Fatalf("dns %#v", tun.DNS)
	}
}

func TestAPIUpReusesPublicKey(t *testing.T) {
	priv := bytes.Repeat([]byte{0x11}, 32)
	pub := bytes.Repeat([]byte{0x22}, 32)
	var posts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Api-Key ") {
			t.Errorf("authorization %q", got)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		posts = append(posts, body["public_key"])
		for _, key := range []string{"os_version", "app_version", "uuid"} {
			if body[key] == "" {
				t.Errorf("missing %s", key)
			}
		}
		last := map[string]any{
			"config":   "[Interface]\nAddress = 10.8.1.3/32\nDNS = 1.1.1.1\nPrivateKey = $WIREGUARD_CLIENT_PRIVATE_KEY\n[Peer]\nPublicKey = " + base64.StdEncoding.EncodeToString(pub) + "\nEndpoint = 203.0.113.10:51820\n",
			"hostName": "203.0.113.10",
			"port":     51820,
		}
		raw, _ := json.Marshal(map[string]string{"config": EncodeURI(envWithLast(t, last, "1.1.1.1", "8.8.8.8"))})
		_, _ = w.Write(raw)
		_ = priv
	}))
	defer srv.Close()

	orig := tunnelStarter
	tunnelStarter = func(tun Tunnel, _ *slog.Logger) (tunnelHandle, error) {
		return tunnelHandle{dial: &noopDial{}, close: func() error { return nil }}, nil
	}
	t.Cleanup(func() { tunnelStarter = orig })

	state := t.TempDir()
	api := EncodeURI(mustJSON(map[string]string{
		"api_endpoint": srv.URL,
		"api_key":      "test-key",
	}))
	b := newTestBackend(t, "api-1", api, state, nil)
	if err := b.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := b.Down(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := b.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(posts) != 2 || posts[0] == "" || posts[0] != posts[1] {
		t.Fatalf("public keys %#v", posts)
	}
	st, err := os.Stat(filepath.Join(state, "keys", "api-1"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %o", st.Mode().Perm())
	}

	other := EncodeURI(mustJSON(map[string]string{
		"api_endpoint": srv.URL,
		"api_key":      "test-key-2",
	}))
	b2 := newTestBackend(t, "api-1", other, state, nil)
	if err := b2.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(posts) != 3 || posts[2] == posts[0] {
		t.Fatalf("uri change reused key %#v", posts)
	}
}

func TestAPIBadResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not-a-config"))
	}))
	defer srv.Close()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	api := EncodeURI(mustJSON(map[string]string{
		"api_endpoint": srv.URL,
		"api_key":      "super-secret-api-key",
	}))
	b := newTestBackend(t, "api-bad", api, t.TempDir(), log)
	if err := b.Up(t.Context()); err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(buf.String(), "super-secret-api-key") || strings.Contains(buf.String(), "vpn://") {
		t.Fatalf("log leaked secret:\n%s", buf.String())
	}
}

func TestUpWarnsOnRandomTrailers(t *testing.T) {
	priv := bytes.Repeat([]byte{0x11}, 32)
	pub := bytes.Repeat([]byte{0x22}, 32)
	doc := fullDoc(t, base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), "", "", true)
	orig := tunnelStarter
	tunnelStarter = func(Tunnel, *slog.Logger) (tunnelHandle, error) {
		return tunnelHandle{close: func() error { return nil }}, nil
	}
	t.Cleanup(func() { tunnelStarter = orig })
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	b := newTestBackend(t, "warn-1", EncodeURI(doc), t.TempDir(), log)
	if err := b.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "RandomTrailers") {
		t.Fatalf("no warning:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), base64.StdEncoding.EncodeToString(priv)) {
		t.Fatalf("warning leaked private key:\n%s", buf.String())
	}
}

type noopDial struct{}

func (noopDial) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("noop")
}

func newTestBackend(t *testing.T, id, uri, state string, log *slog.Logger) *Backend {
	t.Helper()
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	b, err := New(backend.Config{ID: id, Type: "amneziawg", Priority: 100, URI: uri}, backend.Deps{
		Logger:   log,
		StateDir: state,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fullDoc(t *testing.T, priv, pub, psk, hpk string, trailers bool) []byte {
	t.Helper()
	extra := "RandomTrailers = off\nDisableCookies = off\n"
	if trailers {
		extra = "RandomTrailers = on\nDisableCookies = off\n"
	}
	if psk != "" {
		extra += "PresharedKey = " + psk + "\n"
	}
	if hpk != "" {
		extra += "HeaderProtectionKey = " + hpk + "\n"
	}
	extra += "ContentPaddingAddition = 10-20\nRekeyAfterTime = 20-30\nRekeyTimeout = 5\nRejectAfterTime = 100-120\nKeepaliveTimeout = 10\nMaxHandshakeAttempts = 5\n"
	text := "[Interface]\nAddress = 10.8.1.3/32\nDNS = $PRIMARY_DNS, $SECONDARY_DNS\nPrivateKey = $WIREGUARD_CLIENT_PRIVATE_KEY\nMTU = 1280\nJc = 4\nJmin = 10\nJmax = 50\nS1 = 15\nS2 = 15\nS3 = 15\nS4 = 15\nH1 = 1-2\nH2 = 3-4\nH3 = 5-6\nH4 = 7-8\n" + extra + "[Peer]\nPublicKey = " + pub + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.10:51820\nPersistentKeepalive = 25\n"
	last := map[string]any{
		"config":          text,
		"hostName":        "203.0.113.10",
		"port":            51820,
		"client_priv_key": priv,
	}
	return envWithLast(t, last, "1.1.1.1", "8.8.8.8")
}

func envWithLast(t *testing.T, last map[string]any, dns1, dns2 string) []byte {
	t.Helper()
	lastJSON, err := json.Marshal(last)
	if err != nil {
		t.Fatal(err)
	}
	return mustJSON(map[string]any{
		"dns1":     dns1,
		"dns2":     dns2,
		"hostName": "203.0.113.10",
		"containers": []any{
			map[string]any{
				"container": "amnezia-awg",
				"awg":       map[string]any{"last_config": string(lastJSON)},
			},
		},
	})
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}
