package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDefaultsAndRejects(t *testing.T) {
	f, err := Parse([]byte(Template()))
	if err != nil {
		t.Fatal(err)
	}
	if f.Listen != DefaultListen || f.HTTPListen != DefaultHTTPListen {
		t.Fatalf("listeners %+v", f)
	}
	if f.Balancer.Type != "sticky" || f.Balancer.FailThreshold != 3 || f.Balancer.RecoverThreshold != 2 {
		t.Fatalf("balancer %+v", f.Balancer)
	}
	if len(f.Balancer.CheckURLs) != 2 {
		t.Fatalf("urls %#v", f.Balancer.CheckURLs)
	}
	if f.Log.Level != "info" || f.Log.Format != "text" {
		t.Fatalf("log %+v", f.Log)
	}

	if _, err := Parse([]byte("listen: 127.0.0.1:1080\nbackends:\n  - type: amneziawg\n    uri: vpn://x\n")); err == nil {
		t.Fatal("missing id was accepted")
	}
	if _, err := Parse([]byte("listen: 127.0.0.1:1080\nbackends:\n  - id: a\n    type: wireguard\n    uri: vpn://x\n")); err == nil {
		t.Fatal("unknown type was accepted")
	}
	if _, err := Parse([]byte("listen: 1.2.3.4:1080\n")); err == nil {
		t.Fatal("non-loopback listen was accepted")
	}
	custom, err := Parse([]byte("listen: 127.0.0.1:1080\nbalancer:\n  type: sticky\n  check_urls:\n    - tcp://127.0.0.1:9\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(custom.Balancer.CheckURLs) != 1 || custom.Balancer.CheckURLs[0] != "tcp://127.0.0.1:9" {
		t.Fatalf("check_urls were not replaced: %#v", custom.Balancer.CheckURLs)
	}
}

func TestFileModeAndInstallKeepsConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if _, err := InstallConfig(path); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	if err := os.WriteFile(path, []byte("listen: 127.0.0.1:1080\n# keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := InstallConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("install recreated an existing config")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- тестовый путь
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "keep me") {
		t.Fatalf("config was overwritten: %s", raw)
	}
	st, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode after install %o", st.Mode().Perm())
	}
}

func TestAddSchemesAndMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if _, err := InstallConfig(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(path, "", "socks5://127.0.0.1:9050"); err == nil {
		t.Fatal("add accepted socks5")
	}
	if _, err := AddSOCKS5(path, "", "vpn://abc"); err == nil {
		t.Fatal("add-socks5 accepted vpn")
	}
	first, err := Add(path, "", "vpn://example")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != "vpn-1" || first.Priority != 100 || first.Type != "amneziawg" {
		t.Fatalf("first %+v", first)
	}
	second, err := AddSOCKS5(path, "proxy", "socks5://user:s3cret@127.0.0.1:9050")
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != "proxy" || second.Priority != 90 || second.Type != "socks5" {
		t.Fatalf("second %+v", second)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Backends) != 2 {
		t.Fatalf("%d backends", len(f.Backends))
	}
}
