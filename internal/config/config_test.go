package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDefaultsAndRejects(t *testing.T) {
	t.Parallel()
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
	if _, err := Parse([]byte("listen: 127.0.0.1:1080\nhttp_listen: 8.8.8.8:8080\n")); err == nil {
		t.Fatal("non-loopback http_listen was accepted")
	}
	if _, err := Parse([]byte("listen: 127.0.0.1:1080\nhttp_listen: 127.0.0.1:1080\n")); err == nil {
		t.Fatal("identical listeners were accepted")
	}
	if _, err := Parse([]byte("listen: localhost:1080\n")); err == nil {
		t.Fatal("hostname listen was accepted")
	}
	v6, err := Parse([]byte("listen: \"[::1]:1080\"\nhttp_listen: \"[::1]:8080\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if v6.Listen != "[::1]:1080" || v6.HTTPListen != "[::1]:8080" {
		t.Fatalf("ipv6 listeners %+v", v6)
	}
	if _, err := Parse([]byte("listen: 127.0.0.1:1080\nbackends:\n  - id: a\n    type: amneziawg\n    uri: socks5://127.0.0.1:1\n")); err == nil {
		t.Fatal("amneziawg accepted socks5 uri")
	}
	if _, err := Parse([]byte("listen: 127.0.0.1:1080\nbackends:\n  - id: a\n    type: socks5\n    uri: vpn://abc\n")); err == nil {
		t.Fatal("socks5 accepted vpn uri")
	}
	if _, err := Parse([]byte("listen: 127.0.0.1:1080\nbackends:\n  - id: a\n    type: socks5\n    uri: socks5://127.0.0.1\n")); err == nil {
		t.Fatal("socks5 uri without port was accepted")
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
	t.Parallel()
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
	t.Parallel()
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

func TestDefaultIDsPrioritiesAndEndpoint(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if _, err := InstallConfig(path); err != nil {
		t.Fatal(err)
	}
	if _, err := AddSOCKS5(path, "", "socks5://user:s3cret@127.0.0.1"); err == nil || strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "socks5://user") {
		t.Fatalf("missing port: %v", err)
	}
	first, err := Add(path, "", "vpn://one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Add(path, "", "vpn://two")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != "vpn-1" || first.Priority != 100 {
		t.Fatalf("first %+v", first)
	}
	if second.ID != "vpn-2" || second.Priority != 90 {
		t.Fatalf("second id=%s priority=%d type=%s", second.ID, second.Priority, second.Type)
	}
	third, err := AddSOCKS5(path, "", "socks5://user:s3cret@127.0.0.1:9050")
	if err != nil {
		t.Fatal(err)
	}
	if third.ID != "vpn-3" || third.Priority != 80 || third.Type != "socks5" {
		t.Fatalf("third id=%s priority=%d type=%s", third.ID, third.Priority, third.Type)
	}
	ep, err := SOCKS5Endpoint(third.URI)
	if err != nil {
		t.Fatal(err)
	}
	if ep != "127.0.0.1:9050" || strings.Contains(ep, "s3cret") {
		t.Fatalf("endpoint %q", ep)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}
