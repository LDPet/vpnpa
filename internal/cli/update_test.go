package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateReplacesByRenameAndRestartsOnlyIfActive(t *testing.T) {
	payload := []byte("new-vpnpa-binary")
	sum := sha256.Sum256(payload)
	asset, err := releaseAsset()
	if err != nil {
		t.Fatal(err)
	}
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.URL.Path {
		case "/SHA256SUMS":
			_, _ = fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), asset)
		case "/" + asset:
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	exe := filepath.Join(dir, "vpnpa")
	if err := os.WriteFile(exe, []byte("old-vpnpa-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	old, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = old.Close() })
	before, err := old.Stat()
	if err != nil {
		t.Fatal(err)
	}

	allow := func(*url.URL) error { return nil }
	inactive := &fakeRun{out: []byte("inactive\n"), outputErr: errors.New("exit status 3")}
	var stdout, stderr bytes.Buffer
	if err := updateExe(context.Background(), srv.Client(), srv.URL+"/", exe, allow, inactive, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(inactive.calls, "\n"), "restart") {
		t.Fatalf("restarted an inactive service: %v", inactive.calls)
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("content %q", got)
	}
	after, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("binary was written in place")
	}
	if after.Mode().Perm() != 0o755 {
		t.Fatalf("mode %o", after.Mode().Perm())
	}
	buf := make([]byte, len("old-vpnpa-binary"))
	if _, err := old.ReadAt(buf, 0); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "old-vpnpa-binary" {
		t.Fatalf("running inode changed: %q", buf)
	}

	payload2 := []byte("newer-vpnpa-binary")
	sum2 := sha256.Sum256(payload2)
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/SHA256SUMS":
			_, _ = fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum2[:]), asset)
		case "/" + asset:
			_, _ = w.Write(payload2)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv2.Close)
	active := &fakeRun{out: []byte("active\n")}
	stdout.Reset()
	stderr.Reset()
	if err := updateExe(context.Background(), srv2.Client(), srv2.URL+"/", exe, allow, active, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(active.calls, "\n")
	if !strings.Contains(joined, "systemctl --user is-active vpnpa.service") {
		t.Fatalf("is-active args: %s", joined)
	}
	if !strings.Contains(joined, "systemctl --user restart vpnpa.service") {
		t.Fatalf("restart args: %s", joined)
	}
	if strings.Contains(joined, "sh ") || strings.Contains(joined, ";") {
		t.Fatalf("shell-looking args: %s", joined)
	}
}

func TestUpdateRejectsBadChecksumAndLeavesNoTemp(t *testing.T) {
	asset, err := releaseAsset()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/SHA256SUMS":
			_, _ = fmt.Fprintf(w, "%s  %s\n", strings.Repeat("ab", 32), asset)
		case "/" + asset:
			_, _ = w.Write([]byte("not-the-hashed-bytes"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	exe := filepath.Join(dir, "vpnpa")
	if err := os.WriteFile(exe, []byte("keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	err = updateExe(context.Background(), srv.Client(), srv.URL+"/", exe, func(*url.URL) error { return nil }, &fakeRun{}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("bad checksum was installed")
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" {
		t.Fatalf("binary changed: %q", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".vpnpa-update-") {
			t.Fatalf("temp left: %s", e.Name())
		}
	}
}

func TestUpdateDoesNotFetchOffAllowlist(t *testing.T) {
	var hits int
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte("metadata"))
	}))
	t.Cleanup(internal.Close)
	dir := t.TempDir()
	exe := filepath.Join(dir, "vpnpa")
	if err := os.WriteFile(exe, []byte("keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := updateExe(context.Background(), internal.Client(), internal.URL+"/", exe, validateReleaseURL, &fakeRun{}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("non-allowlisted URL was accepted")
	}
	if hits != 0 {
		t.Fatalf("fetched %d times from %s", hits, internal.URL)
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" {
		t.Fatalf("binary changed: %q", got)
	}
}

func TestReleaseURLPolicy(t *testing.T) {
	ok := []string{
		"https://github.com/LDPet/vpnpa/releases/latest/download/SHA256SUMS",
		"https://release-assets.githubusercontent.com/asset",
		"https://objects.githubusercontent.com/asset?token=secret",
		"https://github-releases.githubusercontent.com/asset",
	}
	for _, raw := range ok {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateReleaseURL(u); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if got := redactURL(u); strings.Contains(got, "token") || strings.Contains(got, "secret") {
			t.Fatalf("query leaked: %s", got)
		}
	}
	bad := []string{
		"http://github.com/LDPet/vpnpa/releases/latest/download/vpnpa",
		"https://127.0.0.1/vpnpa",
		"https://169.254.169.254/latest/meta-data",
		"https://evil.example/vpnpa",
		"https://github.com.evil.example/vpnpa",
		"https://gist.github.com/vpnpa",
		"file:///etc/passwd",
		"https://user:pass@github.com/vpnpa",
	}
	for _, raw := range bad {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateReleaseURL(u); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	req, err := http.NewRequest(http.MethodGet, "https://169.254.169.254/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := releaseRedirect(req, nil); err == nil {
		t.Fatal("redirect to metadata was allowed")
	}
	if err := releaseRedirect(req, make([]*http.Request, 5)); err == nil {
		t.Fatal("long redirect chain was allowed")
	}
	for _, raw := range []string{"127.0.0.1", "10.1.2.3", "192.168.0.1", "169.254.169.254", "::1", "100.64.0.1", "0.0.0.0"} {
		if !ipBlocked(net.ParseIP(raw)) {
			t.Fatalf("allowed %s", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "1.1.1.1"} {
		if ipBlocked(net.ParseIP(raw)) {
			t.Fatalf("blocked public %s", raw)
		}
	}
}
