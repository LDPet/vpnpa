package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LDPet/vpnpa/internal/paths"
)

type fakeRun struct {
	calls []string
	err   error
	out   []byte
}

func (f *fakeRun) Run(_ context.Context, name string, args ...string) error {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	return f.err
}

func (f *fakeRun) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if f.out != nil {
		return f.out, f.err
	}
	return []byte("0\n"), f.err
}

func TestInstallDoesNotStartAndKeepsConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	layout := paths.FromHome(home)
	if err := os.MkdirAll(filepath.Dir(layout.ConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.ConfigPath, []byte("listen: 127.0.0.1:1080\n# keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := &fakeRun{}
	var stderr bytes.Buffer
	if code := MainWith([]string{"--config", layout.ConfigPath, "--state-dir", layout.StateDir, "install"}, run, &bytes.Buffer{}, &stderr); code != 0 {
		t.Fatalf("code %d %s", code, stderr.String())
	}
	raw, err := os.ReadFile(layout.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "keep") {
		t.Fatalf("config overwritten: %s", raw)
	}
	unit, err := os.ReadFile(layout.UnitPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), " run ") {
		t.Fatalf("unit:\n%s", unit)
	}
	joined := strings.Join(run.calls, "\n")
	if !strings.Contains(joined, "daemon-reload") {
		t.Fatalf("calls %s", joined)
	}
	if strings.Contains(joined, " start ") || strings.Contains(joined, " enable ") {
		t.Fatalf("install started the service: %s", joined)
	}
}

func TestAddRejectsWrongSchemeAndHidesPassword(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	layout := paths.FromHome(home)
	run := &fakeRun{err: os.ErrNotExist}
	var stderr bytes.Buffer
	if code := MainWith([]string{"--config", layout.ConfigPath, "--state-dir", layout.StateDir, "install"}, run, &bytes.Buffer{}, &stderr); code != 0 {
		t.Fatalf("install %d %s", code, stderr.String())
	}
	stderr.Reset()
	if code := MainWith([]string{"--config", layout.ConfigPath, "add", "socks5://127.0.0.1:9050"}, run, &bytes.Buffer{}, &stderr); code == 0 {
		t.Fatal("add accepted socks5")
	}
	stderr.Reset()
	if code := MainWith([]string{"--config", layout.ConfigPath, "add-socks5", "vpn://abc"}, run, &bytes.Buffer{}, &stderr); code == 0 {
		t.Fatal("add-socks5 accepted vpn")
	}
	stderr.Reset()
	var stdout bytes.Buffer
	if code := MainWith([]string{"--config", layout.ConfigPath, "add-socks5", "--id", "adguard", "socks5://user:s3cret@127.0.0.1:1081"}, run, &stdout, &stderr); code != 0 {
		t.Fatalf("add-socks5 %d %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "s3cret") || strings.Contains(stdout.String(), "s3cret") || strings.Contains(stderr.String(), "socks5://") {
		t.Fatalf("secret leaked stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := MainWith([]string{"--config", layout.ConfigPath, "list"}, run, &stdout, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	if strings.Contains(stdout.String(), "s3cret") || strings.Contains(stdout.String(), "socks5://") {
		t.Fatalf("list leaked %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "127.0.0.1:1081") || !strings.Contains(stdout.String(), "adguard") {
		t.Fatalf("list %q", stdout.String())
	}
	st, err := os.Stat(layout.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}

func TestUpEmptyDoesNotStart(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	layout := paths.FromHome(home)
	run := &fakeRun{}
	var stderr bytes.Buffer
	if code := MainWith([]string{"--config", layout.ConfigPath, "--state-dir", layout.StateDir, "install"}, run, &bytes.Buffer{}, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	run.calls = nil
	stderr.Reset()
	if code := MainWith([]string{"--config", layout.ConfigPath, "up"}, run, &bytes.Buffer{}, &stderr); code == 0 {
		t.Fatal("up succeeded with no backends")
	}
	if !strings.Contains(stderr.String(), "vpnpa add") {
		t.Fatalf("stderr %q", stderr.String())
	}
	if len(run.calls) != 0 {
		t.Fatalf("systemctl called: %v", run.calls)
	}
}

func TestSystemctlUnavailableHint(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USER", "alice")
	layout := paths.FromHome(home)
	run := &fakeRun{err: os.ErrNotExist}
	var stderr bytes.Buffer
	if code := MainWith([]string{"--config", layout.ConfigPath, "--state-dir", layout.StateDir, "install"}, run, &bytes.Buffer{}, &stderr); code != 0 {
		t.Fatalf("code %d %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "loginctl enable-linger alice") {
		t.Fatalf("stderr %q", stderr.String())
	}
}

func TestUpdateChecksum(t *testing.T) {
	sum, err := checksumFor("abc  vpnpa-linux-amd64\n", "vpnpa-linux-amd64")
	if err != nil || sum != "abc" {
		t.Fatalf("sum %q %v", sum, err)
	}
	if _, err := checksumFor("abc  other\n", "vpnpa-linux-amd64"); err == nil {
		t.Fatal("missing asset was accepted")
	}
}
