package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/LDPet/vpnpa/internal/backend/amneziawg"
	"github.com/LDPet/vpnpa/internal/paths"
)

type fakeRun struct {
	calls     []string
	err       error
	out       []byte
	outputErr error
}

func (f *fakeRun) Run(_ context.Context, name string, args ...string) error {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	return f.err
}

func (f *fakeRun) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if f.out != nil {
		return f.out, f.outputErr
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
	t.Parallel()
	const good = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	sum, err := checksumFor(good+"  vpnpa-linux-amd64\n", "vpnpa-linux-amd64")
	if err != nil || sum != good {
		t.Fatalf("sum %q %v", sum, err)
	}
	if _, err := checksumFor(good+"  other\n", "vpnpa-linux-amd64"); err == nil {
		t.Fatal("missing asset was accepted")
	}
	if _, err := checksumFor("abc  vpnpa-linux-amd64\n", "vpnpa-linux-amd64"); err == nil {
		t.Fatal("short hash was accepted")
	}
	sum, err = checksumFor(good+" *vpnpa-linux-amd64\n", "vpnpa-linux-amd64")
	if err != nil || sum != good {
		t.Fatalf("star sum %q %v", sum, err)
	}
	conflict := good + "  vpnpa-linux-amd64\n" + strings.Repeat("a", 64) + "  vpnpa-linux-amd64\n"
	if _, err := checksumFor(conflict, "vpnpa-linux-amd64"); err == nil {
		t.Fatal("conflicting hashes were accepted")
	}
}

func TestAddHidesVPNURIAndKeepsMode(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	layout := paths.FromHome(home)
	run := &fakeRun{err: os.ErrNotExist}
	var stderr bytes.Buffer
	if code := MainWith([]string{"--config", layout.ConfigPath, "--state-dir", layout.StateDir, "install"}, run, &bytes.Buffer{}, &stderr); code != 0 {
		t.Fatalf("install %d %s", code, stderr.String())
	}
	if err := os.Chmod(layout.ConfigPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(layout.ConfigPath), 0o755); err != nil {
		t.Fatal(err)
	}
	secret := "super-secret-api-key"
	uri := amneziawg.EncodeRawJSON([]byte(`{"api_key":"` + secret + `","api_endpoint":"https://example.invalid/api"}`))
	stderr.Reset()
	var stdout bytes.Buffer
	if code := MainWith([]string{"--config", layout.ConfigPath, "add", uri}, run, &stdout, &stderr); code != 0 {
		t.Fatalf("add %d %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), secret) || strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String()+stdout.String(), "vpn://") {
		t.Fatalf("uri leaked stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	st, err := os.Stat(layout.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %o", st.Mode().Perm())
	}
	dst, err := os.Stat(filepath.Dir(layout.ConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	if dst.Mode().Perm() != 0o700 {
		t.Fatalf("config dir mode %o", dst.Mode().Perm())
	}
	sst, err := os.Stat(layout.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if sst.Mode().Perm() != 0o700 {
		t.Fatalf("state dir mode %o", sst.Mode().Perm())
	}
}

func TestLogsArgvIsFixed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	run := &fakeRun{}
	var stderr bytes.Buffer
	if code := MainWith([]string{"logs", "-f", "--output=cat", "vpnpa;id"}, run, &bytes.Buffer{}, &stderr); code == 0 {
		t.Fatal("extra journalctl args were accepted")
	}
	if len(run.calls) != 0 {
		t.Fatalf("journalctl invoked: %v", run.calls)
	}
	stderr.Reset()
	if code := MainWith([]string{"logs", "-f"}, run, &bytes.Buffer{}, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	if len(run.calls) != 1 || run.calls[0] != "journalctl --user -u vpnpa.service -n 100 -f" {
		t.Fatalf("calls %v", run.calls)
	}
	run.calls = nil
	if code := MainWith([]string{"down"}, run, &bytes.Buffer{}, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	if run.calls[0] != "systemctl --user stop vpnpa.service" {
		t.Fatalf("down %v", run.calls)
	}
}

// Последовательно: подменяет пакетные killProc, procExe и procCmdline.
func TestSignalReloadOnlyVpnpaMainPID(t *testing.T) {
	var killed int
	prevKill := killProc
	prevExe := procExe
	prevCmd := procCmdline
	killProc = func(pid int, _ syscall.Signal) error {
		killed = pid
		return nil
	}
	t.Cleanup(func() {
		killProc = prevKill
		procExe = prevExe
		procCmdline = prevCmd
	})
	signalReload(context.Background(), &fakeRun{out: []byte(strconv.Itoa(os.Getpid()) + "\n")})
	if killed != 0 {
		t.Fatalf("signaled foreign pid %d", killed)
	}
	procExe = func(int) (string, error) { return "/home/a/.local/bin/vpnpa", nil }
	procCmdline = func(int) ([]byte, error) {
		return []byte("/home/a/.local/bin/vpnpa\x00run\x00--config\x00x\x00"), nil
	}
	signalReload(context.Background(), &fakeRun{out: []byte("1\n")})
	if killed != 0 {
		t.Fatalf("signaled pid 1")
	}
	procCmdline = func(int) ([]byte, error) {
		return []byte("/home/a/.local/bin/vpnpa\x00add\x00vpn://secret\x00"), nil
	}
	signalReload(context.Background(), &fakeRun{out: []byte("4242\n")})
	if killed != 0 {
		t.Fatal("signaled vpnpa add")
	}
	procExe = func(int) (string, error) { return "/bin/bash", nil }
	procCmdline = func(int) ([]byte, error) { return []byte("/bin/bash\x00run\x00"), nil }
	signalReload(context.Background(), &fakeRun{out: []byte("4242\n")})
	if killed != 0 {
		t.Fatal("signaled bash")
	}
	procExe = func(int) (string, error) { return "/home/a/.local/bin/vpnpa (deleted)", nil }
	procCmdline = func(int) ([]byte, error) {
		return []byte("/home/a/.local/bin/vpnpa\x00run\x00"), nil
	}
	signalReload(context.Background(), &fakeRun{out: []byte("4242\n")})
	if killed != 4242 {
		t.Fatalf("did not signal vpnpa run, killed=%d", killed)
	}
	run := &fakeRun{out: []byte("4242\n")}
	signalReload(context.Background(), run)
	if len(run.calls) != 1 || run.calls[0] != "systemctl --user show -p MainPID --value vpnpa.service" {
		t.Fatalf("show args %v", run.calls)
	}
}

func TestUserHintIsNotAShell(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USER", "alice;touch /tmp/pwned")
	layout := paths.FromHome(home)
	run := &fakeRun{err: os.ErrNotExist}
	var stderr bytes.Buffer
	if code := MainWith([]string{"--config", layout.ConfigPath, "--state-dir", layout.StateDir, "install"}, run, &bytes.Buffer{}, &stderr); code != 0 {
		t.Fatalf("code %d %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "touch") || strings.Contains(stderr.String(), "alice;") {
		t.Fatalf("hint is injectable: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "enable-linger $USER") {
		t.Fatalf("stderr %q", stderr.String())
	}
}

func TestStatusRedactsSecrets(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	layout := paths.FromHome(home)
	if err := os.MkdirAll(layout.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte("{\"current\":\"vpn-1\",\"note\":\"vpn://AAAAAAAAAAAAAAAA\",\"socks\":\"socks5://user:s3cret@127.0.0.1:1081\"}\n")
	if err := os.WriteFile(layout.StatusPath(), body, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := MainWith([]string{"--state-dir", layout.StateDir, "--config", layout.ConfigPath, "status"}, &fakeRun{}, &stdout, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	if strings.Contains(stdout.String(), "s3cret") || strings.Contains(stdout.String(), "AAAA") {
		t.Fatalf("status leaked %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "vpn-1") || !strings.Contains(stdout.String(), "127.0.0.1:1081") {
		t.Fatalf("status lost public fields %q", stdout.String())
	}
}
