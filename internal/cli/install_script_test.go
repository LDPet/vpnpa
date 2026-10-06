package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallScript(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("install.sh supports linux")
	}
	script := filepath.Join("..", "..", "install.sh")
	payload := []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$VPNPA_LOG\"\nexit 0\n")
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])

	t.Run("rejects root", func(t *testing.T) {
		home := t.TempDir()
		bin := t.TempDir()
		writeFake(t, bin, "id", "#!/bin/sh\nif [ \"$1\" = \"-u\" ]; then echo 0; exit 0; fi\nexit 1\n")
		cmd := exec.Command("/bin/sh", script)
		cmd.Env = []string{"HOME=" + home, "PATH=" + bin + ":/usr/bin:/bin", "USER=root"}
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("root install succeeded: %s", out)
		}
		if !strings.Contains(string(out), "без root") {
			t.Fatalf("output %q", out)
		}
		if _, err := os.Stat(filepath.Join(home, ".local", "bin", "vpnpa")); !os.IsNotExist(err) {
			t.Fatal("binary installed as root")
		}
	})

	t.Run("rejects other os and arch", func(t *testing.T) {
		home := t.TempDir()
		bin := t.TempDir()
		writeFake(t, bin, "uname", "#!/bin/sh\nif [ \"$1\" = \"-s\" ]; then echo Darwin; exit 0; fi\nif [ \"$1\" = \"-m\" ]; then echo x86_64; exit 0; fi\nexit 1\n")
		cmd := exec.Command("/bin/sh", script)
		cmd.Env = []string{"HOME=" + home, "PATH=" + bin + ":/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("darwin succeeded: %s", out)
		}
		if !strings.Contains(string(out), "неподдерживаемая ОС") {
			t.Fatalf("output %q", out)
		}
		writeFake(t, bin, "uname", "#!/bin/sh\nif [ \"$1\" = \"-s\" ]; then echo Linux; exit 0; fi\nif [ \"$1\" = \"-m\" ]; then echo i686; exit 0; fi\nexit 1\n")
		cmd = exec.Command("/bin/sh", script)
		cmd.Env = []string{"HOME=" + home, "PATH=" + bin + ":/usr/bin:/bin"}
		out, err = cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("i686 succeeded: %s", out)
		}
		if !strings.Contains(string(out), "неподдерживаемая архитектура") {
			t.Fatalf("output %q", out)
		}
	})

	t.Run("installs verifies and does not touch config", func(t *testing.T) {
		home := t.TempDir()
		bin, fix := scriptFakes(t, payload, hash, "")
		cfgDir := filepath.Join(home, ".config", "vpnpa")
		if err := os.MkdirAll(cfgDir, 0o700); err != nil {
			t.Fatal(err)
		}
		cfg := filepath.Join(cfgDir, "config.yaml")
		const marker = "listen: 127.0.0.1:1080\n# keep-secret-uri\n"
		if err := os.WriteFile(cfg, []byte(marker), 0o600); err != nil {
			t.Fatal(err)
		}
		log := filepath.Join(home, "log")
		cmd := exec.Command("/bin/sh", script)
		cmd.Env = []string{
			"HOME=" + home,
			"PATH=" + bin + ":/usr/bin:/bin",
			"FIXTURE_DIR=" + fix,
			"VPNPA_LOG=" + log,
			"CURL_LOG=" + filepath.Join(home, "curl.log"),
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("install failed: %v\n%s", err, out)
		}
		got, err := os.ReadFile(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != marker {
			t.Fatalf("config changed: %q", got)
		}
		installed, err := os.ReadFile(filepath.Join(home, ".local", "bin", "vpnpa"))
		if err != nil {
			t.Fatal(err)
		}
		if string(installed) != string(payload) {
			t.Fatalf("binary %q", installed)
		}
		st, err := os.Stat(filepath.Join(home, ".local", "bin", "vpnpa"))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o755 {
			t.Fatalf("mode %o", st.Mode().Perm())
		}
		bash, err := os.ReadFile(filepath.Join(home, ".bashrc"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(bash), `export PATH="$HOME/.local/bin:$PATH"`) {
			t.Fatalf("bashrc %q", bash)
		}
		if !strings.Contains(string(out), "новый терминал") {
			t.Fatalf("no PATH hint: %s", out)
		}
		text, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(text)) != "install" {
			t.Fatalf("vpnpa args %q", text)
		}
		if strings.Contains(string(out), "sudo ") {
			t.Fatalf("script used sudo: %s", out)
		}
	})

	t.Run("second run restarts only an active service", func(t *testing.T) {
		home := t.TempDir()
		bin, fix := scriptFakes(t, payload, hash, "active")
		log := filepath.Join(home, "log")
		// Pretend the binary dir is already on PATH so bashrc is not required.
		dest := filepath.Join(home, ".local", "bin")
		cmd := exec.Command("/bin/sh", script)
		cmd.Env = []string{
			"HOME=" + home,
			"PATH=" + dest + ":" + bin + ":/usr/bin:/bin",
			"FIXTURE_DIR=" + fix,
			"VPNPA_LOG=" + log,
			"SYSTEMCTL_LOG=" + log,
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("update failed: %v\n%s", err, out)
		}
		text, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Fields(string(text))
		joined := string(text)
		if !strings.Contains(joined, "install") || !strings.Contains(joined, "systemctl --user restart vpnpa.service") {
			t.Fatalf("log %q", text)
		}
		if strings.Index(joined, "install") > strings.Index(joined, "restart vpnpa.service") {
			t.Fatalf("restarted before install: %q", text)
		}
		_ = lines
		if _, err := os.Stat(filepath.Join(home, ".bashrc")); err == nil {
			t.Fatal("bashrc touched while PATH already contains the bindir")
		}
	})

	t.Run("inactive service is not restarted", func(t *testing.T) {
		home := t.TempDir()
		bin, fix := scriptFakes(t, payload, hash, "inactive")
		log := filepath.Join(home, "log")
		cmd := exec.Command("/bin/sh", script)
		cmd.Env = []string{
			"HOME=" + home,
			"PATH=" + bin + ":/usr/bin:/bin",
			"FIXTURE_DIR=" + fix,
			"VPNPA_LOG=" + log,
			"SYSTEMCTL_LOG=" + log,
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("install failed: %v\n%s", err, out)
		}
		text, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(text), "restart") {
			t.Fatalf("restarted inactive service: %q", text)
		}
	})

	t.Run("bad checksum does not replace", func(t *testing.T) {
		home := t.TempDir()
		bin, fix := scriptFakes(t, payload, strings.Repeat("ab", 32), "")
		dest := filepath.Join(home, ".local", "bin", "vpnpa")
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/sh", script)
		cmd.Env = []string{"HOME=" + home, "PATH=" + bin + ":/usr/bin:/bin", "FIXTURE_DIR=" + fix}
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("bad checksum succeeded: %s", out)
		}
		got, err := os.ReadFile(dest)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "old" {
			t.Fatalf("binary replaced: %q", got)
		}
	})

	t.Run("does not follow redirect off github", func(t *testing.T) {
		home := t.TempDir()
		bin, fix := scriptFakes(t, payload, hash, "")
		curlLog := filepath.Join(home, "curl.log")
		cmd := exec.Command("/bin/sh", script)
		cmd.Env = []string{
			"HOME=" + home,
			"PATH=" + bin + ":/usr/bin:/bin",
			"FIXTURE_DIR=" + fix,
			"CURL_LOG=" + curlLog,
			"CURL_CODE=302",
			"CURL_LOCATION=https://169.254.169.254/a.githubusercontent.com/b",
		}
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("redirect succeeded: %s", out)
		}
		if !strings.Contains(string(out), "169.254.169.254") && !strings.Contains(string(out), "неожиданный адрес") {
			t.Fatalf("output %q", out)
		}
		raw, err := os.ReadFile(curlLog)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "169.254.169.254") {
			t.Fatalf("fetched metadata URL: %s", raw)
		}
		if _, err := os.Stat(filepath.Join(home, ".local", "bin", "vpnpa")); !os.IsNotExist(err) {
			t.Fatal("binary installed after bad redirect")
		}
	})
}

func scriptFakes(t *testing.T, payload []byte, hash, active string) (bin, fix string) {
	t.Helper()
	bin = t.TempDir()
	fix = t.TempDir()
	asset := "vpnpa-linux-amd64"
	if runtime.GOARCH == "arm64" {
		asset = "vpnpa-linux-arm64"
	}
	if err := os.WriteFile(filepath.Join(fix, "SHA256SUMS"), []byte(hash+"  "+asset+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fix, asset), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	writeFake(t, bin, "curl", fakeCurl)
	if active != "" {
		body := "#!/bin/sh\necho \"systemctl $*\" >> \"$SYSTEMCTL_LOG\"\nif [ \"$2\" = \"is-active\" ]; then\n"
		if active == "active" {
			body += "  exit 0\nfi\nexit 0\n"
		} else {
			body += "  exit 3\nfi\nexit 0\n"
		}
		writeFake(t, bin, "systemctl", body)
	}
	return bin, fix
}

func writeFake(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

const fakeCurl = `#!/bin/sh
out=""
hdr=""
url=""
if [ -n "${CURL_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$CURL_LOG"
fi
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    -D) hdr=$2; shift 2 ;;
    -A|-w|--proto|--proto-redir|--max-redirs) shift 2 ;;
    --tlsv1.2|-sS|-s|-S|-L|-fsSL) shift ;;
    http://*|https://*) url=$1; shift ;;
    *) shift ;;
  esac
done
if [ -z "$out" ] || [ -z "$url" ]; then
  echo "curl: bad args" >&2
  exit 1
fi
base=$(basename "$url")
code=${CURL_CODE:-200}
if [ -n "$hdr" ]; then
  if [ -n "${CURL_LOCATION:-}" ]; then
    printf 'HTTP/1.1 %s\r\nLocation: %s\r\n\r\n' "$code" "$CURL_LOCATION" > "$hdr"
  else
    printf 'HTTP/1.1 %s\r\n\r\n' "$code" > "$hdr"
  fi
fi
if [ "$code" = "200" ]; then
  cp "$FIXTURE_DIR/$base" "$out" || exit 1
fi
printf '%s' "$code"
`
