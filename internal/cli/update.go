package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	releaseBase    = "https://github.com/LDPet/vpnpa/releases/latest/download/"
	maxBinaryBytes = 64 << 20
	maxSumsBytes   = 1 << 20
)

func cmdUpdate(ctx context.Context, run Runner, stdout, stderr io.Writer) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	return updateExe(ctx, defaultReleaseClient(), releaseBase, exe, validateReleaseURL, run, stdout, stderr)
}

func defaultReleaseClient() *http.Client {
	return &http.Client{
		Timeout:       2 * time.Minute,
		CheckRedirect: releaseRedirect,
	}
}

// releaseRedirect refuses hops that leave the GitHub release hosts or https.
func releaseRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("слишком много перенаправлений")
	}
	return validateReleaseURL(req.URL)
}

func updateExe(ctx context.Context, client *http.Client, base, exe string, policy func(*url.URL) error, run Runner, stdout, stderr io.Writer) error {
	asset, err := releaseAsset()
	if err != nil {
		return err
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	sums, err := httpGet(ctx, client, base+"SHA256SUMS", maxSumsBytes, policy)
	if err != nil {
		return fmt.Errorf("SHA256SUMS: %w", err)
	}
	want, err := checksumFor(string(sums), asset)
	if err != nil {
		return err
	}
	dir := filepath.Dir(exe)
	f, err := os.CreateTemp(dir, ".vpnpa-update-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	installed := false
	defer func() {
		if !installed {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	n, err := downloadTo(ctx, client, base+asset, f, maxBinaryBytes, policy)
	if err != nil {
		return fmt.Errorf("скачивание %s: %w", asset, err)
	}
	if n == 0 {
		return fmt.Errorf("пустой файл %s", asset)
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	got, err := hashReader(f)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("sha256 не совпала для %s", asset)
	}
	if err := f.Chmod(0o755); err != nil { // #nosec G302 -- бинарник в ~/.local/bin должен быть исполняемым
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		return err
	}
	installed = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	_, _ = fmt.Fprintf(stdout, "обновлено %s\n", exe)
	if serviceActive(ctx, run) {
		_, _ = fmt.Fprintln(stderr, "перезапуск vpnpa.service")
		if err := run.Run(ctx, "systemctl", "--user", "restart", "vpnpa.service"); err != nil {
			return err
		}
	}
	return nil
}

func releaseAsset() (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("неподдерживаемая ОС %s", runtime.GOOS)
	}
	switch runtime.GOARCH {
	case "amd64":
		return "vpnpa-linux-amd64", nil
	case "arm64":
		return "vpnpa-linux-arm64", nil
	default:
		return "", fmt.Errorf("неподдерживаемая архитектура %s", runtime.GOARCH)
	}
}

func checksumFor(sums, name string) (string, error) {
	var found string
	for _, line := range strings.Split(sums, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		line = strings.TrimPrefix(line, "\\")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		base := strings.TrimPrefix(fields[len(fields)-1], "*")
		if filepath.Base(base) != name {
			continue
		}
		sum := strings.ToLower(fields[0])
		if len(sum) != sha256.Size*2 || !isHex(sum) {
			return "", fmt.Errorf("плохая сумма sha256 для %s", name)
		}
		if found != "" && found != sum {
			return "", fmt.Errorf("противоречивые суммы для %s", name)
		}
		found = sum
	}
	if found == "" {
		return "", fmt.Errorf("в SHA256SUMS нет %s", name)
	}
	return found, nil
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

func httpGet(ctx context.Context, client *http.Client, rawURL string, limit int64, policy func(*url.URL) error) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if policy != nil {
		if err := policy(u); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vpnpa")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", redactURL(u), resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("ответ %s слишком большой", redactURL(u))
	}
	return body, nil
}

func downloadTo(ctx context.Context, client *http.Client, rawURL string, dst *os.File, limit int64, policy func(*url.URL) error) (int64, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0, err
	}
	if policy != nil {
		if err := policy(u); err != nil {
			return 0, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "vpnpa")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GET %s: %s", redactURL(u), resp.Status)
	}
	n, err := io.Copy(dst, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return n, err
	}
	if n > limit {
		return n, fmt.Errorf("файл %s слишком большой", redactURL(u))
	}
	return n, nil
}

func hashReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	c.RawQuery = ""
	c.Fragment = ""
	c.User = nil
	return c.String()
}

func validateReleaseURL(u *url.URL) error {
	if u == nil {
		return errors.New("пустой адрес релиза")
	}
	if u.Scheme != "https" {
		return errors.New("адрес релиза должен быть https")
	}
	if u.User != nil {
		return errors.New("адрес релиза не должен содержать пароль")
	}
	host := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(host); ip != nil && ipBlocked(ip) {
		return fmt.Errorf("адрес релиза %s не разрешён", host)
	}
	if !releaseHostOK(host) {
		return fmt.Errorf("адрес релиза %s не разрешён", host)
	}
	return nil
}

func releaseHostOK(host string) bool {
	switch host {
	case "github.com",
		"release-assets.githubusercontent.com",
		"objects.githubusercontent.com",
		"github-releases.githubusercontent.com":
		return true
	}
	if strings.HasSuffix(host, ".githubusercontent.com") && !strings.Contains(host, "..") {
		return true
	}
	return false
}

func ipBlocked(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	if addr.Is4() {
		b := addr.As4()
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
			return true
		}
	}
	return false
}

func serviceActive(ctx context.Context, run Runner) bool {
	out, err := run.Output(ctx, "systemctl", "--user", "is-active", "vpnpa.service")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}
