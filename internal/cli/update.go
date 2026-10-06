package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const releaseBase = "https://github.com/LDPet/vpnpa/releases/latest/download/"

func cmdUpdate(ctx context.Context, run Runner, stdout, stderr io.Writer) error {
	asset, err := releaseAsset()
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	sums, err := httpGet(ctx, client, releaseBase+"SHA256SUMS")
	if err != nil {
		return fmt.Errorf("SHA256SUMS: %w", err)
	}
	want, err := checksumFor(string(sums), asset)
	if err != nil {
		return err
	}
	bin, err := httpGet(ctx, client, releaseBase+asset)
	if err != nil {
		return fmt.Errorf("скачивание %s: %w", asset, err)
	}
	sum := sha256.Sum256(bin)
	if hex.EncodeToString(sum[:]) != want {
		return fmt.Errorf("sha256 не совпала для %s", asset)
	}
	if err := replaceBinary(exe, bin); err != nil {
		return err
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
	for _, line := range strings.Split(sums, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && filepath.Base(fields[len(fields)-1]) == name {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("в SHA256SUMS нет %s", name)
}

func httpGet(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
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
		return nil, fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

func replaceBinary(exe string, data []byte) error {
	dir := filepath.Dir(exe)
	f, err := os.CreateTemp(dir, ".vpnpa-update-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o755); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		return err
	}
	ok = true
	return nil
}

func serviceActive(ctx context.Context, run Runner) bool {
	out, err := run.Output(ctx, "systemctl", "--user", "is-active", "vpnpa.service")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}
