//go:build !windows

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/LDPet/vpnpa/internal/paths"
)

func replaceExecutable(tmp, exe string) error {
	return os.Rename(tmp, exe)
}

func restartUpdated(ctx context.Context, run Runner, _ string, _ paths.Layout, stderr io.Writer) error {
	if !serviceActive(ctx, run) {
		return nil
	}
	_, _ = fmt.Fprintln(stderr, "перезапуск vpnpa.service")
	return run.Run(ctx, "systemctl", "--user", "restart", "vpnpa.service")
}

func serviceActive(ctx context.Context, run Runner) bool {
	out, err := run.Output(ctx, "systemctl", "--user", "is-active", "vpnpa.service")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}
