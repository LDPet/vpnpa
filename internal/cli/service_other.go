//go:build !windows

package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"

	"github.com/LDPet/vpnpa/internal/app"
	"github.com/LDPet/vpnpa/internal/atomicfile"
	"github.com/LDPet/vpnpa/internal/paths"
	"github.com/LDPet/vpnpa/internal/unitfile"
)

func launchWithoutCommand(string, string, string, string, io.Writer) (int, bool) {
	return 0, false
}

func launchTrayCommand(paths.Layout, string, string, io.Writer) (int, bool) {
	return 0, false
}

func foregroundHooks(_ *slog.Logger) (runHooks, error) {
	return runHooks{
		ctx:  context.Background(),
		stop: func() {},
		bind: func(*app.App) {},
	}, nil
}

// installPrereq отказывается писать каталоги, если некуда положить unit или бинарник.
func installPrereq(layout paths.Layout) error {
	if layout.UnitPath == "" || layout.BinPath == "" {
		return fmt.Errorf("не удалось определить путь unit или бинарника")
	}
	return nil
}

// finishInstall пишет user unit и просит systemd перечитать его.
// Сервис не включается и не стартует.
func finishInstall(ctx context.Context, layout paths.Layout, run Runner, stderr io.Writer) error {
	text := unitfile.Text(layout.BinPath, layout.ConfigPath, layout.StateDir)
	if err := atomicfile.Write(layout.UnitPath, []byte(text), 0o644); err != nil {
		return err
	}
	if err := run.Run(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
		_, _ = fmt.Fprintf(stderr, "systemctl --user недоступен. Войдите в обычную пользовательскую сессию или выполните: sudo loginctl enable-linger %s\n", currentUser())
	}
	return nil
}

func startProxy(ctx context.Context, _ paths.Layout, run Runner) error {
	return run.Run(ctx, "systemctl", "--user", "start", "vpnpa.service")
}

func cmdDown(ctx context.Context, _ paths.Layout, run Runner) error {
	return run.Run(ctx, "systemctl", "--user", "stop", "vpnpa.service")
}

func cmdEnable(ctx context.Context, _ paths.Layout, run Runner, stdout io.Writer) error {
	if err := run.Run(ctx, "systemctl", "--user", "enable", "vpnpa.service"); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, "Сервис включён и поднимется при входе в сессию.")
	_, _ = fmt.Fprintf(stdout, "После выхода из сессии он живёт, только если включён linger: sudo loginctl enable-linger %s\n", currentUser())
	return nil
}

func cmdDisable(ctx context.Context, _ paths.Layout, run Runner) error {
	return run.Run(ctx, "systemctl", "--user", "disable", "vpnpa.service")
}

func currentUser() string {
	u := os.Getenv("USER")
	if u == "" {
		cu, err := user.Current()
		if err != nil {
			return "$USER"
		}
		u = cu.Username
	}
	if !safeUser(u) {
		return "$USER"
	}
	return u
}

func safeUser(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
		default:
			return false
		}
	}
	return true
}

func cmdLogs(ctx context.Context, _ paths.Layout, run Runner, args []string, _ io.Writer) error {
	follow := false
	for _, a := range args {
		switch a {
		case "-f", "--follow":
			follow = true
		default:
			return fmt.Errorf("vpnpa logs принимает только -f")
		}
	}
	journal := []string{"--user", "-u", "vpnpa.service", "-n", "100", "--no-pager"}
	if follow {
		journal = []string{"--user", "-u", "vpnpa.service", "-n", "100", "-f"}
	}
	return run.Run(ctx, "journalctl", journal...)
}
