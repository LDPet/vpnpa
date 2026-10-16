//go:build windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/LDPet/vpnpa/internal/app"
	"github.com/LDPet/vpnpa/internal/logx"
	"github.com/LDPet/vpnpa/internal/paths"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
const runValueName = "vpnpa"

func launchWithoutCommand(configPath, stateDir, level, format string, stderr io.Writer) (int, bool) {
	layout, err := layoutFrom(configPath, stateDir)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1, true
	}
	return runTray(layout, level, format, stderr)
}

func launchTrayCommand(layout paths.Layout, level, format string, stderr io.Writer) (int, bool) {
	return runTray(layout, level, format, stderr)
}

func runTray(layout paths.Layout, level, format string, stderr io.Writer) (int, bool) {
	if err := cmdTray(layout, level, format); err != nil {
		_, _ = fmt.Fprintln(stderr, logx.Redact(err.Error()))
		return 1, true
	}
	return 0, true
}

func foregroundHooks(log *slog.Logger) (runHooks, error) {
	ctx, cancel := context.WithCancel(context.Background())
	var ptr atomic.Pointer[app.App]
	release, err := holdInstance(control{
		reload: func() {
			a := ptr.Load()
			if a == nil {
				return
			}
			if err := a.Reload(context.Background()); err != nil && log != nil {
				log.Warn("ошибка перечитывания конфига", "err", err)
			}
		},
		stop: cancel,
		down: cancel,
	})
	if err != nil {
		cancel()
		return runHooks{}, err
	}
	return runHooks{
		ctx: ctx,
		stop: func() {
			cancel()
			release()
		},
		bind: func(a *app.App) { ptr.Store(a) },
	}, nil
}

func installPrereq(paths.Layout) error { return nil }

func finishInstall(_ context.Context, layout paths.Layout, _ Runner, stderr io.Writer) error {
	_, _ = fmt.Fprintf(stderr, "конфиг: %s\nсостояние: %s\n", layout.ConfigPath, layout.StateDir)
	_, _ = fmt.Fprintln(stderr, "Запустите vpnpa.exe: иконка появится в трее. Автозапуск при входе: vpnpa enable")
	return nil
}

func startProxy(_ context.Context, layout paths.Layout, _ Runner) error {
	if instanceRunning() {
		return signalEvent(eventUp)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return spawnDetached(exe, "--config", layout.ConfigPath, "--state-dir", layout.StateDir, "tray")
}

func cmdDown(_ context.Context, _ paths.Layout, _ Runner) error {
	if !instanceRunning() {
		return fmt.Errorf("vpnpa не запущен")
	}
	if err := signalEvent(eventStop); err != nil {
		return err
	}
	if !waitInstanceGone(10 * time.Second) {
		return fmt.Errorf("vpnpa не остановился")
	}
	return nil
}

func cmdEnable(_ context.Context, _ paths.Layout, _ Runner, stdout io.Writer) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	if err := k.SetStringValue(runValueName, quoteCmdLine(exe)); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, "Автозапуск включён: vpnpa стартует при входе в Windows.")
	return nil
}

func cmdDisable(_ context.Context, _ paths.Layout, _ Runner) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	defer func() { _ = k.Close() }()
	if err := k.DeleteValue(runValueName); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

func cmdLogs(_ context.Context, layout paths.Layout, _ Runner, args []string, stdout io.Writer) error {
	follow := false
	for _, a := range args {
		switch a {
		case "-f", "--follow":
			follow = true
		default:
			return fmt.Errorf("vpnpa logs принимает только -f")
		}
	}
	return tailLog(stdout, logPath(layout), 100, follow)
}

func logPath(layout paths.Layout) string {
	return filepath.Join(layout.StateDir, "vpnpa.log")
}

func spawnDetached(exe string, args ...string) error {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:       true,
		CreationFlags:    windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP,
		NoInheritHandles: true,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
