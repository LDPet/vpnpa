//go:build windows

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
)

// replaceExecutable не пишет в запущенный exe. Windows позволяет переименовать
// файл работающего процесса; на освободившееся имя встаёт уже проверенный временный файл.
func replaceExecutable(tmp, exe string) error {
	old := exe + ".old"
	if err := os.Remove(old); err != nil && !os.IsNotExist(err) {
		old = exe + ".old-" + strconv.Itoa(os.Getpid())
	}
	moved := false
	if _, err := os.Stat(exe); err == nil {
		if err := os.Rename(exe, old); err != nil {
			return err
		}
		moved = true
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		if moved {
			_ = os.Rename(old, exe)
		}
		return err
	}
	if moved {
		_ = os.Remove(old)
	}
	return nil
}

func restartUpdated(_ context.Context, _ Runner, exe string, stderr io.Writer) error {
	if !instanceRunning() {
		return nil
	}
	_, _ = fmt.Fprintln(stderr, "перезапуск vpnpa")
	if err := signalEvent(eventStop); err != nil {
		return err
	}
	if !waitInstanceGone(10 * time.Second) {
		return fmt.Errorf("vpnpa не остановился")
	}
	return spawnDetached(exe, "tray")
}
