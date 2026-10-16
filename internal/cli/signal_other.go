//go:build !windows

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// killProc и чтение /proc подменяются в тестах.
var (
	killProc    = syscall.Kill
	procExe     = func(pid int) (string, error) { return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)) }
	procCmdline = func(pid int) ([]byte, error) {
		return os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)) // #nosec G304 -- pid это числовой MainPID от systemctl
	}
)

// signalReload посылает SIGHUP MainPID user unit. Ошибка systemctl и мёртвый
// сервис тихо пропускаются: add уже записал конфиг, демон подхватит его при старте.
// pid <= 1 отсекается. Перед сигналом isVpnpaRun проверяет, что это всё ещё
// `vpnpa run`, а не чужой процесс, которому достался тот же номер.
func signalReload(ctx context.Context, run Runner) {
	out, err := run.Output(ctx, "systemctl", "--user", "show", "-p", "MainPID", "--value", "vpnpa.service")
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 1 {
		return
	}
	if !isVpnpaRun(pid) {
		return
	}
	_ = killProc(pid, syscall.SIGHUP)
}

// isVpnpaRun сообщает, что pid — демон vpnpa: базовое имя exe равно vpnpa
// и среди аргументов есть "run". Суффикс " (deleted)" снимается: после
// `vpnpa update` ядро помечает так старый inode ещё живого процесса.
// Чужой pid и другая команда того же бинарника сигнал не получают.
func isVpnpaRun(pid int) bool {
	exe, err := procExe(pid)
	if err != nil {
		return false
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	if filepath.Base(exe) != "vpnpa" {
		return false
	}
	raw, err := procCmdline(pid)
	if err != nil {
		return false
	}
	parts := strings.Split(string(raw), "\x00")
	for _, p := range parts[1:] {
		if p == "run" {
			return true
		}
	}
	return false
}
