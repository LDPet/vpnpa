// Package paths — каталоги rootless-установки vpnpa на Linux.
// Всё лежит в домашнем каталоге пользователя: конфиг, state, user unit и бинарник.
// root и /etc не используются.
package paths

import (
	"os"
	"path/filepath"
)

const (
	configDirName = "vpnpa"
	stateDirName  = "vpnpa"
)

// Layout — файлы одной установки vpnpa.
type Layout struct {
	// ConfigPath — ~/.config/vpnpa/config.yaml, права 0600: в URI есть ключ или пароль.
	ConfigPath string
	// StateDir — ~/.local/state/vpnpa: status.json, prefer и каталог keys.
	StateDir string
	// UnitPath — ~/.config/systemd/user/vpnpa.service, не системный unit.
	UnitPath string
	// BinPath — ~/.local/bin/vpnpa, его подменяет `vpnpa update` через rename.
	BinPath string
}

// Default строит раскладку от домашнего каталога текущего пользователя.
func Default() (Layout, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Layout{}, err
	}
	return FromHome(home), nil
}

// FromHome строит раскладку от заданного home. Удобно в тестах и при установке.
func FromHome(home string) Layout {
	return Layout{
		ConfigPath: filepath.Join(home, ".config", configDirName, "config.yaml"),
		StateDir:   filepath.Join(home, ".local", "state", stateDirName),
		UnitPath:   filepath.Join(home, ".config", "systemd", "user", "vpnpa.service"),
		BinPath:    filepath.Join(home, ".local", "bin", "vpnpa"),
	}
}

// StatusPath — status.json. Демон переписывает его целиком через rename на каждом цикле проб.
func (l Layout) StatusPath() string {
	return filepath.Join(l.StateDir, "status.json")
}

// PreferPath — файл prefer. Балансировщик перечитывает его на каждом цикле проб,
// отдельный сигнал для смены предпочтения не нужен.
func (l Layout) PreferPath() string {
	return filepath.Join(l.StateDir, "prefer")
}

// KeysDir — каталог пар X25519 для API-ссылок, по файлу на id бэкенда.
// Пара переиспользуется, пока URI не изменился.
func (l Layout) KeysDir() string {
	return filepath.Join(l.StateDir, "keys")
}
