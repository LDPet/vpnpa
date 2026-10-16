// Package paths — каталоги установки vpnpa без root и без /etc.
// На Linux это домашний каталог: конфиг, state, user unit и бинарник.
// На Windows конфиг и state лежат в %AppData%\vpnpa, unit нет.
package paths

import (
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

// FromHome строит Linux-раскладку от заданного home. Удобно в тестах и при установке.
// На Windows Default этим путём не пользуется.
func FromHome(home string) Layout {
	return Layout{
		ConfigPath: filepath.Join(home, ".config", configDirName, "config.yaml"),
		StateDir:   filepath.Join(home, ".local", "state", stateDirName),
		UnitPath:   filepath.Join(home, ".config", "systemd", "user", "vpnpa.service"),
		BinPath:    filepath.Join(home, ".local", "bin", "vpnpa"),
	}
}

// FromAppData строит Windows-раскладку от каталога %AppData% (или его аналога в тесте).
// Unit нет: автозапуск — запись HKCU Run, не systemd. BinPath заполняет Default
// из пути исполняемого файла, здесь он пустой.
func FromAppData(appData string) Layout {
	base := filepath.Join(appData, configDirName)
	return Layout{
		ConfigPath: filepath.Join(base, "config.yaml"),
		StateDir:   filepath.Join(base, "state"),
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
