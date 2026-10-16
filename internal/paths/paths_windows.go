//go:build windows

package paths

import (
	"os"
	"path/filepath"
)

// Default строит раскладку в %AppData%\vpnpa.
// Домашний каталог и Linux-пути ~/.config и ~/.local не используются.
func Default() (Layout, error) {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return Layout{}, err
		}
		appData = dir
	}
	layout := FromAppData(appData)
	exe, err := os.Executable()
	if err != nil {
		return layout, nil
	}
	abs, err := filepath.Abs(exe)
	if err != nil {
		return layout, nil
	}
	layout.BinPath = abs
	return layout, nil
}
