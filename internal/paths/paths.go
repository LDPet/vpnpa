// Package paths holds the rootless locations vpnpa uses on Linux.
package paths

import (
	"os"
	"path/filepath"
)

const (
	configDirName = "vpnpa"
	stateDirName  = "vpnpa"
)

// Layout is the set of files one vpnpa installation uses.
type Layout struct {
	ConfigPath string
	StateDir   string
	UnitPath   string
	BinPath    string
}

// Default resolves paths under the user's home directory.
func Default() (Layout, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Layout{}, err
	}
	return FromHome(home), nil
}

// FromHome builds a layout rooted at home.
func FromHome(home string) Layout {
	return Layout{
		ConfigPath: filepath.Join(home, ".config", configDirName, "config.yaml"),
		StateDir:   filepath.Join(home, ".local", "state", stateDirName),
		UnitPath:   filepath.Join(home, ".config", "systemd", "user", "vpnpa.service"),
		BinPath:    filepath.Join(home, ".local", "bin", "vpnpa"),
	}
}

// StatusPath is the atomically rewritten daemon status file.
func (l Layout) StatusPath() string {
	return filepath.Join(l.StateDir, "status.json")
}

// PreferPath is reread by the daemon on every probe cycle.
func (l Layout) PreferPath() string {
	return filepath.Join(l.StateDir, "prefer")
}

// KeysDir stores API X25519 keypairs, one file per backend id.
func (l Layout) KeysDir() string {
	return filepath.Join(l.StateDir, "keys")
}
