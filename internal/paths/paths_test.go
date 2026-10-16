package paths

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestFromHomeLinuxLayout(t *testing.T) {
	home := filepath.Join("home", "alice")
	got := FromHome(home)
	if got.ConfigPath != filepath.Join(home, ".config", "vpnpa", "config.yaml") {
		t.Fatalf("config %s", got.ConfigPath)
	}
	if got.StateDir != filepath.Join(home, ".local", "state", "vpnpa") {
		t.Fatalf("state %s", got.StateDir)
	}
	if got.UnitPath != filepath.Join(home, ".config", "systemd", "user", "vpnpa.service") {
		t.Fatalf("unit %s", got.UnitPath)
	}
	if got.BinPath != filepath.Join(home, ".local", "bin", "vpnpa") {
		t.Fatalf("bin %s", got.BinPath)
	}
}

func TestFromAppDataHasNoUnit(t *testing.T) {
	root := filepath.Join("appdata")
	got := FromAppData(root)
	if got.ConfigPath != filepath.Join(root, "vpnpa", "config.yaml") {
		t.Fatalf("config %s", got.ConfigPath)
	}
	if got.StateDir != filepath.Join(root, "vpnpa", "state") {
		t.Fatalf("state %s", got.StateDir)
	}
	if got.UnitPath != "" || got.BinPath != "" {
		t.Fatalf("windows layout has unit or bin: %+v", got)
	}
	if got.StatusPath() != filepath.Join(root, "vpnpa", "state", "status.json") {
		t.Fatalf("status %s", got.StatusPath())
	}
	if got.KeysDir() != filepath.Join(root, "vpnpa", "state", "keys") {
		t.Fatalf("keys %s", got.KeysDir())
	}
	if got.PreferPath() != filepath.Join(root, "vpnpa", "state", "prefer") {
		t.Fatalf("prefer %s", got.PreferPath())
	}
}

func TestDefaultUsesHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows default is AppData")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	got, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	want := FromHome(home)
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
}
