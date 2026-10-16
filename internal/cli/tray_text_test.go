package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/LDPet/vpnpa/internal/paths"
)

func TestTrayStatusText(t *testing.T) {
	if got := trayStatusText(false, true, "vpn-1", true); got != "vpnpa выключен" {
		t.Fatalf("%q", got)
	}
	if got := trayStatusText(true, false, "vpn-1", true); got != "запуск…" {
		t.Fatalf("%q", got)
	}
	if got := trayStatusText(true, true, "", false); got != "нет живого бэкенда" {
		t.Fatalf("%q", got)
	}
	if got := trayStatusText(true, true, "vpn-1", true); got != "текущий: vpn-1" {
		t.Fatalf("%q", got)
	}
	if got := trayStatusText(true, true, "vpn-1", false); got != "текущий: vpn-1, не жив" {
		t.Fatalf("%q", got)
	}
}

func TestQuoteCmdLine(t *testing.T) {
	if got := quoteCmdLine(`C:\vpnpa.exe`); got != `C:\vpnpa.exe` {
		t.Fatalf("%q", got)
	}
	if got := quoteCmdLine(`C:\Program Files\vpnpa.exe`); got != `"C:\Program Files\vpnpa.exe"` {
		t.Fatalf("%q", got)
	}
	if got := quoteCmdLine(""); got != `""` {
		t.Fatalf("%q", got)
	}
}

func TestTrayLaunchArgsKeepPaths(t *testing.T) {
	layout := paths.Layout{ConfigPath: `C:\Program Files\vpnpa\config.yaml`, StateDir: `D:\state`}
	got := trayLaunchArgs(layout)
	want := []string{"--config", layout.ConfigPath, "--state-dir", layout.StateDir, "tray"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("%q", got)
	}
	cmd := autostartCommand(`C:\Program Files\vpnpa.exe`, layout)
	if cmd != `"C:\Program Files\vpnpa.exe" --config "C:\Program Files\vpnpa\config.yaml" --state-dir D:\state tray` {
		t.Fatalf("%q", cmd)
	}
}

func TestMenuLabelEscapesAmpersand(t *testing.T) {
	if got := menuLabel("a&b"); got != "a&&b" {
		t.Fatalf("%q", got)
	}
}

func TestShortNoteRedactsAndCuts(t *testing.T) {
	err := errString("vpn://super-secret-key-value " + strings.Repeat("я", 100))
	got := shortNote(err)
	if strings.Contains(got, "super-secret") || strings.Contains(got, "vpn://super") {
		t.Fatalf("secret leaked %q", got)
	}
	if len([]rune(got)) > 80 {
		t.Fatalf("len %d %q", len([]rune(got)), got)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestTailLogLastLines(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/vpnpa.log"
	body := "one\ntwo vpn://secretvalue\nthree\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := tailLog(&buf, path, 2, false); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if strings.Contains(got, "one\n") || strings.Contains(got, "secretvalue") || strings.Contains(got, "vpn://secret") {
		t.Fatalf("tail %q", got)
	}
	if !strings.Contains(got, "two ") || !strings.Contains(got, "three") {
		t.Fatalf("tail %q", got)
	}
}
