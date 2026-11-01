package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/LDPet/vpnpa/internal/paths"
)

func TestAddSOCKSUsingAdd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	layout := paths.FromHome(home)
	if _, err := os.Stat(layout.ConfigPath); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := prepareLayout(layout); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	args := []string{"--config", layout.ConfigPath, "--state-dir", layout.StateDir, "add", "--id", "proxy", "socks5://user:secret@127.0.0.1:1081"}
	if code := MainWith(args, &fakeRun{}, &out, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	if strings.Contains(out.String()+stderr.String(), "secret") {
		t.Fatal("password leaked")
	}
	out.Reset()
	stderr.Reset()
	if code := MainWith([]string{"--config", layout.ConfigPath, "list"}, &fakeRun{}, &out, &stderr); code != 0 {
		t.Fatal(stderr.String())
	}
	if !strings.Contains(out.String(), "proxy\tsocks5") {
		t.Fatal(out.String())
	}
}

func TestConfirmations(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	layout := paths.FromHome(home)
	var out, stderr bytes.Buffer
	if code := MainWith([]string{"--state-dir", layout.StateDir, "prefer", "direct"}, &fakeRun{}, &out, &stderr); code != 0 || !strings.Contains(out.String(), "direct") {
		t.Fatalf("%d %s %s", code, out.String(), stderr.String())
	}
	out.Reset()
	stderr.Reset()
	if code := MainWith([]string{"--state-dir", layout.StateDir, "prefer", "unknown"}, &fakeRun{}, &out, &stderr); code == 0 || out.Len() != 0 {
		t.Fatalf("%d %s", code, out.String())
	}
}
