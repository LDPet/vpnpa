package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LDPet/vpnpa/internal/paths"
)

func TestPreferDirectWithoutConfiguredBackends(t *testing.T) {
	home := t.TempDir()
	layout := paths.FromHome(home)
	if err := os.MkdirAll(filepath.Dir(layout.ConfigPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.ConfigPath, []byte("backends: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmdPrefer(layout, []string{"direct"}); err != nil {
		t.Fatal(err)
	}
	if !readDirectPreference(layout.PreferPath()) {
		t.Fatal("direct preference not saved")
	}
	var out bytes.Buffer
	if err := cmdList(layout, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "direct") {
		t.Fatalf("list = %q", out.String())
	}
	if err := cmdPrefer(layout, []string{"auto"}); err != nil {
		t.Fatal(err)
	}
	if readDirectPreference(layout.PreferPath()) {
		t.Fatal("direct still preferred")
	}
}
