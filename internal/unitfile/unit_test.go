package unitfile

import (
	"strings"
	"testing"
)

func TestTextRunsForeground(t *testing.T) {
	text := Text("/home/user/.local/bin/vpnpa", "/home/user/.config/vpnpa/config.yaml", "/home/user/.local/state/vpnpa")
	if !strings.Contains(text, "ExecStart=/home/user/.local/bin/vpnpa run --config /home/user/.config/vpnpa/config.yaml --state-dir /home/user/.local/state/vpnpa") {
		t.Fatalf("exec start:\n%s", text)
	}
	if !strings.Contains(text, "WantedBy=default.target") {
		t.Fatal("not a user unit")
	}
	if !strings.Contains(text, "Restart=on-failure") {
		t.Fatal("no restart policy")
	}
	if strings.Contains(text, "Type=forking") {
		t.Fatal("unit forks")
	}
}
