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
	if strings.Contains(text, "User=root") || strings.Contains(text, "sudo") {
		t.Fatalf("unit runs as root:\n%s", text)
	}
	spaced := Text("/home/user name/.local/bin/vpnpa", "/home/user name/.config/vpnpa/config.yaml", "/home/user name/.local/state/vpnpa")
	want := `ExecStart="/home/user name/.local/bin/vpnpa" run --config "/home/user name/.config/vpnpa/config.yaml" --state-dir "/home/user name/.local/state/vpnpa"`
	if !strings.Contains(spaced, want) {
		t.Fatalf("unquoted path would split:\n%s", spaced)
	}
	percent := Text("/home/user/%h/vpnpa", "/home/user/%h/config.yaml", "/home/user/%h/state")
	if strings.Contains(percent, "%h") && !strings.Contains(percent, "%%h") {
		t.Fatalf("systemd would expand %%h:\n%s", percent)
	}
	if !strings.Contains(percent, "/home/user/%%h/vpnpa") {
		t.Fatalf("percent not escaped:\n%s", percent)
	}
}
