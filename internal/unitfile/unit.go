// Package unitfile renders the systemd --user unit.
package unitfile

import "fmt"

// Text is the user unit installed by `vpnpa install`.
// ExecStart runs `vpnpa run` in the foreground; systemd owns the lifecycle.
func Text(bin, configPath, stateDir string) string {
	return fmt.Sprintf(`[Unit]
Description=vpnpa local VPN proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run --config %s --state-dir %s
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=default.target
`, bin, configPath, stateDir)
}
