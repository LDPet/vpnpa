// Package unitfile renders the systemd --user unit.
package unitfile

import "strings"

// Text is the user unit installed by `vpnpa install`.
// ExecStart runs `vpnpa run` in the foreground with the user config and state
// directory. There is no User=root: systemd --user starts it as the session user.
func Text(bin, configPath, stateDir string) string {
	return `[Unit]
Description=vpnpa local VPN proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=` + systemdArg(bin) + ` run --config ` + systemdArg(configPath) + ` --state-dir ` + systemdArg(stateDir) + `
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=default.target
`
}

// systemdArg quotes a path that contains whitespace or quotes and doubles %
// so systemd does not treat it as a specifier. Plain paths stay unquoted so
// the unit matches the usual ~/.local layout.
func systemdArg(s string) string {
	s = strings.ReplaceAll(s, "%", "%%")
	if s == "" || strings.ContainsAny(s, " \t\"\\") {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		return `"` + s + `"`
	}
	return s
}
