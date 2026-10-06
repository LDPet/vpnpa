// Package unitfile собирает текст systemd user unit.
// Это unit сессии (`systemctl --user`), не системный: директивы User= нет,
// процесс идёт от пользователя, который сделал `vpnpa install`.
package unitfile

import "strings"

// Text возвращает unit, который пишет `vpnpa install`.
// ExecStart запускает `vpnpa run` на переднем плане (Type=simple) с конфигом
// и каталогом состояния. WantedBy=default.target поднимает сервис при входе
// в пользовательскую сессию. После выхода из сессии он живёт только если
// включён linger (`loginctl enable-linger`), сам unit linger не включает.
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

// systemdArg готовит путь к ExecStart. Обычный путь ~/.local остаётся без кавычек.
// Пробел, кавычка или обратный слэш заключаются в кавычки. Каждый % удваивается:
// иначе systemd прочитает его как спецификатор (%h, %u и т.д.) и подменит путь.
func systemdArg(s string) string {
	s = strings.ReplaceAll(s, "%", "%%")
	if s == "" || strings.ContainsAny(s, " \t\"\\") {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		return `"` + s + `"`
	}
	return s
}
