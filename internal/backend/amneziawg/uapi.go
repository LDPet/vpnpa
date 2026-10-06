package amneziawg

import (
	"strings"
)

// BuildUAPI собирает текст IPC amneziawg-go: строки key=value и перевод строки.
// Устройство читает его через IpcSet, отдельного файла конфигурации нет.
// Пустые поля пропускаются, чтобы не затереть умолчания библиотеки.
//
// Порядок как у UAPI: сначала устройство (private_key и параметры обфускации
// AWG 3.1: jc/jmin/jmax, s1–s4, h1–h4, i1–i5, header_protection_key), затем
// пир (public_key, preshared_key, endpoint, allowed_ip).
// Секреты остаются в строке; в лог её можно отдать только через RedactUAPI.
func BuildUAPI(t Tunnel) string {
	var b strings.Builder
	line := func(key, val string) {
		if strings.TrimSpace(val) == "" {
			return
		}
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(strings.TrimSpace(val))
		b.WriteByte('\n')
	}
	line("private_key", t.PrivateKeyHex)
	line("jc", t.JC)
	line("jmin", t.Jmin)
	line("jmax", t.Jmax)
	line("s1", t.S1)
	line("s2", t.S2)
	line("s3", t.S3)
	line("s4", t.S4)
	line("h1", t.H1)
	line("h2", t.H2)
	line("h3", t.H3)
	line("h4", t.H4)
	line("i1", t.I1)
	line("i2", t.I2)
	line("i3", t.I3)
	line("i4", t.I4)
	line("i5", t.I5)
	line("header_protection_key", t.HeaderProtectionKeyHex)
	line("content_padding_addition", t.ContentPaddingAddition)
	line("rekey_after_time", t.RekeyAfterTime)
	line("rekey_timeout", t.RekeyTimeout)
	line("reject_after_time", t.RejectAfterTime)
	line("keepalive_timeout", t.KeepaliveTimeout)
	line("max_handshake_attempts", t.MaxHandshakeAttempts)
	if t.RandomTrailers != "" {
		line("random_trailers", t.RandomTrailers)
	}
	if t.DisableCookies != "" {
		line("disable_cookies", t.DisableCookies)
	}
	line("public_key", t.PublicKeyHex)
	line("preshared_key", t.PresharedHex)
	line("endpoint", t.Endpoint)
	line("persistent_keepalive_interval", t.PersistentKeepalive)
	for _, ip := range t.AllowedIPs {
		line("allowed_ip", ip)
	}
	return b.String()
}

// RedactUAPI прячет перед debug-логом только private_key, preshared_key
// и header_protection_key. public_key пира, endpoint и параметры обфускации
// остаются: по ним видно, что ушло в устройство.
func RedactUAPI(uapi string) string {
	var b strings.Builder
	for _, line := range strings.Split(uapi, "\n") {
		key, _, ok := strings.Cut(line, "=")
		if !ok {
			if line != "" {
				b.WriteString(line)
				b.WriteByte('\n')
			}
			continue
		}
		switch key {
		case "private_key", "preshared_key", "header_protection_key":
			b.WriteString(key)
			b.WriteString("=<redacted>\n")
		default:
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
