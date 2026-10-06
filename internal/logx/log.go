// Package logx настраивает slog и прячет секреты до того, как строка попадёт в журнал.
// Сюда же кладётся короткий id соединения, чтобы связать строки одного dial.
package logx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"regexp"
	"strings"
)

type ctxKey struct{}

// New собирает логер в w. По умолчанию уровень info и текстовый формат;
// format "json" включает JSON. Значения, похожие на vpn://, пароль SOCKS,
// API-ключ или ключ UAPI, заменяются до записи.
func New(w io.Writer, level, format string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if strings.EqualFold(strings.TrimSpace(format), "json") {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(redactHandler{next: h})
}

// Redact прячет секреты в уже собранной строке: лог, stderr команды, status.
// Заглушка vpn://... из текста справки не трогается — в ней нет ключа.
func Redact(s string) string {
	if s == "" {
		return s
	}
	s = vpnURIRe.ReplaceAllStringFunc(s, redactVPN)
	s = socksUserRe.ReplaceAllString(s, "socks5://<redacted>@")
	s = uapiKeyRe.ReplaceAllString(s, "${1}${2}<redacted>")
	s = wgKeyRe.ReplaceAllString(s, "${1}${2}<redacted>")
	s = jsonSecretRe.ReplaceAllString(s, `${1}<redacted>${3}`)
	s = assignSecretRe.ReplaceAllString(s, "${1}${2}<redacted>")
	s = apiHeaderRe.ReplaceAllString(s, "${1}<redacted>")
	return s
}

func redactVPN(m string) string {
	payload := strings.TrimPrefix(m, "vpn://")
	trimmed := strings.TrimRight(payload, ".,;:)]}")
	if trimmed == "" || trimmed == "..." || !containsAlnum(trimmed) {
		return m
	}
	return "vpn://<redacted>" + payload[len(trimmed):]
}

func containsAlnum(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return true
		}
	}
	return false
}

var (
	vpnURIRe       = regexp.MustCompile(`vpn://[^\s'"<>]+`)
	socksUserRe    = regexp.MustCompile(`socks5://[^\s/@]+@`)
	uapiKeyRe      = regexp.MustCompile(`(?i)\b(private_key|preshared_key|header_protection_key)(=)([^\s]+)`)
	wgKeyRe        = regexp.MustCompile(`(?i)\b(PrivateKey|PresharedKey|HeaderProtectionKey)(\s*=\s*)(\S+)`)
	jsonSecretRe   = regexp.MustCompile(`(?i)("(?:api_key|private_key|preshared_key|password|private)"\s*:\s*")([^"]*)(")`)
	assignSecretRe = regexp.MustCompile(`(?i)\b(api_key|password)(\s*[=:]\s*)(\S+)`)
	apiHeaderRe    = regexp.MustCompile(`(?i)(Api-Key\s+)\S+`)
)

type redactHandler struct {
	next slog.Handler
}

func (h redactHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h redactHandler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, Redact(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(redactAttr(a))
		return true
	})
	return h.next.Handle(ctx, nr)
}

func (h redactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		red[i] = redactAttr(a)
	}
	return redactHandler{next: h.next.WithAttrs(red)}
}

func (h redactHandler) WithGroup(name string) slog.Handler {
	return redactHandler{next: h.next.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	switch strings.ToLower(a.Key) {
	case "uri", "password", "api_key", "private_key", "preshared_key", "preshared", "authorization":
		a.Value = slog.StringValue("<redacted>")
		return a
	}
	a.Value = redactValue(a.Value)
	return a
}

func redactValue(v slog.Value) slog.Value {
	switch v.Kind() {
	case slog.KindString:
		return slog.StringValue(Redact(v.String()))
	case slog.KindGroup:
		as := v.Group()
		out := make([]slog.Attr, len(as))
		for i, a := range as {
			out[i] = redactAttr(a)
		}
		return slog.GroupValue(out...)
	case slog.KindAny:
		if err, ok := v.Any().(error); ok && err != nil {
			return slog.StringValue(Redact(err.Error()))
		}
		return v
	default:
		return v
	}
}

// WithConnID кладёт id в контекст соединения. Ingress ставит его до dial,
// чтобы строки лога одного клиента несли один conn_id.
func WithConnID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// ConnID возвращает id, записанный WithConnID. Пустая строка, если его не было.
func ConnID(ctx context.Context) string {
	v, _ := ctx.Value(ctxKey{}).(string)
	return v
}

// NewConnID возвращает короткий случайный id, который можно писать в лог.
// Это не секрет и не идентификатор клиента снаружи.
func NewConnID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b[:])
}
