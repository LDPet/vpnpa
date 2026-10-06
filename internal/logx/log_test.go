package logx

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactKeepsHelpAndHidesSecrets(t *testing.T) {
	t.Parallel()
	help := "использование: vpnpa add [--id name] 'vpn://...'"
	if got := Redact(help); got != help {
		t.Fatalf("help changed: %q", got)
	}
	secret := strings.Repeat("A", 32)
	in := "link vpn://" + secret + " socks5://user:s3cret@127.0.0.1:1081 private_key=aabbccdd \"api_key\": \"k\" Api-Key super and endpoint=203.0.113.10:51820"
	got := Redact(in)
	for _, leak := range []string{secret, "s3cret", "aabbccdd", "super"} {
		if strings.Contains(got, leak) {
			t.Fatalf("leaked %q in %q", leak, got)
		}
	}
	if !strings.Contains(got, "203.0.113.10:51820") || !strings.Contains(got, "127.0.0.1:1081") {
		t.Fatalf("public fields dropped: %q", got)
	}
	if !strings.Contains(got, "vpn://<redacted>") {
		t.Fatalf("vpn uri not marked: %q", got)
	}
}

func TestLoggerHidesSecrets(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := New(&buf, "debug", "text")
	log.Warn("битая ссылка", "err", errors.New("vpn://"+strings.Repeat("B", 24)), "endpoint", "203.0.113.10:51820")
	log.Debug("uapi", "config", "private_key=deadbeef\nendpoint=1.2.3.4:51820\n")
	log.Info("socks", "endpoint", "socks5://user:s3cret@10.0.0.1:1080")
	log.Info("uri", "uri", "vpn://SHOULDNOTAPPEAR")
	out := buf.String()
	for _, leak := range []string{"s3cret", "deadbeef", strings.Repeat("B", 24), "SHOULDNOTAPPEAR"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q in %s", leak, out)
		}
	}
	if !strings.Contains(out, "203.0.113.10:51820") || !strings.Contains(out, "1.2.3.4:51820") {
		t.Fatalf("endpoint dropped: %s", out)
	}
	if !log.Enabled(t.Context(), slog.LevelInfo) {
		t.Fatal("info disabled")
	}
}
