// Package logx configures slog and carries a per-connection id.
package logx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"strings"
)

type ctxKey struct{}

// New builds a logger writing to w. level is info by default; format is text
// by default and json when requested.
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
	return slog.New(h)
}

// WithConnID returns a child context carrying id.
func WithConnID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// ConnID returns the id stored by WithConnID.
func ConnID(ctx context.Context) string {
	v, _ := ctx.Value(ctxKey{}).(string)
	return v
}

// NewConnID returns a short random id safe to log.
func NewConnID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b[:])
}
