//go:build !windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/LDPet/vpnpa/internal/paths"
)

func TestHumanStatus(t *testing.T) {
	home := t.TempDir()
	layout := paths.FromHome(home)
	if err := os.MkdirAll(layout.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	raw := `{"listen":"127.0.0.1:1080","http_listen":"127.0.0.1:8080","current":"home","preference":"auto","egress_ip":"203.0.113.1","backends":[{"id":"home","alive":true}]}`
	if err := os.WriteFile(layout.StatusPath(), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, output, want string
		err                error
	}{
		{"active", "active\n", "Сервис systemd: работает", nil},
		{"inactive", "inactive\n", "может быть устаревшим", nil},
		{"failed", "failed\n", "может быть устаревшим", nil},
		{"unavailable", "", "Состояние сервиса systemd: неизвестно", errors.New("unavailable")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			r := &fakeRun{out: []byte(tc.output), outputErr: tc.err}
			if err := cmdStatus(context.Background(), layout, r, nil, &out); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{tc.want, "home (доступен)", "auto", "127.0.0.1:1080", "127.0.0.1:8080", "203.0.113.1"} {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("missing %q in %q", want, out.String())
				}
			}
			if tc.name == "inactive" && !strings.Contains(out.String(), "отдельно запущенный vpnpa run не проверяется") {
				t.Fatal(out.String())
			}
		})
	}
	if err := os.Remove(layout.StatusPath()); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := cmdStatus(context.Background(), layout, &fakeRun{out: []byte("active\n")}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Снимок состояния отсутствует") {
		t.Fatal(out.String())
	}
	if err := os.WriteFile(layout.StatusPath(), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmdStatus(context.Background(), layout, &fakeRun{}, nil, &out); err == nil {
		t.Fatal("malformed JSON accepted")
	}
}
func TestServiceConfirmations(t *testing.T) {
	for _, command := range []string{"down", "disable"} {
		t.Run(command, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			var out, stderr bytes.Buffer
			if code := MainWith([]string{command}, &fakeRun{}, &out, &stderr); code != 0 || out.Len() == 0 {
				t.Fatalf("%d %q %q", code, out.String(), stderr.String())
			}
			if command == "down" && !strings.Contains(out.String(), "Сервис vpnpa остановлен.") {
				t.Fatal(out.String())
			}
			out.Reset()
			stderr.Reset()
			if code := MainWith([]string{command}, &fakeRun{err: errors.New("failed")}, &out, &stderr); code == 0 || out.Len() != 0 {
				t.Fatalf("%d %q %q", code, out.String(), stderr.String())
			}
		})
	}
}
func TestHumanStatusRedactsAndHandlesDirect(t *testing.T) {
	layout := paths.FromHome(t.TempDir())
	if err := os.MkdirAll(layout.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	raw := `{"current":"direct","preference":"socks5://user:secret@127.0.0.1:1081","backends":[{"id":"direct","direct":true,"health":"unchecked"}]}`
	if err := os.WriteFile(layout.StatusPath(), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := cmdStatus(context.Background(), layout, &fakeRun{out: []byte("active\n")}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "secret") || !strings.Contains(out.String(), "direct (не проверялась)") {
		t.Fatal(out.String())
	}
}
