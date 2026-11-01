package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/LDPet/vpnpa/internal/balance/sticky"
	"github.com/LDPet/vpnpa/internal/logx"
	"github.com/LDPet/vpnpa/internal/paths"
)

// cmdStatus preserves the original JSON output for scripts and Windows.
func cmdStatus(ctx context.Context, layout paths.Layout, run Runner, args []string, stdout io.Writer) error {
	jsonOutput := false
	for _, arg := range args {
		if arg != "--json" || jsonOutput {
			return fmt.Errorf("использование: vpnpa status [--json]")
		}
		jsonOutput = true
	}
	raw, err := os.ReadFile(layout.StatusPath()) // #nosec G304 -- путь задаёт layout
	if jsonOutput || runtime.GOOS == "windows" {
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("нет файла состояния, сервис не запущен")
			}
			return err
		}
		_, _ = fmt.Fprint(stdout, logx.Redact(string(raw)))
		if len(raw) == 0 || raw[len(raw)-1] != '\n' {
			_, _ = fmt.Fprintln(stdout)
		}
		return nil
	}

	service := serviceState(ctx, run)
	switch service {
	case "active":
		_, _ = fmt.Fprintln(stdout, "Сервис systemd: работает")
	case "inactive", "failed":
		_, _ = fmt.Fprintf(stdout, "Сервис systemd: остановлен (%s); отдельно запущенный vpnpa run не проверяется\n", service)
	default:
		_, _ = fmt.Fprintln(stdout, "Состояние сервиса systemd: неизвестно")
	}
	if err != nil {
		if os.IsNotExist(err) {
			_, _ = fmt.Fprintln(stdout, "Снимок состояния отсутствует.")
			return nil
		}
		return err
	}
	var st sticky.Status
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("не удалось прочитать снимок состояния: некорректный JSON")
	}
	if service == "inactive" || service == "failed" {
		_, _ = fmt.Fprintln(stdout, "Снимок состояния может быть устаревшим.")
	} else {
		_, _ = fmt.Fprintln(stdout, "Последний снимок состояния (актуальность не подтверждена):")
	}
	current := st.Current
	if current == "" {
		current = "не выбран"
	}
	availability := "неизвестна"
	for _, b := range st.Backends {
		if b.ID == st.Current && st.Current != "" {
			switch {
			case b.Direct || b.Health == "unchecked":
				availability = "не проверялась"
			case b.Waiting:
				availability = "ожидает активации"
			case b.Alive:
				availability = "доступен"
			default:
				availability = "недоступен"
			}
			break
		}
	}
	preference := st.Preference
	if preference == "" {
		preference = "неизвестно"
	}
	_, _ = fmt.Fprintf(stdout, "Выход: %s (%s)\nПредпочтение: %s\n", logx.Redact(current), availability, logx.Redact(preference))
	if st.Listen != "" {
		_, _ = fmt.Fprintf(stdout, "SOCKS5: %s\n", logx.Redact(st.Listen))
	}
	if st.HTTPListen != "" {
		_, _ = fmt.Fprintf(stdout, "HTTP CONNECT: %s\n", logx.Redact(st.HTTPListen))
	}
	if st.EgressIP != "" {
		_, _ = fmt.Fprintf(stdout, "Внешний IP: %s\n", logx.Redact(st.EgressIP))
	}
	return nil
}

func serviceState(ctx context.Context, run Runner) string {
	raw, err := run.Output(ctx, "systemctl", "--user", "show", "--property=ActiveState", "--value", "vpnpa.service")
	if err != nil {
		return "unknown"
	}
	switch state := strings.TrimSpace(string(raw)); state {
	case "active", "inactive", "failed":
		return state
	default:
		return "unknown"
	}
}
