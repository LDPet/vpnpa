package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/LDPet/vpnpa/internal/logx"
	"github.com/LDPet/vpnpa/internal/paths"
)

// tailLog печатает последние n строк файла. follow дочитывает новые байты,
// пока процесс не остановят. Секреты прогоняются через logx.Redact ещё раз.
func tailLog(w io.Writer, path string, n int, follow bool) error {
	f, err := os.Open(path) // #nosec G304 -- путь лога задаёт каталог состояния
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("нет лога, vpnpa не запущен")
		}
		return err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	if err := writeLastLines(w, raw, n); err != nil {
		return err
	}
	if !follow {
		return nil
	}
	off, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	buf := make([]byte, 4096)
	for {
		time.Sleep(400 * time.Millisecond)
		st, err := f.Stat()
		if err != nil {
			return err
		}
		if st.Size() < off {
			off = 0
		}
		if st.Size() == off {
			continue
		}
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return err
		}
		for {
			nr, rerr := f.Read(buf)
			if nr > 0 {
				if _, err := io.WriteString(w, logx.Redact(string(buf[:nr]))); err != nil {
					return err
				}
				off += int64(nr)
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				return rerr
			}
		}
	}
}

func writeLastLines(w io.Writer, raw []byte, n int) error {
	if n <= 0 {
		return nil
	}
	parts := bytes.Split(raw, []byte("\n"))
	if len(parts) > 0 && len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}
	if len(parts) > n {
		parts = parts[len(parts)-n:]
	}
	for _, ln := range parts {
		if _, err := fmt.Fprintln(w, logx.Redact(string(ln))); err != nil {
			return err
		}
	}
	return nil
}

// trayLaunchArgs — аргументы фонового процесса с теми же config и state,
// что у команды, которая его породила. Голый `tray` сбросил бы пути на AppData.
func trayLaunchArgs(layout paths.Layout) []string {
	args := make([]string, 0, 5)
	if layout.ConfigPath != "" {
		args = append(args, "--config", layout.ConfigPath)
	}
	if layout.StateDir != "" {
		args = append(args, "--state-dir", layout.StateDir)
	}
	args = append(args, "tray")
	return args
}

// autostartCommand — строка для HKCU Run: exe и те же пути, что у enable.
func autostartCommand(exe string, layout paths.Layout) string {
	parts := make([]string, 0, 6)
	parts = append(parts, quoteCmdLine(exe))
	for _, a := range trayLaunchArgs(layout) {
		parts = append(parts, quoteCmdLine(a))
	}
	return strings.Join(parts, " ")
}

// quoteCmdLine готовит один аргумент командной строки Windows.
// Путь без пробелов и кавычек остаётся как есть.
func quoteCmdLine(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			slashes++
		case '"':
			for n := 0; n < slashes*2+1; n++ {
				b.WriteByte('\\')
			}
			b.WriteByte('"')
			slashes = 0
		default:
			for n := 0; n < slashes; n++ {
				b.WriteByte('\\')
			}
			slashes = 0
			b.WriteByte(s[i])
		}
	}
	for n := 0; n < slashes*2; n++ {
		b.WriteByte('\\')
	}
	b.WriteByte('"')
	return b.String()
}

// menuLabel прячет мнемонику Windows: одиночный & подчёркивает следующую букву.
func menuLabel(s string) string {
	return strings.ReplaceAll(s, "&", "&&")
}

// trayStatusText — строка пункта трея. haveFresh значит, что status.json
// уже записан этим запуском, а не остался от прошлого процесса.
func trayStatusText(running, haveFresh bool, current string, alive bool) string {
	if !running {
		return "vpnpa выключен"
	}
	if !haveFresh {
		return "запуск…"
	}
	if current == "" {
		return "нет живого бэкенда"
	}
	if alive {
		return "текущий: " + current
	}
	return "текущий: " + current + ", не жив"
}

// shortNote укорачивает ошибку для пункта меню и вырезает секреты.
func shortNote(err error) string {
	if err == nil {
		return ""
	}
	msg := logx.Redact(err.Error())
	const max = 80
	r := []rune(msg)
	if len(r) > max {
		msg = string(r[:max])
	}
	return msg
}
