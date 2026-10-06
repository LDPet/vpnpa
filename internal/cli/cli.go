// Package cli implements the vpnpa commands.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/LDPet/vpnpa/internal/app"
	"github.com/LDPet/vpnpa/internal/atomicfile"
	"github.com/LDPet/vpnpa/internal/config"
	"github.com/LDPet/vpnpa/internal/logx"
	"github.com/LDPet/vpnpa/internal/paths"
	"github.com/LDPet/vpnpa/internal/unitfile"
)

// Runner executes host commands such as systemctl. Tests substitute it.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) error
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner uses os/exec and inherits stdout and stderr for Run.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (ExecRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// Main runs one invocation. args does not include the program name.
func Main(args []string) int {
	return MainWith(args, ExecRunner{}, os.Stdout, os.Stderr)
}

// MainWith is Main with injected dependencies.
func MainWith(args []string, run Runner, stdout, stderr io.Writer) int {
	global, rest := splitGlobal(args)
	fs := flag.NewFlagSet("vpnpa", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to config.yaml")
	logLevel := fs.String("log-level", "", "debug, info, warn or error")
	logFormat := fs.String("log-format", "", "text or json")
	stateDir := fs.String("state-dir", "", "state directory")
	if err := fs.Parse(global); err != nil {
		return 2
	}
	if len(rest) == 0 {
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}
	layout, err := layoutFrom(*configPath, *stateDir)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	ctx := context.Background()
	cmd, cmdArgs := rest[0], rest[1:]
	switch cmd {
	case "install":
		err = cmdInstall(ctx, layout, run, stderr)
	case "add":
		err = cmdAdd(ctx, layout, run, false, cmdArgs, stderr)
	case "add-socks5":
		err = cmdAdd(ctx, layout, run, true, cmdArgs, stderr)
	case "list":
		err = cmdList(layout, stdout)
	case "prefer":
		err = cmdPrefer(layout, cmdArgs)
	case "run":
		err = cmdRun(layout, *logLevel, *logFormat)
	case "up":
		err = cmdUp(ctx, layout, run, stdout)
	case "down":
		err = run.Run(ctx, "systemctl", "--user", "stop", "vpnpa.service")
	case "status":
		err = cmdStatus(layout, stdout)
	case "logs":
		err = cmdLogs(ctx, run, cmdArgs)
	case "enable":
		err = cmdEnable(ctx, run, stdout)
	case "disable":
		err = run.Run(ctx, "systemctl", "--user", "disable", "vpnpa.service")
	case "update":
		err = cmdUpdate(ctx, run, stdout, stderr)
	case "help", "-h", "--help":
		_, _ = fmt.Fprintln(stdout, usage)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "неизвестная команда %q\n%s\n", cmd, usage)
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, logx.Redact(err.Error()))
		return 1
	}
	return 0
}

func layoutFrom(configPath, stateDir string) (paths.Layout, error) {
	layout, err := paths.Default()
	if err != nil {
		if configPath == "" || stateDir == "" {
			return paths.Layout{}, err
		}
		layout = paths.Layout{}
	}
	if configPath != "" {
		layout.ConfigPath = configPath
	}
	if stateDir != "" {
		layout.StateDir = stateDir
	}
	if layout.ConfigPath == "" || layout.StateDir == "" {
		return paths.Layout{}, fmt.Errorf("не заданы пути конфигурации и состояния")
	}
	return layout, nil
}

func cmdInstall(ctx context.Context, layout paths.Layout, run Runner, stderr io.Writer) error {
	if layout.UnitPath == "" || layout.BinPath == "" {
		return fmt.Errorf("не удалось определить путь unit или бинарника")
	}
	if err := ensurePrivateDir(layout.StateDir); err != nil {
		return err
	}
	if err := ensurePrivateDir(layout.KeysDir()); err != nil {
		return err
	}
	if _, err := config.InstallConfig(layout.ConfigPath); err != nil {
		return err
	}
	if err := ensurePrivateDir(filepath.Dir(layout.ConfigPath)); err != nil {
		return err
	}
	if err := os.Chmod(layout.ConfigPath, 0o600); err != nil {
		return err
	}
	text := unitfile.Text(layout.BinPath, layout.ConfigPath, layout.StateDir)
	if err := atomicfile.Write(layout.UnitPath, []byte(text), 0o644); err != nil {
		return err
	}
	if err := run.Run(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
		_, _ = fmt.Fprintf(stderr, "systemctl --user недоступен. Войдите в обычную пользовательскую сессию или выполните: sudo loginctl enable-linger %s\n", currentUser())
	}
	return nil
}

func cmdAdd(ctx context.Context, layout paths.Layout, run Runner, socks bool, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	id := fs.String("id", "", "backend id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		if socks {
			return fmt.Errorf("использование: vpnpa add-socks5 [--id name] 'socks5://...'")
		}
		return fmt.Errorf("использование: vpnpa add [--id name] 'vpn://...'")
	}
	var (
		b   config.Backend
		err error
	)
	if socks {
		b, err = config.AddSOCKS5(layout.ConfigPath, *id, fs.Arg(0))
	} else {
		b, err = config.Add(layout.ConfigPath, *id, fs.Arg(0))
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(layout.ConfigPath, 0o600); err != nil {
		return err
	}
	if err := ensurePrivateDir(filepath.Dir(layout.ConfigPath)); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stderr, "добавлен %s type=%s priority=%d\n", b.ID, b.Type, b.Priority)
	signalReload(ctx, run)
	return nil
}

func cmdList(layout paths.Layout, stdout io.Writer) error {
	f, err := config.Load(layout.ConfigPath)
	if err != nil {
		return err
	}
	if len(f.Backends) == 0 {
		_, _ = fmt.Fprintln(stdout, "бэкендов нет")
		return nil
	}
	for _, b := range f.Backends {
		line := fmt.Sprintf("%s\t%s\tpriority=%d", b.ID, b.Type, b.Priority)
		if b.Type == "socks5" {
			if ep, err := config.SOCKS5Endpoint(b.URI); err == nil {
				line += "\t" + ep
			}
		}
		_, _ = fmt.Fprintln(stdout, logx.Redact(line))
	}
	return nil
}

func cmdPrefer(layout paths.Layout, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("использование: vpnpa prefer <id>|auto")
	}
	choice := args[0]
	if err := ensurePrivateDir(layout.StateDir); err != nil {
		return err
	}
	if choice != "auto" {
		f, err := config.Load(layout.ConfigPath)
		if err != nil {
			return err
		}
		found := false
		for _, b := range f.Backends {
			if b.ID == choice {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("нет бэкенда %q", choice)
		}
	}
	return atomicfile.Write(layout.PreferPath(), []byte(choice+"\n"), 0o600)
}

func cmdRun(layout paths.Layout, level, format string) error {
	f, err := config.Load(layout.ConfigPath)
	if err != nil {
		return err
	}
	if level != "" {
		f.Log.Level = level
	}
	if format != "" {
		f.Log.Format = format
	}
	if err := f.Validate(); err != nil {
		return err
	}
	log := logx.New(os.Stderr, f.Log.Level, f.Log.Format)
	a := app.New(app.Options{
		File:       f,
		ConfigPath: layout.ConfigPath,
		StateDir:   layout.StateDir,
		Logger:     log,
		Signals:    true,
	})
	return a.Run(context.Background())
}

func cmdUp(ctx context.Context, layout paths.Layout, run Runner, stdout io.Writer) error {
	f, err := config.Load(layout.ConfigPath)
	if err != nil {
		return err
	}
	if len(f.Backends) == 0 {
		return fmt.Errorf("список бэкендов пуст, сервис не запущен. Добавьте ссылку: vpnpa add 'vpn://...'")
	}
	if err := run.Run(ctx, "systemctl", "--user", "start", "vpnpa.service"); err != nil {
		return err
	}
	deadline := time.Now().Add(15 * time.Second)
	var dialErr error
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", f.Listen, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			dialErr = nil
			break
		}
		dialErr = err
		time.Sleep(100 * time.Millisecond)
	}
	if dialErr != nil {
		return fmt.Errorf("SOCKS %s не принял соединение: %w", f.Listen, dialErr)
	}
	_, _ = fmt.Fprintf(stdout, "SOCKS5 %s\nHTTP CONNECT %s\n", f.Listen, f.HTTPListen)
	if st, err := os.ReadFile(layout.StatusPath()); err == nil { // #nosec G304 -- путь status.json задаёт раскладка
		text := string(st)
		if i := strings.Index(text, `"current"`); i >= 0 {
			_, _ = fmt.Fprintln(stdout, strings.TrimSpace(logx.Redact(text)))
		}
	}
	return nil
}

func cmdStatus(layout paths.Layout, stdout io.Writer) error {
	raw, err := os.ReadFile(layout.StatusPath()) // #nosec G304 -- путь status.json задаёт раскладка
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

func cmdLogs(ctx context.Context, run Runner, args []string) error {
	follow := false
	for _, a := range args {
		switch a {
		case "-f", "--follow":
			follow = true
		default:
			return fmt.Errorf("vpnpa logs принимает только -f")
		}
	}
	journal := []string{"--user", "-u", "vpnpa.service", "-n", "100", "--no-pager"}
	if follow {
		journal = []string{"--user", "-u", "vpnpa.service", "-n", "100", "-f"}
	}
	return run.Run(ctx, "journalctl", journal...)
}

func cmdEnable(ctx context.Context, run Runner, stdout io.Writer) error {
	if err := run.Run(ctx, "systemctl", "--user", "enable", "vpnpa.service"); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, "Сервис включён и поднимется при входе в сессию.")
	_, _ = fmt.Fprintf(stdout, "После выхода из сессии он живёт, только если включён linger: sudo loginctl enable-linger %s\n", currentUser())
	return nil
}

// killProc and the /proc readers are replaced in tests.
var (
	killProc    = syscall.Kill
	procExe     = func(pid int) (string, error) { return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)) }
	procCmdline = func(pid int) ([]byte, error) {
		return os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)) // #nosec G304 -- pid is the numeric MainPID from systemctl
	}
)

func signalReload(ctx context.Context, run Runner) {
	out, err := run.Output(ctx, "systemctl", "--user", "show", "-p", "MainPID", "--value", "vpnpa.service")
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 1 {
		return
	}
	if !isVpnpaRun(pid) {
		return
	}
	_ = killProc(pid, syscall.SIGHUP)
}

// isVpnpaRun reports whether pid is the vpnpa daemon (argv contains "run"),
// not a recycled PID or another command of the same binary.
func isVpnpaRun(pid int) bool {
	exe, err := procExe(pid)
	if err != nil {
		return false
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	if filepath.Base(exe) != "vpnpa" {
		return false
	}
	raw, err := procCmdline(pid)
	if err != nil {
		return false
	}
	parts := strings.Split(string(raw), "\x00")
	for _, p := range parts[1:] {
		if p == "run" {
			return true
		}
	}
	return false
}

func currentUser() string {
	u := os.Getenv("USER")
	if u == "" {
		cu, err := user.Current()
		if err != nil {
			return "$USER"
		}
		u = cu.Username
	}
	if !safeUser(u) {
		return "$USER"
	}
	return u
}

func safeUser(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
		default:
			return false
		}
	}
	return true
}

// ensurePrivateDir creates path as 0700 and tightens an existing directory
// to 0700. Relative paths and "." are left alone so the process cwd is not chmod'd.
func ensurePrivateDir(path string) error {
	if path == "" || path == "." || !filepath.IsAbs(path) {
		return nil
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s: нужен каталог, не ссылка", path)
	}
	return os.Chmod(path, 0o700) // #nosec G302 -- каталог должен быть 0700, файл секретов остаётся 0600
}

func splitGlobal(args []string) (global, rest []string) {
	takesValue := map[string]bool{
		"--config": true, "--log-level": true, "--log-format": true, "--state-dir": true,
		"-config": true, "-log-level": true, "-log-format": true, "-state-dir": true,
	}
	prefixes := []string{"--config=", "--log-level=", "--log-format=", "--state-dir="}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if takesValue[a] && i+1 < len(args) {
			global = append(global, a, args[i+1])
			i++
			continue
		}
		consumed := false
		for _, p := range prefixes {
			if strings.HasPrefix(a, p) {
				global = append(global, a)
				consumed = true
				break
			}
		}
		if consumed {
			continue
		}
		rest = append(rest, a)
	}
	return global, rest
}

const usage = `vpnpa — локальный прокси поверх AmneziaWG и чужих SOCKS5

Использование:
  vpnpa install
  vpnpa add [--id name] 'vpn://...'
  vpnpa add-socks5 [--id name] 'socks5://...'
  vpnpa list
  vpnpa prefer <id>|auto
  vpnpa run
  vpnpa up
  vpnpa down
  vpnpa status
  vpnpa logs [-f]
  vpnpa enable
  vpnpa disable
  vpnpa update

Флаги: --config, --state-dir, --log-level, --log-format`
