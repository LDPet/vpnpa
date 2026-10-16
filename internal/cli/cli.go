// Package cli — команды vpnpa. run крутит демон в этом процессе.
// add и add-socks5 пишут конфиг и шлют SIGHUP живому `vpnpa run`, сверив MainPID.
// prefer только пишет файл. list и status читают файлы. logs зовёт journalctl.
// up, down, enable и disable зовут systemctl --user. update подменяет бинарник
// и перезапускает сервис, только если тот уже active.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/LDPet/vpnpa/internal/app"
	"github.com/LDPet/vpnpa/internal/atomicfile"
	"github.com/LDPet/vpnpa/internal/config"
	"github.com/LDPet/vpnpa/internal/logx"
	"github.com/LDPet/vpnpa/internal/paths"
)

// Runner запускает команды хоста вроде systemctl. Тесты подставляют свою реализацию.
type Runner interface {
	// Run выполняет команду. Ненулевой код возврата становится ошибкой.
	Run(ctx context.Context, name string, args ...string) error
	// Output выполняет команду и возвращает её stdout.
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner зовёт os/exec. Run наследует stdout и stderr процесса,
// чтобы systemctl и journalctl писали туда же, куда vpnpa.
type ExecRunner struct{}

// Run выполняет команду и пробрасывает её код возврата.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Output выполняет команду и возвращает stdout. Так читается MainPID перед SIGHUP.
func (ExecRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// Main выполняет один запуск. args без имени программы.
// Возврат — код процесса: 0, 1 (ошибка) или 2 (пользование).
func Main(args []string) int {
	return MainWith(args, ExecRunner{}, os.Stdout, os.Stderr)
}

// MainWith — Main с подставленными командами хоста и потоками. Нужен тестам.
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
		if code, ok := launchWithoutCommand(*configPath, *stateDir, *logLevel, *logFormat, stderr); ok {
			return code
		}
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
		err = cmdDown(ctx, layout, run)
	case "status":
		err = cmdStatus(layout, stdout)
	case "logs":
		err = cmdLogs(ctx, layout, run, cmdArgs, stdout)
	case "enable":
		err = cmdEnable(ctx, layout, run, stdout)
	case "disable":
		err = cmdDisable(ctx, layout, run)
	case "update":
		err = cmdUpdate(ctx, run, layout, stdout, stderr)
	case "tray":
		if code, ok := launchTrayCommand(layout, *logLevel, *logFormat, stderr); ok {
			return code
		}
		_, _ = fmt.Fprintf(stderr, "неизвестная команда %q\n%s\n", cmd, usage)
		return 2
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

// cmdInstall готовит каталоги и конфиг 0600. Сервис не стартует:
// пустой список бэкендов не должен поднимать слушатели.
// На Linux следом пишется user unit. На Windows unit нет.
func cmdInstall(ctx context.Context, layout paths.Layout, run Runner, stderr io.Writer) error {
	if err := installPrereq(layout); err != nil {
		return err
	}
	if err := prepareLayout(layout); err != nil {
		return err
	}
	return finishInstall(ctx, layout, run, stderr)
}

// prepareLayout создаёт каталоги state и keys и конфиг 0600, если файла ещё нет.
func prepareLayout(layout paths.Layout) error {
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
	return os.Chmod(layout.ConfigPath, 0o600)
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
	// Живой демон подхватывает новую запись по SIGHUP, systemctl restart не нужен.
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

// cmdPrefer записывает id или "auto" в файл prefer. Демон перечитывает его
// на следующем цикле проб, отдельно слать сигнал не нужно.
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

// cmdRun — передний план демона, то, что стоит в ExecStart user unit.
// Сигналы включены: SIGHUP перечитывает конфиг, SIGINT и SIGTERM выходят.
// На Windows тот же процесс ещё слушает события трея: reload и остановка.
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
	hooks, err := foregroundHooks(log)
	if err != nil {
		return err
	}
	defer hooks.stop()
	a := app.New(app.Options{
		File:       f,
		ConfigPath: layout.ConfigPath,
		StateDir:   layout.StateDir,
		Logger:     log,
		Signals:    true,
	})
	hooks.bind(a)
	return a.Run(hooks.ctx)
}

func cmdUp(ctx context.Context, layout paths.Layout, run Runner, stdout io.Writer) error {
	f, err := config.Load(layout.ConfigPath)
	if err != nil {
		return err
	}
	if len(f.Backends) == 0 {
		return errNoBackends()
	}
	if err := startProxy(ctx, layout, run); err != nil {
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

func errNoBackends() error {
	return fmt.Errorf("список бэкендов пуст, сервис не запущен. Добавьте ссылку: vpnpa add 'vpn://...'")
}

// ensurePrivateDir создаёт каталог с правами 0700 и ужимает уже существующий до 0700.
// Относительный путь и "." не трогаются, чтобы не сделать chmod на cwd процесса.
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

// splitGlobal забирает глобальные флаги до имени команды, в том числе
// когда они стоят после неё. Командные флаги (--id) остаются в rest.
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

На Windows запуск без команды открывает трей. install.sh и systemd — только Linux.

Флаги: --config, --state-dir, --log-level, --log-format`
