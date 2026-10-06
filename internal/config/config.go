// Package config читает и пишет единственный YAML vpnpa.
// Файл всегда 0600: в URI vpn:// лежит приватный ключ, в socks5:// может быть пароль.
package config

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// FileMode обязателен: в URI vpn:// есть приватный ключ, в socks5:// может быть пароль.
	FileMode os.FileMode = 0o600

	// DefaultListen — SOCKS5 на loopback, если в файле поле опущено.
	DefaultListen = "127.0.0.1:1080"
	// DefaultHTTPListen — HTTP CONNECT на loopback. Порт нарочно другой, чем у SOCKS5.
	DefaultHTTPListen = "127.0.0.1:8080"
	// DefaultBalancer — единственный реализованный тип балансировщика.
	DefaultBalancer = "sticky"
)

// DefaultCheckURLs опрашиваются по порядку. Первый HTTP 204 выигрывает,
// второй остаётся запасным, если первый URL недоступен. Непустой check_urls
// в файле заменяет эту пару целиком, а не дополняет её.
var DefaultCheckURLs = []string{
	"https://www.gstatic.com/generate_204",
	"https://cp.cloudflare.com/generate_204",
}

// Duration — строка YAML вида "15s" или "5m", не число наносекунд.
type Duration time.Duration

// UnmarshalYAML разбирает строку длительности Go.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("duration: %w", err)
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML пишет длительность строкой Go, чтобы файл оставался читаемым.
func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

// Std возвращает длительность стандартной библиотеки.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// File — документ на диске. Неизвестные поля YAML отвергаются.
type File struct {
	Listen     string    `yaml:"listen"`
	HTTPListen string    `yaml:"http_listen"`
	Balancer   Balancer  `yaml:"balancer"`
	Backends   []Backend `yaml:"backends"`
	Log        Log       `yaml:"log"`
}

// Balancer — блок sticky. Ноль и пустые строки добираются в applyDefaults.
type Balancer struct {
	Type             string   `yaml:"type"`
	CheckInterval    Duration `yaml:"check_interval"`
	CheckTimeout     Duration `yaml:"check_timeout"`
	FailThreshold    int      `yaml:"fail_threshold"`
	RecoverThreshold int      `yaml:"recover_threshold"`
	// RestartInterval — пауза между Down+Up нетекущего мёртвого бэкенда.
	// Текущий бэкенд этим интервалом не переподнимается.
	RestartInterval Duration `yaml:"restart_interval"`
	// CheckURLs — список проб. nil после разбора значит «взять умолчание».
	// Пустой список и непустой список сохраняются: непустой заменяет пару
	// generate_204, а не добавляется к ней.
	CheckURLs      []string `yaml:"check_urls"`
	EgressURL      string   `yaml:"egress_url,omitempty"`
	EgressInterval Duration `yaml:"egress_interval,omitempty"`
}

// Backend — одна запись выхода. URI не логируется: в нём ключ или пароль.
type Backend struct {
	ID       string `yaml:"id"`
	Type     string `yaml:"type"`
	Priority int    `yaml:"priority"`
	URI      string `yaml:"uri"`
}

// Log выбирает уровень и формат slog.
type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// KnownTypes — типы, которые схема конфига принимает.
// Новый протокол регистрируется в своём пакете и добавляется сюда,
// иначе файл с ним не пройдёт Validate, даже если фабрика уже есть.
var KnownTypes = struct {
	Backends []string
	Balancer []string
}{
	Backends: []string{"amneziawg", "socks5"},
	Balancer: []string{"sticky"},
}

// Load читает path, подставляет умолчания и проверяет документ.
func Load(path string) (File, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- путь конфигурации задаёт пользователь
	if err != nil {
		return File{}, err
	}
	return Parse(raw)
}

// Parse разбирает YAML, подставляет умолчания и проверяет документ.
func Parse(raw []byte) (File, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return File{}, fmt.Errorf("parse config: empty document")
	}
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return File{}, fmt.Errorf("parse config: %w", err)
	}
	f.applyDefaults()
	if err := f.Validate(); err != nil {
		return File{}, err
	}
	return f, nil
}

// applyDefaults заполняет пропущенные поля. Заданный список check_urls
// заменяет умолчание целиком, в том числе когда тест даёт одну пробу tcp://.
func (f *File) applyDefaults() {
	if f.Listen == "" {
		f.Listen = DefaultListen
	}
	if f.HTTPListen == "" {
		f.HTTPListen = DefaultHTTPListen
	}
	if f.Balancer.Type == "" {
		f.Balancer.Type = DefaultBalancer
	}
	if f.Balancer.CheckInterval == 0 {
		f.Balancer.CheckInterval = Duration(15 * time.Second)
	}
	if f.Balancer.CheckTimeout == 0 {
		f.Balancer.CheckTimeout = Duration(8 * time.Second)
	}
	if f.Balancer.FailThreshold == 0 {
		f.Balancer.FailThreshold = 3
	}
	if f.Balancer.RecoverThreshold == 0 {
		f.Balancer.RecoverThreshold = 2
	}
	if f.Balancer.RestartInterval == 0 {
		f.Balancer.RestartInterval = Duration(5 * time.Minute)
	}
	if f.Balancer.CheckURLs == nil {
		f.Balancer.CheckURLs = append([]string(nil), DefaultCheckURLs...)
	}
	if f.Balancer.EgressURL == "" {
		f.Balancer.EgressURL = "https://api.ipify.org"
	}
	if f.Balancer.EgressInterval == 0 {
		f.Balancer.EgressInterval = Duration(time.Minute)
	}
	if f.Log.Level == "" {
		f.Log.Level = "info"
	}
	if f.Log.Format == "" {
		f.Log.Format = "text"
	}
}

// Validate проверяет обязательные поля, известные типы и loopback-слушатели.
// Слушать не-loopback нельзя: прокси не должен быть открыт в сеть хоста.
func (f File) Validate() error {
	if err := requireLoopback(f.Listen, "listen"); err != nil {
		return err
	}
	if err := requireLoopback(f.HTTPListen, "http_listen"); err != nil {
		return err
	}
	if !contains(KnownTypes.Balancer, f.Balancer.Type) {
		return fmt.Errorf("unknown balancer type %q", f.Balancer.Type)
	}
	if f.Balancer.FailThreshold < 1 {
		return fmt.Errorf("fail_threshold must be >= 1")
	}
	if f.Balancer.RecoverThreshold < 1 {
		return fmt.Errorf("recover_threshold must be >= 1")
	}
	switch strings.ToLower(f.Log.Level) {
	case "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("unknown log level %q", f.Log.Level)
	}
	switch strings.ToLower(f.Log.Format) {
	case "text", "json":
	default:
		return fmt.Errorf("unknown log format %q", f.Log.Format)
	}
	seen := map[string]struct{}{}
	for i, b := range f.Backends {
		if strings.TrimSpace(b.ID) == "" {
			return fmt.Errorf("backends[%d]: id is required", i)
		}
		if _, ok := seen[b.ID]; ok {
			return fmt.Errorf("backends[%d]: duplicate id %q", i, b.ID)
		}
		seen[b.ID] = struct{}{}
		if !validID(b.ID) {
			return fmt.Errorf("backends[%d]: id %q must match [A-Za-z0-9._-]+", i, b.ID)
		}
		if strings.TrimSpace(b.Type) == "" {
			return fmt.Errorf("backends[%d]: type is required", i)
		}
		if !contains(KnownTypes.Backends, b.Type) {
			return fmt.Errorf("backends[%d]: unknown type %q", i, b.Type)
		}
		if strings.TrimSpace(b.URI) == "" {
			return fmt.Errorf("backends[%d]: uri is required", i)
		}
		switch b.Type {
		case "amneziawg":
			if !strings.HasPrefix(strings.TrimSpace(b.URI), "vpn://") {
				return fmt.Errorf("backends[%d]: amneziawg uri must start with vpn://", i)
			}
		case "socks5":
			if _, err := ParseSOCKS5URI(b.URI); err != nil {
				return fmt.Errorf("backends[%d]: socks5 uri must be socks5://host:port", i)
			}
		}
	}
	if f.Listen == f.HTTPListen {
		return fmt.Errorf("listen and http_listen must differ")
	}
	return nil
}

func validID(id string) bool {
	if id == "" || id == "." || id == ".." {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

func requireLoopback(addr, field string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%s: host must be a loopback address", field)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("%s: host must be a loopback address", field)
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

// Template — конфиг, который install пишет, только если файла ещё нет.
func Template() string {
	return `# vpnpa. Добавьте выход командой vpnpa add 'vpn://...' или vpnpa add-socks5 'socks5://...'.
# В ссылке vpn:// есть приватный ключ, поэтому у файла права 0600.
listen: 127.0.0.1:1080
http_listen: 127.0.0.1:8080
balancer:
  type: sticky
  check_interval: 15s
  check_timeout: 8s
  fail_threshold: 3
  recover_threshold: 2
  restart_interval: 5m
  check_urls:
    - https://www.gstatic.com/generate_204
    - https://cp.cloudflare.com/generate_204
backends: []
log:
  level: info
  format: text
`
}
