// Package config loads and writes the single YAML file vpnpa uses.
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
	// FileMode is required because a vpn:// URI carries a private key and a
	// socks5 URI may carry a password.
	FileMode os.FileMode = 0o600

	DefaultListen     = "127.0.0.1:1080"
	DefaultHTTPListen = "127.0.0.1:8080"
	DefaultBalancer   = "sticky"
)

// DefaultCheckURLs are tried in order. The first HTTP 204 wins.
var DefaultCheckURLs = []string{
	"https://www.gstatic.com/generate_204",
	"https://cp.cloudflare.com/generate_204",
}

// Duration is a YAML string such as "15s" or "5m".
type Duration time.Duration

// UnmarshalYAML parses a Go duration string.
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

// MarshalYAML emits a Go duration string.
func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

// Std returns the standard library duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// File is the on-disk document.
type File struct {
	Listen     string    `yaml:"listen"`
	HTTPListen string    `yaml:"http_listen"`
	Balancer   Balancer  `yaml:"balancer"`
	Backends   []Backend `yaml:"backends"`
	Log        Log       `yaml:"log"`
}

// Balancer is the sticky-balancer block.
type Balancer struct {
	Type             string   `yaml:"type"`
	CheckInterval    Duration `yaml:"check_interval"`
	CheckTimeout     Duration `yaml:"check_timeout"`
	FailThreshold    int      `yaml:"fail_threshold"`
	RecoverThreshold int      `yaml:"recover_threshold"`
	RestartInterval  Duration `yaml:"restart_interval"`
	CheckURLs        []string `yaml:"check_urls"`
	EgressURL        string   `yaml:"egress_url,omitempty"`
	EgressInterval   Duration `yaml:"egress_interval,omitempty"`
}

// Backend is one egress entry.
type Backend struct {
	ID       string `yaml:"id"`
	Type     string `yaml:"type"`
	Priority int    `yaml:"priority"`
	URI      string `yaml:"uri"`
}

// Log selects slog level and format.
type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// KnownTypes are the backend and balancer types the config schema accepts.
// A new protocol is registered in its package and added here.
var KnownTypes = struct {
	Backends []string
	Balancer []string
}{
	Backends: []string{"amneziawg", "socks5"},
	Balancer: []string{"sticky"},
}

// Load reads path, applies defaults and validates the document.
func Load(path string) (File, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- путь конфигурации задаёт пользователь
	if err != nil {
		return File{}, err
	}
	return Parse(raw)
}

// Parse decodes YAML, applies defaults and validates.
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

// applyDefaults fills omitted fields. A present check_urls list replaces the
// defaults entirely, including when a test supplies a single tcp:// probe.
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

// Validate checks required fields, known types and loopback listeners.
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

// Template is the config written by install when no file exists yet.
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
