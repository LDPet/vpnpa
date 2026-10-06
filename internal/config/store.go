package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/LDPet/vpnpa/internal/atomicfile"
	"gopkg.in/yaml.v3"
)

// Save writes f to path with mode 0600. Existing permissions are never widened.
func Save(path string, f File) error {
	raw, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	body := append([]byte("# vpnpa config. Права файла 0600: в uri может быть ключ или пароль.\n"), raw...)
	if err := atomicfile.Write(path, body, FileMode); err != nil {
		return err
	}
	return os.Chmod(path, FileMode)
}

// InstallConfig writes the template only when path does not already exist.
// A config that already has links is left untouched. The file mode is 0600.
func InstallConfig(path string) (created bool, err error) {
	if _, err := os.Stat(path); err == nil {
		if chErr := os.Chmod(path, FileMode); chErr != nil {
			return false, chErr
		}
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return false, err
	}
	if err := atomicfile.Write(path, []byte(Template()), FileMode); err != nil {
		return false, err
	}
	return true, nil
}

func dirOf(path string) string {
	i := strings.LastIndex(path, string(os.PathSeparator))
	if i < 0 {
		return "."
	}
	return path[:i]
}

// ValidateAmnezia optionally checks that a vpn:// payload decodes.
// The amneziawg package installs it; tests of the scheme check can leave it nil.
var ValidateAmnezia func(uri string) error

// Add appends an amneziawg backend. uri must be a vpn:// link.
// The first backend gets priority 100, each next one is 10 lower.
// id defaults to vpn-N. The file mode stays 0600.
func Add(path, id, uri string) (Backend, error) {
	uri = strings.TrimSpace(uri)
	if !strings.HasPrefix(uri, "vpn://") {
		return Backend{}, fmt.Errorf("vpnpa add принимает только ссылку vpn://")
	}
	if ValidateAmnezia != nil {
		if err := ValidateAmnezia(uri); err != nil {
			return Backend{}, fmt.Errorf("vpnpa add: ссылка vpn:// не разбирается")
		}
	}
	return add(path, id, "amneziawg", uri)
}

// AddSOCKS5 appends a socks5 backend. uri must be socks5://.
func AddSOCKS5(path, id, uri string) (Backend, error) {
	uri = strings.TrimSpace(uri)
	if err := validateSOCKS5URI(uri); err != nil {
		return Backend{}, err
	}
	return add(path, id, "socks5", uri)
}

func add(path, id, typ, uri string) (Backend, error) {
	f, err := Load(path)
	if err != nil {
		return Backend{}, err
	}
	if id == "" {
		id = nextID(f.Backends)
	}
	b := Backend{
		ID:       id,
		Type:     typ,
		Priority: nextPriority(f.Backends),
		URI:      uri,
	}
	f.Backends = append(f.Backends, b)
	if err := f.Validate(); err != nil {
		return Backend{}, err
	}
	if err := Save(path, f); err != nil {
		return Backend{}, err
	}
	return b, nil
}

func nextID(backends []Backend) string {
	used := map[string]struct{}{}
	for _, b := range backends {
		used[b.ID] = struct{}{}
	}
	for n := 1; ; n++ {
		id := fmt.Sprintf("vpn-%d", n)
		if _, ok := used[id]; !ok {
			return id
		}
	}
}

func nextPriority(backends []Backend) int {
	if len(backends) == 0 {
		return 100
	}
	min := backends[0].Priority
	for _, b := range backends[1:] {
		if b.Priority < min {
			min = b.Priority
		}
	}
	return min - 10
}

func validateSOCKS5URI(uri string) error {
	if strings.HasPrefix(uri, "vpn://") {
		return fmt.Errorf("vpnpa add-socks5 принимает только ссылку socks5://")
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "socks5" || u.Host == "" {
		return fmt.Errorf("vpnpa add-socks5 принимает только ссылку socks5://")
	}
	return nil
}

// SOCKS5Endpoint returns host:port without userinfo.
func SOCKS5Endpoint(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("socks5 uri has no host")
	}
	return u.Host, nil
}
