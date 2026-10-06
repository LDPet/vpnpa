package config

// Файл store.go дописывает бэкенды в YAML и разбирает URI socks5://.
// Запись идёт через atomicfile: читатель не видит обрезанный конфиг с ключом.

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/LDPet/vpnpa/internal/atomicfile"
	"gopkg.in/yaml.v3"
)

// ErrBadSOCKS5URI возвращается, когда URI бэкенда socks5 — не socks5://host:port.
// Текст ошибки никогда не содержит сам URI и пароль.
var ErrBadSOCKS5URI = errors.New("socks5 uri must be socks5://host:port")

// SOCKS5Creds — host:port чужого прокси. User и Pass заполняются только если
// в URI есть userinfo. Pass и исходный URI логировать нельзя.
type SOCKS5Creds struct {
	Host string
	User string
	Pass string
	Auth bool
}

// Save пишет f в path с правами 0600. Существующие права не расширяются:
// atomicfile снимает group/world, которых у файла ещё не было.
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

// InstallConfig пишет шаблон, только если path ещё нет.
// Файл со ссылками не затирается. Права в любом случае приводятся к 0600.
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

// ValidateAmnezia при желании проверяет, что полезная нагрузка vpn:// разбирается.
// Пакет amneziawg ставит сюда DecodeURI. Тесты проверки схемы могут оставить nil:
// тогда add смотрит только на префикс, не на qCompress.
var ValidateAmnezia func(uri string) error

// Add дописывает бэкенд amneziawg. uri обязан начинаться с vpn://.
// Первый бэкенд получает приоритет 100, каждый следующий — на 10 меньше.
// Пустой id становится vpn-N. Права файла остаются 0600.
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

// AddSOCKS5 дописывает бэкенд socks5. uri обязан быть socks5://host:port,
// с паролем или без. Ошибка разбора не цитирует пароль.
func AddSOCKS5(path, id, uri string) (Backend, error) {
	uri = strings.TrimSpace(uri)
	if _, err := ParseSOCKS5URI(uri); err != nil {
		return Backend{}, fmt.Errorf("vpnpa add-socks5 принимает только ссылку socks5://host:port")
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

// ParseSOCKS5URI проверяет socks5://host:port с необязательными именем и паролем.
// Путь, query и fragment запрещены. Ошибки не содержат URI и пароль.
func ParseSOCKS5URI(uri string) (SOCKS5Creds, error) {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil || u.Scheme != "socks5" || u.Host == "" || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return SOCKS5Creds{}, ErrBadSOCKS5URI
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" || port == "" {
		return SOCKS5Creds{}, ErrBadSOCKS5URI
	}
	pn, err := strconv.Atoi(port)
	if err != nil || pn < 1 || pn > 65535 {
		return SOCKS5Creds{}, ErrBadSOCKS5URI
	}
	creds := SOCKS5Creds{Host: u.Host}
	if u.User != nil {
		creds.User = u.User.Username()
		creds.Pass, _ = u.User.Password()
		if creds.User == "" || len(creds.User) > 255 || len(creds.Pass) > 255 {
			return SOCKS5Creds{}, ErrBadSOCKS5URI
		}
		creds.Auth = true
	}
	return creds, nil
}

// SOCKS5Endpoint возвращает host:port без userinfo — строку, которую можно логировать.
func SOCKS5Endpoint(uri string) (string, error) {
	creds, err := ParseSOCKS5URI(uri)
	if err != nil {
		return "", err
	}
	return creds.Host, nil
}
