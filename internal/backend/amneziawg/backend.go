// Package amneziawg — клиент AmneziaWG 3.1 внутри процесса.
//
// Ссылка vpn:// — это base64. Нагрузка либо Qt qCompress (4 байта длины и zlib),
// либо сразу JSON. JSON с туннелем становится userspace-устройством amneziawg-go:
// netstack вместо TUN хоста и текстовый UAPI. JSON только с api_endpoint и
// api_key — ссылка на API: пара X25519 пишется на диск и переиспользуется,
// пока URI бэкенда не сменился.
package amneziawg

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"sync"

	"github.com/LDPet/vpnpa/internal/backend"
	"github.com/LDPet/vpnpa/internal/config"
	"github.com/LDPet/vpnpa/internal/dialer"
)

func init() {
	backend.Register("amneziawg", func(cfg backend.Config, deps backend.Deps) (backend.Backend, error) {
		return New(cfg, deps)
	})
	// Схема vpn:// проверяется при vpnpa add, до записи в конфиг.
	config.ValidateAmnezia = func(uri string) error {
		_, err := DecodeURI(uri)
		return err
	}
}

// Backend — клиент AmneziaWG в этом процессе, без сетевого интерфейса хоста.
type Backend struct {
	id       string
	priority int
	uri      string
	stateDir string
	log      *slog.Logger

	mu       sync.Mutex
	handle   *tunnelHandle
	endpoint string
}

// New проверяет, что URI вообще разбирается как vpn://, и возвращает бэкенд.
// Туннель и запрос к API стартуют в Up, не здесь.
func New(cfg backend.Config, deps backend.Deps) (*Backend, error) {
	if _, err := DecodeURI(cfg.URI); err != nil {
		return nil, err
	}
	log := deps.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Backend{
		id:       cfg.ID,
		priority: cfg.Priority,
		uri:      cfg.URI,
		stateDir: deps.StateDir,
		log:      log,
	}, nil
}

// ID возвращает имя бэкенда из конфига.
func (b *Backend) ID() string { return b.id }

// Priority возвращает приоритет из конфига.
func (b *Backend) Priority() int { return b.priority }

// Endpoint возвращает host:port пира после успешного Up. До Up строка пустая.
func (b *Backend) Endpoint() string { return b.endpoint }

// Up разбирает vpn:// и поднимает userspace-устройство.
// Повторный Up ничего не делает: устройство уже есть.
//
// Если в ссылке нет туннеля, а есть API, пара ключей берётся из state/keys/<id>.
// Пока URI тот же, публичный ключ не меняется и сервер узнаёт того же клиента.
// Ошибка разбора логируется и возвращается наверх; ключ при этом не затирается.
func (b *Backend) Up(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.handle != nil {
		return nil
	}
	tun, err := b.resolve(ctx)
	if err != nil {
		b.log.Warn("битая ссылка", "backend", b.id, "err", err)
		return err
	}
	if TrailersRangeWarning(tun) {
		b.log.Warn("RandomTrailers=on и диапазоны H1–H3: часть пакетов может теряться, значения не изменены",
			"backend", b.id,
			"endpoint", tun.Endpoint,
		)
	}
	handle, err := tunnelStarter(tun, b.log)
	if err != nil {
		b.log.Warn("ошибка поднятия бэкенда", "backend", b.id, "endpoint", tun.Endpoint, "err", err)
		return err
	}
	b.handle = &handle
	b.endpoint = tun.Endpoint
	b.log.Info("бэкенд поднят", "backend", b.id, "priority", b.priority, "endpoint", tun.Endpoint)
	return nil
}

// Down закрывает userspace-устройство. Файл ключа API не удаляется:
// следующий Up с тем же URI должен предъявить тот же public key.
func (b *Backend) Down(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.handle == nil {
		return nil
	}
	err := b.handle.close()
	b.handle = nil
	b.log.Info("бэкенд остановлен", "backend", b.id, "endpoint", b.endpoint)
	return err
}

// DialContext отдаёт соединение в netstack. Имя из address резолвится DNS
// серверами из ссылки, а не резолвером хоста. Вызов до успешного Up — ошибка.
func (b *Backend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	b.mu.Lock()
	h := b.handle
	b.mu.Unlock()
	if h == nil || h.dial == nil {
		return nil, fmt.Errorf("backend %s is down", b.id)
	}
	return h.dial.DialContext(ctx, network, address)
}

// resolve превращает URI в Tunnel. Полный конфиг парсится сразу.
// Ссылка API требует каталог состояния: без него некуда положить пару ключей,
// а без стабильной пары каждый Up был бы новым клиентом на сервере.
func (b *Backend) resolve(ctx context.Context) (Tunnel, error) {
	doc, err := DecodeURI(b.uri)
	if err != nil {
		return Tunnel{}, err
	}
	if endpoint, apiKey, ok := IsAPI(doc); ok {
		keysDir := ""
		if b.stateDir != "" {
			keysDir = filepath.Join(b.stateDir, "keys")
		}
		if keysDir == "" {
			return Tunnel{}, fmt.Errorf("api link requires a state dir")
		}
		kp, err := loadOrCreateKey(keysDir, b.id, b.uri)
		if err != nil {
			return Tunnel{}, err
		}
		cfg, err := fetchAPIConfig(ctx, endpoint, apiKey, kp)
		if err != nil {
			b.log.Warn("ошибка API", "backend", b.id, "err", err)
			return Tunnel{}, err
		}
		return ParseFullConfig(cfg, kp.Private)
	}
	return ParseFullConfig(doc, "")
}

var _ dialer.Dialer = (*Backend)(nil)
var _ backend.Backend = (*Backend)(nil)
