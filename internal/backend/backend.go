// Package backend — контракт выхода и реестр фабрик.
// Конкретные бэкенды этот пакет не импортирует: они регистрируются в своём init.
// Реестр отдельный от ingress, поэтому тип "socks5" может быть и входом, и выходом.
package backend

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/LDPet/vpnpa/internal/dialer"
)

// Проверка на этапе компиляции: Backend включает Dialer.
var _ interface {
	dialer.Dialer
} = (Backend)(nil)

// Backend — один выход. Балансировку и локальный SOCKS он не знает.
type Backend interface {
	dialer.Dialer

	// ID — имя из конфига. По нему sticky помнит здоровье и файл prefer.
	ID() string
	// Priority — чем больше число, тем раньше бэкенд берётся, когда текущего
	// ещё нет или текущий уже нежив. Сам по себе больший приоритет текущего не вытесняет.
	Priority() int
	// Up поднимает туннель или проверяет чужой прокси.
	// Повторный вызов уже поднятого бэкенда ничего не делает.
	Up(ctx context.Context) error
	// Down гасит то, чем владеет vpnpa. Чужой процесс SOCKS5 не останавливает
	// и сохранённую пару ключей API не удаляет.
	Down(ctx context.Context) error
}

// Config — один блок backends из YAML.
type Config struct {
	ID       string
	Type     string
	Priority int
	URI      string
}

// Deps — зависимости процесса, которые фабрика получает снаружи.
type Deps struct {
	Logger *slog.Logger
	// StateDir — каталог состояния. Бэкенд AmneziaWG кладёт туда ключи API.
	StateDir string
}

// Factory собирает бэкенд из конфига. Её регистрирует пакет протокола.
type Factory func(cfg Config, deps Deps) (Backend, error)

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

// Register добавляет тип бэкенда. Вызывается из init конкретного пакета.
// Реестр ingress с тем же именем — другой: "socks5" допустим с обеих сторон.
func Register(typ string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	factories[typ] = f
}

// Types возвращает имена зарегистрированных типов бэкендов.
func Types() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(factories))
	for name := range factories {
		out = append(out, name)
	}
	return out
}

// Known сообщает, зарегистрирован ли тип.
func Known(typ string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, ok := factories[typ]
	return ok
}

// New создаёт бэкенд. Неизвестный тип отклоняется здесь, до Up.
func New(cfg Config, deps Deps) (Backend, error) {
	mu.RLock()
	f, ok := factories[cfg.Type]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown backend type %q", cfg.Type)
	}
	if deps.Logger == nil {
		deps.Logger = slog.New(slog.DiscardHandler)
	}
	return f(cfg, deps)
}

// EndpointOf возвращает host:port, который безопасно писать в лог.
// Пустая строка, если бэкенд не сообщает точку входа. В строке нет ключей и паролей.
func EndpointOf(b Backend) string {
	type endpoint interface {
		Endpoint() string
	}
	if e, ok := b.(endpoint); ok {
		return e.Endpoint()
	}
	return ""
}
