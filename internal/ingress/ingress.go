// Package ingress — контракт локальных слушателей и реестр их фабрик.
// Слушатель принимает соединения только на loopback и уводит их в dialer.Dialer.
// Что за Dialer — конкретный туннель или sticky — пакету неважно.
package ingress

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/LDPet/vpnpa/internal/dialer"
)

// Ingress принимает локальные соединения и звонит через переданный Dialer.
// Serve обязан слушать только loopback; другой адрес отклоняется и сокет не открывается.
type Ingress interface {
	Serve(ctx context.Context, dial dialer.Dialer) error
}

// Factory собирает ingress, привязанный к listen.
type Factory func(listen string, log *slog.Logger) (Ingress, error)

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

// Register добавляет тип входа. Реестр не связан с реестром бэкендов.
func Register(typ string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	factories[typ] = f
}

// Known сообщает, зарегистрирован ли тип входа.
func Known(typ string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, ok := factories[typ]
	return ok
}

// New собирает ingress. Неизвестный тип возвращает ошибку, сокет при этом не открывается.
func New(typ, listen string, log *slog.Logger) (Ingress, error) {
	mu.RLock()
	f, ok := factories[typ]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown ingress type %q", typ)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return f(listen, log)
}
