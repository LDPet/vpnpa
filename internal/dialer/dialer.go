// Package dialer — общий контракт исходящего соединения.
// Его реализуют и конкретный бэкенд, и sticky-балансировщик, поэтому
// ingress не отличает туннель от выбора туннеля.
package dialer

import (
	"context"
	"errors"
	"net"
)

// Dialer открывает соединение к address в сети network.
// address приходит как есть от клиента (часто host:port с именем, не IP):
// реализация не должна резолвить имя на хосте, если протокол умеет передать его дальше.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ErrNoHealthyBackend возвращается, когда ни один бэкенд сейчас не выбран.
// В этом случае трафик не уходит в сеть хоста в обход прокси.
var ErrNoHealthyBackend = errors.New("no healthy backend")
