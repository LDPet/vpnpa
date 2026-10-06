package ingress

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// Listen открывает TCP только на loopback. Пустой хост, имя и любой не-loopback
// IP отклоняются до bind: прокси не должен слушать сеть хоста.
func Listen(addr string) (net.Listener, error) {
	if err := requireLoopback(addr); err != nil {
		return nil, err
	}
	return net.Listen("tcp", addr)
}

func requireLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("listen %s: port is required", addr)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return fmt.Errorf("listen %s: host must be a loopback address", addr)
	}
	return nil
}

// CloseOnDone закрывает c, когда ctx отменён. Возвращённую stop вызывают,
// когда обработчик закончил: иначе поздняя отмена закроет уже переиспользованный conn.
// Для nil возвращается пустая stop.
func CloseOnDone(ctx context.Context, c net.Conn) func() {
	if c == nil {
		return func() {}
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	return func() { _ = stop() }
}
