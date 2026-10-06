package amneziawg

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/LDPet/vpnpa/internal/dialer"
)

// packetHexDump ловит дамп пакета из 8 и более байт в логе библиотеки.
// Такие строки не пишем: в них полезная нагрузка пользователя.
var packetHexDump = regexp.MustCompile(`(?:^|[^0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[ \t]+){7,}[0-9A-Fa-f]{2}(?:$|[^0-9A-Fa-f])`)

// tunnelHandle — живой userspace-туннель. dial ходит в netstack,
// close гасит устройство. Таблицу маршрутов хоста это не касается.
type tunnelHandle struct {
	dial  dialer.Dialer
	close func() error
}

// startTunnel поднимает amneziawg-go внутри процесса. Таблица маршрутов
// хоста не меняется. Тесты подменяют tunnelStarter, чтобы не открывать UDP.
var tunnelStarter = startTunnel

// startTunnel собирает TUN в памяти (gVisor netstack), а не /dev/net/tun.
// Адреса и DNS берутся из ссылки: имена резолвит сам netstack, не резолвер хоста.
// Затем NewDevice + IpcSet(UAPI) + Up. Сокет наружу — обычный UDP bind библиотеки,
// без привилегий и без правил iptables.
func startTunnel(t Tunnel, log *slog.Logger) (tunnelHandle, error) {
	tunDev, tnet, err := netstack.CreateNetTUN(t.Addresses, t.DNS, t.MTU)
	if err != nil {
		return tunnelHandle{}, fmt.Errorf("netstack: %w", err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), deviceLogger(log))
	uapi := BuildUAPI(t)
	if log != nil {
		log.Debug("uapi", "config", RedactUAPI(uapi))
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return tunnelHandle{}, fmt.Errorf("ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return tunnelHandle{}, fmt.Errorf("device up: %w", err)
	}
	return tunnelHandle{dial: tnet, close: func() error { dev.Close(); return nil }}, nil
}

// deviceLogger отдаёт сообщения библиотеки в slog только на уровне debug.
// Дампы пакетов отбрасываются и там: в журнал не должна попадать полезная нагрузка.
func deviceLogger(log *slog.Logger) *device.Logger {
	if log == nil || !log.Enabled(context.Background(), slog.LevelDebug) {
		return &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	}
	write := func(level slog.Level) func(string, ...any) {
		return func(format string, args ...any) {
			if dumpsPacket(args) {
				return
			}
			msg := fmt.Sprintf(format, args...)
			if packetHexDump.MatchString(msg) {
				return
			}
			if level == slog.LevelDebug {
				log.Debug(msg)
				return
			}
			log.Warn(msg)
		}
	}
	return &device.Logger{Verbosef: write(slog.LevelDebug), Errorf: write(slog.LevelWarn)}
}

func dumpsPacket(args []any) bool {
	for _, a := range args {
		switch v := a.(type) {
		case []byte:
			if len(v) > 0 {
				return true
			}
		case string:
			if packetHexDump.MatchString(v) {
				return true
			}
		}
	}
	return false
}
