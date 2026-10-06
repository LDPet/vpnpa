package amneziawg

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/LDPet/vpnpa/internal/dialer"
)

// tunnelHandle is the live userspace tunnel.
type tunnelHandle struct {
	dial  dialer.Dialer
	close func() error
}

// startTunnel brings up amneziawg-go inside the process. The host routing
// table is not touched. Tests replace tunnelStarter.
var tunnelStarter = startTunnel

func startTunnel(t Tunnel, log *slog.Logger) (tunnelHandle, error) {
	tunDev, tnet, err := netstack.CreateNetTUN(t.Addresses, t.DNS, t.MTU)
	if err != nil {
		return tunnelHandle{}, fmt.Errorf("netstack: %w", err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), deviceLogger(log))
	uapi := BuildUAPI(t)
	log.Debug("uapi", "config", RedactUAPI(uapi))
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

func deviceLogger(log *slog.Logger) *device.Logger {
	if log == nil || !log.Enabled(context.Background(), slog.LevelDebug) {
		return &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	}
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			log.Debug(fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			log.Warn(fmt.Sprintf(format, args...))
		},
	}
}
