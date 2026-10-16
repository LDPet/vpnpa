//go:build !windows

package cli

import (
	"context"
	"os"
	"strconv"
	"syscall"
	"testing"
)

// Последовательно: подменяет пакетные killProc, procExe и procCmdline.
func TestSignalReloadOnlyVpnpaMainPID(t *testing.T) {
	var killed int
	prevKill := killProc
	prevExe := procExe
	prevCmd := procCmdline
	killProc = func(pid int, _ syscall.Signal) error {
		killed = pid
		return nil
	}
	t.Cleanup(func() {
		killProc = prevKill
		procExe = prevExe
		procCmdline = prevCmd
	})
	signalReload(context.Background(), &fakeRun{out: []byte(strconv.Itoa(os.Getpid()) + "\n")})
	if killed != 0 {
		t.Fatalf("signaled foreign pid %d", killed)
	}
	procExe = func(int) (string, error) { return "/home/a/.local/bin/vpnpa", nil }
	procCmdline = func(int) ([]byte, error) {
		return []byte("/home/a/.local/bin/vpnpa\x00run\x00--config\x00x\x00"), nil
	}
	signalReload(context.Background(), &fakeRun{out: []byte("1\n")})
	if killed != 0 {
		t.Fatalf("signaled pid 1")
	}
	procCmdline = func(int) ([]byte, error) {
		return []byte("/home/a/.local/bin/vpnpa\x00add\x00vpn://secret\x00"), nil
	}
	signalReload(context.Background(), &fakeRun{out: []byte("4242\n")})
	if killed != 0 {
		t.Fatal("signaled vpnpa add")
	}
	procExe = func(int) (string, error) { return "/bin/bash", nil }
	procCmdline = func(int) ([]byte, error) { return []byte("/bin/bash\x00run\x00"), nil }
	signalReload(context.Background(), &fakeRun{out: []byte("4242\n")})
	if killed != 0 {
		t.Fatal("signaled bash")
	}
	procExe = func(int) (string, error) { return "/home/a/.local/bin/vpnpa (deleted)", nil }
	procCmdline = func(int) ([]byte, error) {
		return []byte("/home/a/.local/bin/vpnpa\x00run\x00"), nil
	}
	signalReload(context.Background(), &fakeRun{out: []byte("4242\n")})
	if killed != 4242 {
		t.Fatalf("did not signal vpnpa run, killed=%d", killed)
	}
	run := &fakeRun{out: []byte("4242\n")}
	signalReload(context.Background(), run)
	if len(run.calls) != 1 || run.calls[0] != "systemctl --user show -p MainPID --value vpnpa.service" {
		t.Fatalf("show args %v", run.calls)
	}
}
