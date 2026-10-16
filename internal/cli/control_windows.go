//go:build windows

package cli

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

const (
	mutexName   = `Local\vpnpa`
	eventReload = `Local\vpnpa-reload`
	eventStop   = `Local\vpnpa-stop`
	eventUp     = `Local\vpnpa-up`
	eventDown   = `Local\vpnpa-down`
)

// errAlreadyRunning — в этой сессии Windows уже есть процесс vpnpa.
var errAlreadyRunning = errors.New("vpnpa уже запущен")

// control — действия живого процесса по именованным событиям.
// stop гасит процесс, down только прокси, up поднимает прокси, reload перечитывает конфиг.
type control struct {
	reload func()
	stop   func()
	up     func()
	down   func()
}

// holdInstance держит мьютекс одного процесса и ждёт события, пока release
// не отпустит ожидание. События создаются раньше мьютекса: как только
// другой процесс видит мьютекс, SetEvent уже находит имена.
func holdInstance(c control) (func(), error) {
	reloadH, err := createEvent(eventReload)
	if err != nil {
		return nil, err
	}
	stopH, err := createEvent(eventStop)
	if err != nil {
		_ = windows.CloseHandle(reloadH)
		return nil, err
	}
	upH, err := createEvent(eventUp)
	if err != nil {
		_ = windows.CloseHandle(reloadH)
		_ = windows.CloseHandle(stopH)
		return nil, err
	}
	downH, err := createEvent(eventDown)
	if err != nil {
		_ = windows.CloseHandle(reloadH)
		_ = windows.CloseHandle(stopH)
		_ = windows.CloseHandle(upH)
		return nil, err
	}
	exitH, err := windows.CreateEvent(nil, 0, 0, nil)
	if exitH == 0 {
		_ = windows.CloseHandle(reloadH)
		_ = windows.CloseHandle(stopH)
		_ = windows.CloseHandle(upH)
		_ = windows.CloseHandle(downH)
		if err == nil {
			err = errors.New("не создано событие выхода")
		}
		return nil, err
	}
	handles := []windows.Handle{reloadH, stopH, upH, downH, exitH}
	mu, err := createMutex()
	if err != nil {
		for _, h := range handles {
			_ = windows.CloseHandle(h)
		}
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			ev, werr := windows.WaitForMultipleObjects(handles, false, windows.INFINITE)
			if werr != nil {
				return
			}
			switch ev {
			case windows.WAIT_OBJECT_0:
				if c.reload != nil {
					c.reload()
				}
			case windows.WAIT_OBJECT_0 + 1:
				if c.stop != nil {
					c.stop()
				}
			case windows.WAIT_OBJECT_0 + 2:
				if c.up != nil {
					c.up()
				}
			case windows.WAIT_OBJECT_0 + 3:
				if c.down != nil {
					c.down()
				}
			default:
				return
			}
		}
	}()
	release := func() {
		_ = windows.SetEvent(exitH)
		<-done
		for _, h := range handles {
			_ = windows.CloseHandle(h)
		}
		_ = windows.CloseHandle(mu)
	}
	return release, nil
}

func createMutex() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(mutexName)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateMutex(nil, false, name)
	if h == 0 {
		if err == nil {
			err = errors.New("не создан мьютекс vpnpa")
		}
		return 0, err
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		_ = windows.CloseHandle(h)
		return 0, errAlreadyRunning
	}
	return h, nil
}

func createEvent(name string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	// Автосброс: одно SetEvent будит один Wait.
	h, err := windows.CreateEvent(nil, 0, 0, p)
	if h == 0 {
		if err == nil {
			err = errors.New("не создано событие " + name)
		}
		return 0, err
	}
	return h, nil
}

func instanceRunning() bool {
	p, err := windows.UTF16PtrFromString(mutexName)
	if err != nil {
		return false
	}
	h, err := windows.OpenMutex(windows.SYNCHRONIZE, false, p)
	if err != nil {
		return false
	}
	_ = windows.CloseHandle(h)
	return true
}

func signalEvent(name string) error {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	h, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, p)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	return windows.SetEvent(h)
}

func waitInstanceGone(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !instanceRunning() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !instanceRunning()
}
