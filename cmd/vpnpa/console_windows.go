//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

func init() {
	prepareConsole()
}

// prepareConsole убирает консольное окно, которое Windows создаёт при запуске
// console-подсистемы из проводника, и подключает stdout к консоли cmd,
// если бинарник собран как windowsgui.
func prepareConsole() {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getConsoleWindow := kernel32.NewProc("GetConsoleWindow")
	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd != 0 {
		if consoleOwner(hwnd) == windows.GetCurrentProcessId() {
			freeConsole := kernel32.NewProc("FreeConsole")
			_, _, _ = freeConsole.Call()
		}
		return
	}
	attach := kernel32.NewProc("AttachConsole")
	const attachParent = ^uintptr(0)
	r, _, _ := attach.Call(attachParent)
	if r == 0 {
		return
	}
	reopenStd(&os.Stdout, windows.STD_OUTPUT_HANDLE, "CONOUT$")
	reopenStd(&os.Stderr, windows.STD_ERROR_HANDLE, "CONOUT$")
	reopenStd(&os.Stdin, windows.STD_INPUT_HANDLE, "CONIN$")
}

func consoleOwner(hwnd uintptr) uint32 {
	var pid uint32
	_, _ = windows.GetWindowThreadProcessId(windows.HWND(hwnd), &pid)
	return pid
}

func reopenStd(target **os.File, std uint32, name string) {
	h, err := windows.GetStdHandle(std)
	if err != nil || h == 0 || h == windows.InvalidHandle {
		f, oerr := os.OpenFile(name, os.O_RDWR, 0)
		if oerr != nil {
			return
		}
		*target = f
		return
	}
	*target = os.NewFile(uintptr(h), name)
}
