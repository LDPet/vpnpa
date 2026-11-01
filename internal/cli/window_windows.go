//go:build windows

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/LDPet/vpnpa/internal/config"
	"github.com/LDPet/vpnpa/internal/logx"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var guiUser32 = windows.NewLazySystemDLL("user32.dll")
var guiKernel32 = windows.NewLazySystemDLL("kernel32.dll")
var guiGDI32 = windows.NewLazySystemDLL("gdi32.dll")
var guiCreate = guiUser32.NewProc("CreateWindowExW")
var guiDefProc = guiUser32.NewProc("DefWindowProcW")
var guiSend = guiUser32.NewProc("SendMessageW")
var guiPost = guiUser32.NewProc("PostMessageW")
var guiShow = guiUser32.NewProc("ShowWindow")
var guiForeground = guiUser32.NewProc("SetForegroundWindow")
var guiMessageBox = guiUser32.NewProc("MessageBoxW")

const (
	wmDestroy   = 2
	wmClose     = 0x10
	wmCommand   = 0x111
	wmTimer     = 0x113
	wmFont      = 0x30
	wmShowApp   = 0x8001
	wmQuitApp   = 0x8002
	wmResult    = 0x8003
	wsChild     = 0x40000000
	wsVisible   = 0x10000000
	wsBorder    = 0x00800000
	wsTabstop   = 0x10000
	lbAddString = 0x180
	lbReset     = 0x184
	lbGetSel    = 0x188
	lbSetSel    = 0x186
	lbGetTop    = 0x18e
	lbSetTop    = 0x197
	bmGetCheck  = 0xF0
	bmSetCheck  = 0xF1
	idList      = 100
	idURI       = 101
	idName      = 102
	idAdd       = 103
	idRemove    = 104
	idAuto      = 105
	idChoose    = 106
	idDirect    = 107
	idUp        = 108
	idDown      = 109
	idStartup   = 110
)

type winClass struct {
	Size, Style                        uint32
	Proc                               uintptr
	ClsExtra, WndExtra                 int32
	Instance, Icon, Cursor, Background uintptr
	Menu, Class                        *uint16
	SmallIcon                          uintptr
}
type winMessage struct {
	Hwnd           uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	X, Y           int32
	Private        uint32
}

type settingsWindow struct {
	s                                *session
	hwnd                             atomic.Uintptr
	pending                          atomic.Bool
	list, uri, name, status, startup uintptr
	ids                              []string
	labels                           []string
	busy                             bool
	results                          chan windowResult
	controls                         []uintptr
}

type windowResult struct {
	err   error
	clear bool
}

var activeWindow *settingsWindow
var settingsCallback = syscall.NewCallback(settingsProc)

func showExistingWindow() {
	if err := signalEvent(eventShow); err != nil {
		guiMessageBox.Call(0, uintptr(unsafe.Pointer(wide("vpnpa уже запущен без окна управления. Остановите работающий процесс и запустите приложение снова."))), uintptr(unsafe.Pointer(wide("vpnpa"))), 0x30)
	}
}

func newSettingsWindow(s *session) *settingsWindow {
	return &settingsWindow{s: s, results: make(chan windowResult, 1)}
}
func (w *settingsWindow) show() {
	if h := w.hwnd.Load(); h != 0 {
		guiPost.Call(h, wmShowApp, 0, 0)
	} else {
		w.pending.Store(true)
	}
}
func (w *settingsWindow) close() {
	if h := w.hwnd.Load(); h != 0 {
		guiPost.Call(h, wmQuitApp, 0, 0)
	}
}
func wide(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }
func (w *settingsWindow) run(show bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	activeWindow = w
	instance, _, _ := guiKernel32.NewProc("GetModuleHandleW").Call(0)
	cursor, _, _ := guiUser32.NewProc("LoadCursorW").Call(0, 32512)
	clsName, _ := windows.UTF16PtrFromString("vpnpaSettingsWindow")
	cls := winClass{Size: uint32(unsafe.Sizeof(winClass{})), Proc: settingsCallback, Instance: instance, Cursor: cursor, Background: 6, Class: clsName}
	atom, _, _ := guiUser32.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&cls)))
	if atom == 0 {
		w.s.logger().Error("не удалось создать класс окна")
		return
	}
	h, _, _ := guiCreate.Call(0, uintptr(unsafe.Pointer(clsName)), uintptr(unsafe.Pointer(wide("vpnpa — управление"))), 0x00CA0000, 0x80000000, 0x80000000, 700, 620, 0, 0, instance, 0)
	if h == 0 {
		w.s.logger().Error("не удалось создать окно")
		return
	}
	w.hwnd.Store(h)
	w.build(h, instance)
	if show || w.pending.Swap(false) {
		w.show()
	}
	guiUser32.NewProc("SetTimer").Call(h, 1, 2000, 0)
	var msg winMessage
	for {
		ret, _, _ := guiUser32.NewProc("GetMessageW").Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		if handled, _, _ := guiUser32.NewProc("IsDialogMessageW").Call(h, uintptr(unsafe.Pointer(&msg))); handled != 0 {
			continue
		}
		guiUser32.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&msg)))
		guiUser32.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&msg)))
	}
	w.hwnd.Store(0)
}
func (w *settingsWindow) control(parent, instance uintptr, class, title string, style uintptr, x, y, width, height, id int) uintptr {
	h, _, _ := guiCreate.Call(0, uintptr(unsafe.Pointer(wide(class))), uintptr(unsafe.Pointer(wide(title))), wsChild|wsVisible|style, uintptr(x), uintptr(y), uintptr(width), uintptr(height), parent, uintptr(id), instance, 0)
	if id != 0 {
		w.controls = append(w.controls, h)
	}
	font, _, _ := guiGDI32.NewProc("GetStockObject").Call(17)
	guiSend.Call(h, wmFont, font, 1)
	return h
}
func (w *settingsWindow) build(h, instance uintptr) {
	add := func(class, title string, style uintptr, x, y, width, height, id int) uintptr {
		return w.control(h, instance, class, title, style, x, y, width, height, id)
	}
	w.status = add("STATIC", "", 0, 18, 14, 640, 52, 0)
	add("STATIC", "Подключения (выберите строку):", 0, 18, 72, 500, 20, 0)
	w.list = add("LISTBOX", "", wsBorder|wsTabstop|0x0001|0x00200000, 18, 96, 640, 170, idList)
	add("BUTTON", "Удалить", wsTabstop, 18, 274, 100, 28, idRemove)
	add("BUTTON", "Выбрать выход", wsTabstop, 128, 274, 145, 28, idChoose)
	add("BUTTON", "Авто", wsTabstop, 283, 274, 100, 28, idAuto)
	add("BUTTON", "Напрямую", wsTabstop, 393, 274, 115, 28, idDirect)
	add("STATIC", "Ссылка vpn:// или socks5:// (содержит секрет):", 0, 18, 318, 500, 20, 0)
	w.uri = add("EDIT", "", wsBorder|wsTabstop|0x0080|0x0020, 18, 340, 640, 26, idURI)
	add("STATIC", "Имя (необязательно):", 0, 18, 379, 170, 20, 0)
	w.name = add("EDIT", "", wsBorder|wsTabstop|0x0080, 180, 376, 220, 26, idName)
	add("BUTTON", "Добавить", wsTabstop, 415, 375, 110, 28, idAdd)
	add("BUTTON", "Включить", wsTabstop, 18, 423, 110, 28, idUp)
	add("BUTTON", "Выключить", wsTabstop, 138, 423, 110, 28, idDown)
	w.startup = add("BUTTON", "Запускать при входе в Windows", wsTabstop|3, 275, 427, 320, 23, idStartup)
	add("STATIC", "Приложение создаёт локальный прокси: настройте его в нужных программах.\r\nПрямой выход передаёт трафик без VPN.", 0, 18, 478, 640, 52, 0)
	w.refresh()
}
func settingsProc(hwnd uintptr, msg uint32, wp, lp uintptr) uintptr {
	w := activeWindow
	if w != nil {
		switch msg {
		case wmClose:
			guiShow.Call(hwnd, 0)
			return 0
		case wmDestroy:
			guiUser32.NewProc("PostQuitMessage").Call(0)
			return 0
		case wmQuitApp:
			guiUser32.NewProc("DestroyWindow").Call(hwnd)
			return 0
		case wmShowApp:
			guiShow.Call(hwnd, 9)
			guiForeground.Call(hwnd)
			w.refresh()
			return 0
		case wmTimer:
			w.refresh()
			return 0
		case wmResult:
			result := <-w.results
			w.busy = false
			w.enableControls(true)
			if result.clear {
				setText(w.uri, "")
				setText(w.name, "")
			}
			if result.err != nil {
				w.message("Не удалось выполнить действие: "+logx.Redact(result.err.Error()), 0x10)
			}
			w.refresh()
			w.s.kick()
			return 0
		case wmCommand:
			if wp>>16 == 0 {
				w.action(int(wp & 0xffff))
				return 0
			}
		}
	}
	r, _, _ := guiDefProc.Call(hwnd, uintptr(msg), wp, lp)
	return r
}
func getText(h uintptr) string {
	n, _, _ := guiUser32.NewProc("GetWindowTextLengthW").Call(h)
	if n > 1<<20 {
		return ""
	}
	b := make([]uint16, n+1)
	guiUser32.NewProc("GetWindowTextW").Call(h, uintptr(unsafe.Pointer(&b[0])), n+1)
	return windows.UTF16ToString(b)
}
func setText(h uintptr, s string) {
	guiUser32.NewProc("SetWindowTextW").Call(h, uintptr(unsafe.Pointer(wide(s))))
}
func (w *settingsWindow) message(s string, flags uintptr) uintptr {
	r, _, _ := guiMessageBox.Call(w.hwnd.Load(), uintptr(unsafe.Pointer(wide(logx.Redact(s)))), uintptr(unsafe.Pointer(wide("vpnpa"))), flags)
	return r
}
func (w *settingsWindow) selected() string {
	n, _, _ := guiSend.Call(w.list, lbGetSel, 0, 0)
	if int32(n) < 0 || int(n) >= len(w.ids) {
		return ""
	}
	return w.ids[n]
}
func (w *settingsWindow) refresh() {
	f, err := config.Load(w.s.layout.ConfigPath)
	if err != nil {
		setText(w.status, "Ошибка чтения конфигурации")
		return
	}
	w.s.mu.Lock()
	running, started, note := w.s.running, w.s.started, w.s.note
	w.s.mu.Unlock()
	current, alive, fresh := readTrayStatus(w.s.layout.StatusPath(), started)
	state := trayStatusText(running, fresh, current, alive)
	if !running && note != "" {
		state = note
	}
	if !running && len(f.Backends) == 0 && (note == "" || strings.Contains(note, "список бэкендов пуст")) {
		state = "Добавьте подключение или выберите прямой выход"
	} else if !running && strings.Contains(state, "список бэкендов пуст") {
		state = "Прокси выключен — нажмите «Включить»"
	}
	setText(w.status, fmt.Sprintf("%s   |   Предпочтение: %s\r\nSOCKS5: %s    HTTP: %s", state, readPrefer(w.s.layout.PreferPath()), f.Listen, f.HTTPListen))
	if w.busy {
		setText(w.status, "Применение изменений…")
	}
	selected := w.selected()
	status := trayStatusJSON{}
	if running && fresh {
		if raw, e := os.ReadFile(w.s.layout.StatusPath()); e == nil {
			_ = json.Unmarshal(raw, &status)
		}
	}
	labels := make([]string, 0, len(f.Backends))
	ids := make([]string, 0, len(f.Backends))
	for _, b := range f.Backends {
		availability := "неизвестно"
		for _, st := range status.Backends {
			if st.ID == b.ID {
				if st.Waiting {
					availability = "ожидает активации"
				} else if st.Alive {
					availability = "доступен"
				} else {
					availability = "недоступен"
				}
				break
			}
		}
		labels = append(labels, fmt.Sprintf("%s  ·  %s  ·  %s", b.ID, b.Type, availability))
		ids = append(ids, b.ID)
	}
	if !slices.Equal(labels, w.labels) || !slices.Equal(ids, w.ids) {
		top, _, _ := guiSend.Call(w.list, lbGetTop, 0, 0)
		guiSend.Call(w.list, lbReset, 0, 0)
		w.ids, w.labels = ids, labels
		for i, label := range labels {
			guiSend.Call(w.list, lbAddString, 0, uintptr(unsafe.Pointer(wide(label))))
			if ids[i] == selected {
				guiSend.Call(w.list, lbSetSel, uintptr(i), 0)
			}
		}
		guiSend.Call(w.list, lbSetTop, top, 0)
	}
	k, e := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	checked := uintptr(0)
	if e == nil {
		if _, _, e = k.GetStringValue(runValueName); e == nil {
			checked = 1
		}
		_ = k.Close()
	}
	guiSend.Call(w.startup, bmSetCheck, checked, 0)
}
func (w *settingsWindow) action(id int) {
	if w.busy {
		return
	}
	var err error
	switch id {
	case idAdd:
		uri := strings.TrimSpace(getText(w.uri))
		name := strings.TrimSpace(getText(w.name))
		w.runAsync(func() windowResult {
			var e error
			switch {
			case strings.HasPrefix(uri, "vpn://"):
				_, e = config.Add(w.s.layout.ConfigPath, name, uri)
			case strings.HasPrefix(uri, "socks5://"):
				_, e = config.AddSOCKS5(w.s.layout.ConfigPath, name, uri)
			default:
				e = fmt.Errorf("Введите ссылку vpn:// или socks5://")
			}
			if e != nil {
				return windowResult{err: e}
			}
			w.s.setNote("")
			return windowResult{err: w.s.reloadConfig(), clear: true}
		})
		return
	case idRemove:
		choice := w.selected()
		if choice == "" {
			err = fmt.Errorf("Выберите подключение")
			break
		}
		if w.message("Удалить выбранное подключение «"+choice+"»?", 0x24) != 6 {
			return
		}
		w.runAsync(func() windowResult {
			if e := config.Remove(w.s.layout.ConfigPath, choice); e != nil {
				return windowResult{err: e}
			}
			var preferErr error
			if readPrefer(w.s.layout.PreferPath()) == choice {
				preferErr = cmdPrefer(w.s.layout, []string{"auto"})
			}
			return windowResult{err: errors.Join(preferErr, w.s.reloadConfig())}
		})
		return
	case idChoose:
		choice := w.selected()
		if choice == "" {
			err = fmt.Errorf("Выберите подключение")
		} else {
			err = cmdPrefer(w.s.layout, []string{choice})
		}
	case idAuto:
		err = cmdPrefer(w.s.layout, []string{"auto"})
	case idDirect:
		if w.message("Прямое подключение передаёт трафик без VPN. Продолжить?", 0x24) == 6 {
			err = cmdPrefer(w.s.layout, []string{"direct"})
		}
	case idUp:
		w.runAsync(func() windowResult { return windowResult{err: w.s.up()} })
		return
	case idDown:
		w.runAsync(func() windowResult { w.s.down(); return windowResult{} })
		return
	case idStartup:
		checked, _, _ := guiSend.Call(w.startup, bmGetCheck, 0, 0)
		if checked == 1 {
			err = cmdEnable(context.Background(), w.s.layout, nil, io.Discard)
		} else {
			err = cmdDisable(context.Background(), w.s.layout, nil)
		}
	}
	if err != nil {
		w.message("Не удалось выполнить действие: "+logx.Redact(err.Error()), 0x10)
	}
	w.refresh()
	w.s.kick()
}

func (w *settingsWindow) runAsync(fn func() windowResult) {
	w.busy = true
	w.enableControls(false)
	setText(w.status, "Применение изменений…")
	go func() {
		result := fn()
		w.results <- result
		if h := w.hwnd.Load(); h != 0 {
			guiPost.Call(h, wmResult, 0, 0)
		}
	}()
}

func (w *settingsWindow) enableControls(enabled bool) {
	var value uintptr
	if enabled {
		value = 1
	}
	for _, h := range w.controls {
		guiUser32.NewProc("EnableWindow").Call(h, value)
	}
}
