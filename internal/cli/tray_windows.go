//go:build windows

package cli

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LDPet/vpnpa/internal/app"
	"github.com/LDPet/vpnpa/internal/config"
	"github.com/LDPet/vpnpa/internal/logx"
	"github.com/LDPet/vpnpa/internal/paths"
	"github.com/getlantern/systray"
)

// session — трей и один демон в том же процессе. Оба входа поднимает app.Run,
// то есть один sticky Dialer. Down гасит демон и оставляет иконку.
// Выход из трея останавливает процесс.
type session struct {
	layout paths.Layout
	log    atomic.Pointer[slog.Logger]

	op sync.Mutex
	mu sync.Mutex

	app     *app.App
	cancel  context.CancelFunc
	done    chan struct{}
	gen     int
	running bool
	started time.Time
	note    string

	changed  chan struct{}
	stopLoop chan struct{}
	haltOnce sync.Once

	trayReady atomic.Bool
	quitReq   atomic.Bool

	statusItem *systray.MenuItem
	upItem     *systray.MenuItem
	downItem   *systray.MenuItem
	preferItem *systray.MenuItem
	autoItem   *systray.MenuItem
	items      map[string]*systray.MenuItem
}

func cmdTray(layout paths.Layout, level, format string) error {
	if instanceRunning() {
		_ = signalEvent(eventUp)
		return nil
	}
	if err := prepareLayout(layout); err != nil {
		return err
	}
	// Лог открываем только после мьютекса: проигравший гонку не должен
	// стереть vpnpa.log уже живущего процесса.
	s := newSession(layout, nil)
	release, err := holdInstance(control{
		reload: s.reload,
		stop:   s.requestStop,
		up:     s.upFromUI,
		down:   s.down,
	})
	if err != nil {
		if err == errAlreadyRunning {
			_ = signalEvent(eventUp)
			return nil
		}
		return err
	}
	defer release()
	log, closeLog, err := openTrayLog(layout, level, format)
	if err != nil {
		return err
	}
	defer closeLog()
	s.log.Store(log)
	if err := s.up(); err != nil {
		s.setNote(shortNote(err))
		s.logger().Warn("не включился", "err", err)
	}
	systray.Run(s.onReady, func() {
		s.haltOnce.Do(func() { close(s.stopLoop) })
		s.down()
	})
	return nil
}

func newSession(layout paths.Layout, log *slog.Logger) *session {
	s := &session{
		layout:   layout,
		changed:  make(chan struct{}, 1),
		stopLoop: make(chan struct{}),
		items:    map[string]*systray.MenuItem{},
	}
	if log != nil {
		s.log.Store(log)
	}
	return s
}

var discardLogger = slog.New(slog.DiscardHandler)

func (s *session) logger() *slog.Logger {
	if l := s.log.Load(); l != nil {
		return l
	}
	return discardLogger
}

func (s *session) onReady() {
	systray.SetIcon(trayIcon)
	systray.SetTooltip("vpnpa")
	s.statusItem = systray.AddMenuItem("vpnpa", "")
	s.statusItem.Disable()
	s.upItem = systray.AddMenuItem("Включить", "поднять локальный прокси")
	s.downItem = systray.AddMenuItem("Выключить", "остановить локальный прокси")
	s.preferItem = systray.AddMenuItem("Предпочтение", "выбрать выход")
	s.autoItem = s.preferItem.AddSubMenuItem("Авто", "обычная липкость")
	systray.AddSeparator()
	quit := systray.AddMenuItem("Выход", "остановить процесс")
	s.watchClicks(s.upItem, s.upFromUI)
	s.watchClicks(s.downItem, s.down)
	s.watchClicks(s.autoItem, func() { _ = cmdPrefer(s.layout, []string{"auto"}) })
	s.watchClicks(quit, s.requestStop)
	s.trayReady.Store(true)
	if s.quitReq.Load() {
		systray.Quit()
		return
	}
	s.refresh()
	go s.loop()
}

func (s *session) watchClicks(item *systray.MenuItem, fn func()) {
	go func() {
		for range item.ClickedCh {
			fn()
			s.kick()
		}
	}()
}

func (s *session) loop() {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.stopLoop:
			return
		case <-tick.C:
			s.refresh()
		case <-s.changed:
			s.refresh()
		}
	}
}

func (s *session) upFromUI() {
	if err := s.up(); err != nil {
		s.setNote(shortNote(err))
		s.logger().Warn("не включился", "err", err)
	}
}

func (s *session) requestStop() {
	s.quitReq.Store(true)
	s.haltOnce.Do(func() { close(s.stopLoop) })
	s.down()
	if s.trayReady.Load() {
		systray.Quit()
	}
}

func (s *session) kick() {
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

func (s *session) setNote(msg string) {
	s.mu.Lock()
	s.note = msg
	s.mu.Unlock()
	s.kick()
}

func (s *session) up() error {
	s.op.Lock()
	defer s.op.Unlock()
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	f, err := config.Load(s.layout.ConfigPath)
	if err != nil {
		return err
	}
	if err := f.Validate(); err != nil {
		return err
	}
	if len(f.Backends) == 0 {
		return errNoBackends()
	}
	_ = os.Remove(s.layout.StatusPath())
	ctx, cancel := context.WithCancel(context.Background())
	a := app.New(app.Options{
		File:       f,
		ConfigPath: s.layout.ConfigPath,
		StateDir:   s.layout.StateDir,
		Logger:     s.logger(),
		Signals:    false,
	})
	done := make(chan struct{})
	s.mu.Lock()
	s.gen++
	gen := s.gen
	s.app = a
	s.cancel = cancel
	s.done = done
	s.running = true
	s.started = time.Now()
	s.note = ""
	s.mu.Unlock()
	go func() {
		err := a.Run(ctx)
		s.mu.Lock()
		if s.gen == gen {
			s.running = false
			s.app = nil
			s.cancel = nil
			if err != nil && ctx.Err() == nil {
				s.note = shortNote(err)
			}
		}
		s.mu.Unlock()
		close(done)
		s.kick()
	}()
	s.kick()
	return nil
}

func (s *session) down() {
	s.op.Lock()
	defer s.op.Unlock()
	s.mu.Lock()
	cancel := s.cancel
	done := s.done
	s.gen++
	s.app = nil
	s.cancel = nil
	s.running = false
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	s.kick()
}

func (s *session) reload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.app == nil {
		return
	}
	if err := s.app.Reload(context.Background()); err != nil {
		s.logger().Warn("ошибка перечитывания конфига", "err", err)
	}
}

func (s *session) refresh() {
	if s.statusItem == nil {
		return
	}
	s.mu.Lock()
	running := s.running
	started := s.started
	note := s.note
	s.mu.Unlock()
	current, alive, fresh := readTrayStatus(s.layout.StatusPath(), started)
	line := trayStatusText(running, fresh, current, alive)
	if !running && note != "" {
		line = note
	}
	s.statusItem.SetTitle(menuLabel(line))
	systray.SetTooltip(fitTip(line))
	if running {
		s.upItem.Disable()
		s.downItem.Enable()
	} else {
		s.upItem.Enable()
		s.downItem.Disable()
	}
	s.syncPrefer()
}

func (s *session) syncPrefer() {
	f, err := config.Load(s.layout.ConfigPath)
	if err != nil {
		return
	}
	choice := readPrefer(s.layout.PreferPath())
	if s.autoItem != nil {
		if choice == "auto" {
			s.autoItem.Check()
		} else {
			s.autoItem.Uncheck()
		}
	}
	seen := map[string]struct{}{}
	label := "Предпочтение: " + choice
	s.preferItem.SetTitle(menuLabel(label))
	for _, b := range f.Backends {
		seen[b.ID] = struct{}{}
		item := s.items[b.ID]
		if item == nil {
			item = s.preferItem.AddSubMenuItem(menuLabel(b.ID), "предпочтительный выход")
			s.items[b.ID] = item
			id := b.ID
			s.watchClicks(item, func() { _ = cmdPrefer(s.layout, []string{id}) })
		} else {
			item.Show()
			item.SetTitle(menuLabel(b.ID))
		}
		if b.ID == choice {
			item.Check()
		} else {
			item.Uncheck()
		}
	}
	for id, item := range s.items {
		if _, ok := seen[id]; !ok {
			item.Hide()
			item.Uncheck()
		}
	}
}

func readPrefer(path string) string {
	raw, err := os.ReadFile(path) // #nosec G304 -- путь prefer задаёт раскладка
	if err != nil {
		return "auto"
	}
	choice := strings.TrimSpace(string(raw))
	if choice == "" {
		return "auto"
	}
	return choice
}

type trayStatusJSON struct {
	Current  string `json:"current"`
	Backends []struct {
		ID    string `json:"id"`
		Alive bool   `json:"alive"`
	} `json:"backends"`
}

func readTrayStatus(path string, started time.Time) (current string, alive, fresh bool) {
	fi, err := os.Stat(path)
	if err != nil || fi.ModTime().Before(started) {
		return "", false, false
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- путь status.json задаёт раскладка
	if err != nil {
		return "", false, false
	}
	var st trayStatusJSON
	if err := json.Unmarshal(raw, &st); err != nil {
		return "", false, false
	}
	alive = false
	for _, b := range st.Backends {
		if b.ID == st.Current && st.Current != "" {
			alive = b.Alive
		}
	}
	return st.Current, alive, true
}

func fitTip(s string) string {
	r := []rune(s)
	if len(r) > 120 {
		return string(r[:120])
	}
	return s
}

func openTrayLog(layout paths.Layout, level, format string) (*slog.Logger, func(), error) {
	f, err := config.Load(layout.ConfigPath)
	if err != nil {
		return nil, nil, err
	}
	if level == "" {
		level = f.Log.Level
	}
	if format == "" {
		format = f.Log.Format
	}
	path := logPath(layout)
	if st, err := os.Stat(path); err == nil && st.Size() > 1<<20 {
		_ = os.Remove(path)
	}
	lf, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 G302 -- лог в каталоге состояния, режим 0600
	if err != nil {
		return logx.New(io.Discard, level, format), func() {}, nil
	}
	return logx.New(lf, level, format), func() { _ = lf.Close() }, nil
}
