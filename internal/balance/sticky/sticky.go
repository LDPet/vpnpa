// Package sticky держит трафик на одном живом бэкенде, пока тот не провалит
// порог проб. Оживший бэкенд с большим приоритетом сам место не занимает.
//
// Текущий бэкенд проба не гасит и не поднимает заново: Down/Up по
// restart_interval делается только у того, кто уже не текущий. Проба
// успешна, если хотя бы один URL из списка ответил: для http(s) это ровно
// статус 204, для tcp:// — открывшееся соединение. Файл prefer
// перечитывается на каждом цикле и может прибить выбор к id.
package sticky

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LDPet/vpnpa/internal/backend"
	"github.com/LDPet/vpnpa/internal/dialer"
	"github.com/LDPet/vpnpa/internal/logx"
)

// Options задаёт цикл проб. Нулевые числа заменяются умолчаниями в New.
type Options struct {
	// CheckInterval — пауза между полными обходами всех бэкендов.
	CheckInterval time.Duration
	// CheckTimeout — сколько ждать одну пробу, включая TLS.
	CheckTimeout time.Duration
	// FailThreshold — подряд неудачных проб, после которых живой бэкенд становится мёртвым.
	FailThreshold int
	// RecoverThreshold — подряд удачных проб, после которых мёртвый снова живой.
	RecoverThreshold int
	// RestartInterval — как часто делать Down+Up нетекущему мёртвому бэкенду.
	// Текущего это не касается: его проба не закрывает.
	RestartInterval time.Duration
	// CheckURLs пробуются по порядку. Первый ответ HTTP 204 (или успешный tcp)
	// делает пробу успешной, остальные в этом цикле не вызываются.
	// Пустой список в New заменяется парой generate_204. Непустой список
	// заменяет умолчание целиком, а не дополняет его.
	CheckURLs []string
	// EgressURL — откуда читать внешний IP текущего бэкенда. Сбой этого
	// запроса пробу не валит.
	EgressURL string
	// EgressInterval — как часто обновлять внешний IP.
	EgressInterval time.Duration
	// PreferPath перечитывается на каждом цикле. "auto" или пусто — обычные
	// правила. Иначе id, если этот бэкенд жив и сейчас не в Down/Up.
	PreferPath string
	Logger     *slog.Logger
	// OnStatus вызывается в конце каждого завершённого цикла проб, даже если
	// поля снимка те же. Демон пишет им status.json. Внешний IP шлётся отдельно,
	// и только когда строка IP изменилась.
	OnStatus func(Status)
	// Now подменяет часы restart_interval. Тесты двигают время сами.
	Now func() time.Time
}

// BackendStatus — одна строка status.json.
type BackendStatus struct {
	ID       string `json:"id"`
	Priority int    `json:"priority"`
	Alive    bool   `json:"alive"`
	Endpoint string `json:"endpoint,omitempty"`
}

// Status — снимок, который печатает `vpnpa status` и пишет демон.
// Current пуст, когда живого бэкенда нет: трафик в этом состоянии наружу не идёт.
type Status struct {
	Listen     string          `json:"listen,omitempty"`
	HTTPListen string          `json:"http_listen,omitempty"`
	Current    string          `json:"current,omitempty"`
	Preference string          `json:"preference"`
	EgressIP   string          `json:"egress_ip,omitempty"`
	Backends   []BackendStatus `json:"backends"`
}

// health — счётчики одного id. alive переключается, когда подряд набралось
// FailThreshold провалов или RecoverThreshold успехов. Пороги по умолчанию
// больше единицы, но в конфиге могут быть 1. nextRestart — момент, когда нетекущему мёртвому
// разрешён один Down+Up. restarting стоит на время этого Down/Up:
// иначе проба успеет выбрать бэкенд и тут же закроет его под трафиком.
type health struct {
	alive       bool
	okStreak    int
	failStreak  int
	nextRestart time.Time
	restarting  bool
}

type currentBox struct {
	b backend.Backend
}

// Sticky реализует dialer.Dialer поверх набора бэкендов.
// DialContext читает atomic-указатель currentBox, а не поле current под мьютексом:
// выбор можно опубликовать, не блокируя каждое пользовательское соединение.
type Sticky struct {
	opt Options

	mu      sync.Mutex
	order   []backend.Backend
	byID    map[string]backend.Backend
	health  map[string]*health
	current backend.Backend
	prefer  string
	egress  string

	ptr atomic.Pointer[currentBox]

	kick chan struct{}
}

// New собирает балансировщик. Бэкенды здесь не создаются и не поднимаются:
// их Up уже сделал вызывающий. Пустой CheckURLs заменяется парой
// generate_204 (gstatic и cloudflare). Непустой список используется как есть.
func New(backends []backend.Backend, opt Options) *Sticky {
	if opt.CheckInterval <= 0 {
		opt.CheckInterval = 15 * time.Second
	}
	if opt.CheckTimeout <= 0 {
		opt.CheckTimeout = 8 * time.Second
	}
	if opt.FailThreshold < 1 {
		opt.FailThreshold = 3
	}
	if opt.RecoverThreshold < 1 {
		opt.RecoverThreshold = 2
	}
	if opt.RestartInterval <= 0 {
		opt.RestartInterval = 5 * time.Minute
	}
	// Копия, чтобы последующая правка среза вызывающего не гонялась с пробами.
	// Пустой список — пара по умолчанию. check_urls подменяет список только
	// когда вызывающий действительно передал URL.
	opt.CheckURLs = append([]string(nil), opt.CheckURLs...)
	if len(opt.CheckURLs) == 0 {
		opt.CheckURLs = []string{
			"https://www.gstatic.com/generate_204",
			"https://cp.cloudflare.com/generate_204",
		}
	}
	if opt.EgressURL == "" {
		opt.EgressURL = "https://api.ipify.org"
	}
	if opt.EgressInterval <= 0 {
		opt.EgressInterval = time.Minute
	}
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Sticky{
		opt:    opt,
		byID:   map[string]backend.Backend{},
		health: map[string]*health{},
		prefer: "auto",
		kick:   make(chan struct{}, 1),
	}
	s.setBackendsLocked(backends)
	return s
}

// Run пробует бэкенды, пока ctx не отменён. Первый цикл выполняется сразу,
// не дожидаясь тикера, чтобы трафик не ждал check_interval после старта.
func (s *Sticky) Run(ctx context.Context) {
	s.cycle(ctx)
	s.refreshEgress(ctx)
	probeTick := time.NewTicker(s.opt.CheckInterval)
	defer probeTick.Stop()
	egressTick := time.NewTicker(s.opt.EgressInterval)
	defer egressTick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-probeTick.C:
			s.cycle(ctx)
		case <-egressTick.C:
			s.refreshEgress(ctx)
		case <-s.kick:
			s.probeCurrent(ctx)
		}
	}
}

// SetBackends подменяет список для следующих циклов. Тот же указатель
// сохраняет здоровье и серии. Затем reselect: id из prefer забирает выбор
// только если он selectable (жив и не в restarting), даже когда прежний
// текущий тоже жив. Иначе текущий остаётся, если он ещё в списке и selectable.
// Вызывается после SIGHUP: app передаёт те же tracked-указатели для неизменных
// URI, поэтому Down/Up им не нужен.
func (s *Sticky) SetBackends(list []backend.Backend) {
	s.mu.Lock()
	s.setBackendsLocked(list)
	s.reselectLocked("reload")
	st := s.snapshotLocked()
	s.mu.Unlock()
	s.emit(st)
}

func (s *Sticky) setBackendsLocked(list []backend.Backend) {
	next := make(map[string]backend.Backend, len(list))
	order := make([]backend.Backend, 0, len(list))
	for _, b := range list {
		next[b.ID()] = b
		order = append(order, b)
		old, ok := s.byID[b.ID()]
		if !ok || old != b {
			// Новый экземпляр того же id сохраняет alive, чтобы текущий выбор
			// не сбросился на перезагрузке, но серии обнуляются: туннель другой.
			keep := false
			if ok {
				if h := s.health[b.ID()]; h != nil {
					keep = h.alive
				}
			}
			s.health[b.ID()] = &health{alive: keep}
		}
	}
	for id := range s.health {
		if _, ok := next[id]; !ok {
			delete(s.health, id)
		}
	}
	if s.current != nil {
		if b, ok := next[s.current.ID()]; ok {
			s.current = b
		} else {
			s.current = nil
		}
	}
	s.byID = next
	s.order = order
	s.publishLocked(s.current)
}

// DialContext отправляет соединение только в текущий бэкенд.
// Ошибка dial выбор не меняет: одна ошибка пользователя — не повод бросить
// туннель. Она лишь просит внеочередную пробу текущего.
func (s *Sticky) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	box := s.ptr.Load()
	if box == nil || box.b == nil {
		s.opt.Logger.Warn("нет живых бэкендов", "conn_id", logx.ConnID(ctx), "addr", address)
		return nil, dialer.ErrNoHealthyBackend
	}
	b := box.b
	start := time.Now()
	c, err := b.DialContext(ctx, network, address)
	if err != nil {
		s.opt.Logger.Warn("ошибка dial",
			"conn_id", logx.ConnID(ctx),
			"backend", b.ID(),
			"addr", address,
			"duration", time.Since(start),
			"err", safeErr(err),
		)
		s.requestProbe()
		return nil, fmt.Errorf("backend %s: %w", b.ID(), err)
	}
	s.opt.Logger.Debug("dial", "conn_id", logx.ConnID(ctx), "backend", b.ID(), "addr", address, "duration", time.Since(start))
	return c, nil
}

// Snapshot возвращает копию опубликованного состояния.
func (s *Sticky) Snapshot() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

func (s *Sticky) snapshotLocked() Status {
	st := Status{
		Current:    idOf(s.current),
		Preference: s.prefer,
		EgressIP:   s.egress,
		Backends:   make([]BackendStatus, 0, len(s.order)),
	}
	if st.Preference == "" {
		st.Preference = "auto"
	}
	for _, b := range s.order {
		h := s.health[b.ID()]
		alive := h != nil && h.alive
		st.Backends = append(st.Backends, BackendStatus{
			ID:       b.ID(),
			Priority: b.Priority(),
			Alive:    alive,
			Endpoint: backend.EndpointOf(b),
		})
	}
	return st
}

func (s *Sticky) emit(st Status) {
	if s.opt.OnStatus != nil {
		s.opt.OnStatus(st)
	}
}

func (s *Sticky) requestProbe() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

type probeResult struct {
	b       backend.Backend
	ok      bool
	latency time.Duration
}

func (s *Sticky) cycle(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	backends := s.backendSnapshot()
	results := make([]probeResult, len(backends))
	var wg sync.WaitGroup
	for i, b := range backends {
		wg.Add(1)
		go func(i int, b backend.Backend) {
			defer wg.Done()
			start := time.Now()
			ok := s.probe(ctx, b)
			results[i] = probeResult{b: b, ok: ok, latency: time.Since(start)}
		}(i, b)
	}
	wg.Wait()
	// Отменённый цикл не записывает таймауты как настоящие провалы:
	// иначе остановка процесса перезапускала бы туннели.
	if ctx.Err() != nil {
		return
	}
	s.apply(ctx, results)
}

func (s *Sticky) backendSnapshot() []backend.Backend {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]backend.Backend, len(s.order))
	copy(out, s.order)
	return out
}

func (s *Sticky) apply(ctx context.Context, results []probeResult) {
	s.mu.Lock()
	s.prefer = readPrefer(s.opt.PreferPath)
	type job struct {
		b backend.Backend
	}
	var jobs []job
	for _, r := range results {
		// Проба, начатая до SetBackends, принадлежит старому экземпляру.
		// Применить её — пометить замену мёртвой или поднять уже снятый туннель.
		if cur, ok := s.byID[r.b.ID()]; !ok || cur != r.b {
			continue
		}
		h := s.health[r.b.ID()]
		if h == nil {
			h = &health{}
			s.health[r.b.ID()] = h
		}
		wasAlive := h.alive
		becameDead, becameAlive := h.observe(r.ok, s.opt.FailThreshold, s.opt.RecoverThreshold)
		s.logProbe(r, h)
		if !r.ok && wasAlive && !becameDead {
			s.opt.Logger.Warn("проба к порогу",
				"backend", r.b.ID(),
				"fail_streak", h.failStreak,
				"fail_threshold", s.opt.FailThreshold,
			)
		}
		if becameAlive {
			s.opt.Logger.Info("бэкенд жив", "backend", r.b.ID(), "priority", r.b.Priority())
		}
		if becameDead {
			s.opt.Logger.Info("бэкенд нежив", "backend", r.b.ID(), "priority", r.b.Priority())
			isCurrent := isCurrentID(s.current, r.b.ID())
			// Проба текущий бэкенд не закрывает. nextRestart становится now+интервал,
			// и в очередь Down+Up бэкенд попадает, только если он уже не текущий.
			// Если он ещё текущий, reselect в этом же цикле снимает выбор:
			// бэкенд больше не selectable, даже когда живой замены нет.
			// Сам Down+Up не в этом цикле. Его пустят те циклы, где now >= nextRestart.
			h.nextRestart = s.now().Add(s.opt.RestartInterval)
			if !isCurrent && !h.restarting {
				jobs = append(jobs, job{b: r.b})
			}
		} else if s.restartWantedLocked(h, r.b.ID()) {
			h.nextRestart = s.now().Add(s.opt.RestartInterval)
			jobs = append(jobs, job{b: r.b})
		}
	}
	s.reselectLocked("probe")
	st := s.snapshotLocked()
	s.mu.Unlock()
	s.emit(st)

	for _, j := range jobs {
		s.restart(ctx, j.b)
	}
}

func (s *Sticky) now() time.Time {
	if s.opt.Now != nil {
		return s.opt.Now()
	}
	return time.Now()
}

func (s *Sticky) restartDue(t time.Time) bool {
	return !t.IsZero() && !s.now().Before(t)
}

// restartWantedLocked говорит, пора ли нетекущему мёртвому бэкенду сделать
// один Down+Up. Текущий сюда не попадает никогда.
func (s *Sticky) restartWantedLocked(h *health, id string) bool {
	if h == nil || h.alive || h.restarting || isCurrentID(s.current, id) {
		return false
	}
	if h.failStreak < s.opt.FailThreshold {
		return false
	}
	return h.nextRestart.IsZero() || s.restartDue(h.nextRestart)
}

// ProbeNow выполняет один цикл проб. Фоновый Run для этого не нужен.
func (s *Sticky) ProbeNow(ctx context.Context) {
	s.cycle(ctx)
}

func isCurrentID(cur backend.Backend, id string) bool {
	return cur != nil && cur.ID() == id
}

func (s *Sticky) logProbe(r probeResult, h *health) {
	streak := h.okStreak
	if !r.ok {
		streak = h.failStreak
	}
	s.opt.Logger.Debug("проба",
		"backend", r.b.ID(),
		"ok", r.ok,
		"latency", r.latency,
		"streak", streak,
	)
}

func (s *Sticky) restart(ctx context.Context, b backend.Backend) {
	if ctx.Err() != nil {
		return
	}
	s.mu.Lock()
	h := s.health[b.ID()]
	if !s.sameInstanceLocked(b) || h == nil || h.restarting || isCurrentID(s.current, b.ID()) {
		s.mu.Unlock()
		return
	}
	h.restarting = true
	// Интервал занимается до Down, чтобы соседний цикл не поставил
	// второй переподъём того же бэкенда.
	if h.nextRestart.IsZero() || s.restartDue(h.nextRestart) {
		h.nextRestart = s.now().Add(s.opt.RestartInterval)
	}
	s.mu.Unlock()

	// finished ставится, когда этот вызов сам снял флаг. defer закрывает
	// ранние выходы и не должен сбрасывать уже новый переподъём.
	finished := false
	defer func() {
		if finished {
			return
		}
		s.mu.Lock()
		if s.health[b.ID()] == h {
			h.restarting = false
		}
		s.mu.Unlock()
	}()

	s.opt.Logger.Info("переподъём бэкенда", "backend", b.ID())
	if err := b.Down(ctx); err != nil {
		s.opt.Logger.Warn("ошибка остановки бэкенда", "backend", b.ID(), "err", safeErr(err))
	}
	// Пока шёл Down, экземпляр могли заменить (SIGHUP). Up снятого туннеля
	// вернул бы устройство, которое процесс уже отпустил.
	s.mu.Lock()
	same := s.sameInstanceLocked(b)
	s.mu.Unlock()
	if !same {
		return
	}
	if err := b.Up(ctx); err != nil {
		s.opt.Logger.Warn("ошибка поднятия бэкенда", "backend", b.ID(), "err", safeErr(err))
	}
	// Up может ждать сеть. Reload за это время мог подменить экземпляр;
	// старое устройство не должно остаться поднятым рядом с новым.
	s.mu.Lock()
	same = s.sameInstanceLocked(b)
	s.mu.Unlock()
	if !same {
		if err := b.Down(ctx); err != nil {
			s.opt.Logger.Warn("ошибка остановки бэкенда", "backend", b.ID(), "err", safeErr(err))
		}
		return
	}
	if ctx.Err() != nil {
		return
	}
	start := time.Now()
	ok := s.probe(ctx, b)
	if ctx.Err() != nil {
		return
	}
	s.mu.Lock()
	if !s.sameInstanceLocked(b) || s.health[b.ID()] != h {
		s.mu.Unlock()
		if err := b.Down(ctx); err != nil {
			s.opt.Logger.Warn("ошибка остановки бэкенда", "backend", b.ID(), "err", safeErr(err))
		}
		return
	}
	_, becameAlive := h.observe(ok, s.opt.FailThreshold, s.opt.RecoverThreshold)
	if becameAlive {
		s.opt.Logger.Info("бэкенд жив", "backend", b.ID(), "priority", b.Priority())
	}
	s.logProbe(probeResult{b: b, ok: ok, latency: time.Since(start)}, h)
	// Флаг снимается до reselect, чтобы оживший бэкенд мог быть выбран,
	// когда живых больше нет. Текущим он не был, поэтому это не закрывает
	// туннель, который нёс пользовательский трафик.
	h.restarting = false
	finished = true
	s.reselectLocked("probe")
	st := s.snapshotLocked()
	s.mu.Unlock()
	s.emit(st)
}

func (s *Sticky) sameInstanceLocked(b backend.Backend) bool {
	cur, ok := s.byID[b.ID()]
	return ok && cur == b
}

func (s *Sticky) probeCurrent(ctx context.Context) {
	s.mu.Lock()
	b := s.current
	s.mu.Unlock()
	if b == nil {
		return
	}
	start := time.Now()
	ok := s.probe(ctx, b)
	if ctx.Err() != nil {
		return
	}
	s.apply(ctx, []probeResult{{b: b, ok: ok, latency: time.Since(start)}})
}

// reselectLocked выбирает, куда слать новые соединения.
// Порядок: живой prefer (если не "auto"), иначе прежний текущий, если он
// ещё выбираем, иначе живой с наибольшим приоритетом. Оживший «более важный»
// бэкенд текущий не вытесняет — для этого есть файл prefer.
func (s *Sticky) reselectLocked(why string) {
	prefer := s.prefer
	if prefer == "" {
		prefer = "auto"
	}
	var next backend.Backend
	reason := ""
	if prefer != "auto" {
		if b, ok := s.byID[prefer]; ok && s.selectableLocked(prefer) {
			next = b
			if s.current == nil || s.current.ID() != prefer {
				reason = "prefer"
			}
		}
	}
	if next == nil && s.current != nil && s.selectableLocked(s.current.ID()) {
		next = s.current
	}
	if next == nil {
		next = s.highestSelectableLocked()
		if next != nil && (s.current == nil || s.current.ID() != next.ID()) && reason == "" {
			reason = why
		}
	}
	if idOf(s.current) == "" && next != nil && reason != "prefer" {
		reason = "start"
	}
	s.assignLocked(next, reason)
}

func (s *Sticky) assignLocked(next backend.Backend, reason string) {
	from := idOf(s.current)
	to := idOf(next)
	s.current = next
	// Публикуется конкретный указатель. Тот же id может быть новым экземпляром,
	// а DialContext читает этот указатель, не поле current.
	s.publishLocked(next)
	if from == to {
		return
	}
	if next == nil {
		s.opt.Logger.Info("переключение", "from", from, "to", "", "reason", reason)
		s.opt.Logger.Warn("нет живых бэкендов")
		return
	}
	if reason == "" {
		reason = "start"
	}
	s.opt.Logger.Info("переключение", "from", from, "to", to, "reason", reason)
}

func (s *Sticky) publishLocked(next backend.Backend) {
	if next == nil {
		s.ptr.Store(nil)
		return
	}
	if box := s.ptr.Load(); box != nil && box.b == next {
		return
	}
	s.ptr.Store(&currentBox{b: next})
}

func (s *Sticky) selectableLocked(id string) bool {
	h := s.health[id]
	// Бэкенд с restarting посреди Down/Up. Выбрать его — направить новые
	// dial в устройство, которое проба сейчас закрывает.
	return h != nil && h.alive && !h.restarting
}

func (s *Sticky) highestSelectableLocked() backend.Backend {
	var best backend.Backend
	for _, b := range s.order {
		if !s.selectableLocked(b.ID()) {
			continue
		}
		if best == nil || b.Priority() > best.Priority() {
			best = b
		}
	}
	return best
}

// observe двигает серии. Успех обнуляет провалы и наоборот.
// alive меняется, когда серия добрала failN или recN. При пороге 1
// для этого хватает одной пробы.
func (h *health) observe(ok bool, failN, recN int) (becameDead, becameAlive bool) {
	if ok {
		h.failStreak = 0
		h.okStreak++
		if !h.alive && h.okStreak >= recN {
			h.alive = true
			becameAlive = true
		}
		return false, becameAlive
	}
	h.okStreak = 0
	h.failStreak++
	if h.alive && h.failStreak >= failN {
		h.alive = false
		return true, false
	}
	return false, false
}

// probe обходит CheckURLs по порядку. Первый успех — проба удалась,
// остальные URL в этом обходе не спрашиваются. Все провалы — бэкенд не ответил.
func (s *Sticky) probe(ctx context.Context, b backend.Backend) bool {
	for _, raw := range s.opt.CheckURLs {
		if s.probeOne(ctx, b, raw) {
			return true
		}
	}
	return false
}

func (s *Sticky) probeOne(ctx context.Context, b backend.Backend, raw string) bool {
	ctx, cancel := context.WithTimeout(ctx, s.opt.CheckTimeout)
	defer cancel()
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch u.Scheme {
	case "tcp":
		c, err := b.DialContext(ctx, "tcp", u.Host)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	case "http", "https":
		return s.probeHTTP(ctx, b, raw)
	default:
		return false
	}
}

// probeHTTP считает успехом только HTTP 204. Dial идёт через бэкенд,
// не через сеть хоста. Тело ответа сливается с лимитом и не разбирается.
func (s *Sticky) probeHTTP(ctx context.Context, b backend.Backend, raw string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return false
	}
	transport := &http.Transport{
		DialContext:           b.DialContext,
		ResponseHeaderTimeout: s.opt.CheckTimeout,
		TLSHandshakeTimeout:   s.opt.CheckTimeout,
		DisableKeepAlives:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   s.opt.CheckTimeout,
		// Редирект не считается 204: проверяется ответ именно этого URL.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode == http.StatusNoContent
}

func (s *Sticky) refreshEgress(ctx context.Context) {
	s.mu.Lock()
	b := s.current
	s.mu.Unlock()
	if b == nil || s.opt.EgressURL == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, s.opt.CheckTimeout)
	defer cancel()
	ip, err := fetchEgress(ctx, b, s.opt.EgressURL)
	if err != nil {
		s.opt.Logger.Debug("внешний IP недоступен", "backend", b.ID(), "err", safeErr(err))
		return
	}
	s.mu.Lock()
	// Запрос шёл через снятый снимок. Если бэкенд уже не текущий, прежний IP
	// остаётся: публиковать адрес чужого туннеля нельзя.
	if !isCurrentID(s.current, b.ID()) || (s.current != nil && s.current != b) {
		s.mu.Unlock()
		return
	}
	changed := s.egress != ip
	s.egress = ip
	st := s.snapshotLocked()
	s.mu.Unlock()
	if changed {
		s.opt.Logger.Info("внешний IP", "backend", b.ID(), "egress_ip", ip)
		s.emit(st)
	}
}

func fetchEgress(ctx context.Context, b backend.Backend, raw string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return "", err
	}
	transport := &http.Transport{
		DialContext:           b.DialContext,
		ResponseHeaderTimeout: 8 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		DisableKeepAlives:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("egress status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(string(body))
	if i := strings.IndexAny(text, "\r\n "); i >= 0 {
		text = text[:i]
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

// readPrefer читает файл предпочтения заново на каждом цикле.
// Нет файла, пусто или ошибка — "auto". При auto живой текущий остаётся,
// даже если ожил бэкенд с большим приоритетом. Наибольший приоритет берётся,
// только когда текущего уже нельзя выбрать. `vpnpa prefer` только пишет файл.
func readPrefer(path string) string {
	if path == "" {
		return "auto"
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- путь файла предпочтения задаёт пользователь
	if err != nil {
		return "auto"
	}
	v := strings.TrimSpace(string(raw))
	if v == "" {
		return "auto"
	}
	return v
}

func idOf(b backend.Backend) string {
	if b == nil {
		return ""
	}
	return b.ID()
}

var (
	vpnURI  = regexp.MustCompile(`vpn://\S+`)
	urlUser = regexp.MustCompile(`://[^/\s@]+@`)
)

// safeErr — строка для лога без vpn:// и userinfo в URL.
func safeErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	s = vpnURI.ReplaceAllString(s, "[redacted-uri]")
	s = urlUser.ReplaceAllString(s, "://REDACTED@")
	return s
}
