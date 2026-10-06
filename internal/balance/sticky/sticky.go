// Package sticky keeps user traffic on one live backend until that backend
// fails its probe threshold. A recovered higher-priority backend does not
// take over by itself.
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

// Options configures the probe loop. Zero values are replaced with defaults.
type Options struct {
	CheckInterval    time.Duration
	CheckTimeout     time.Duration
	FailThreshold    int
	RecoverThreshold int
	RestartInterval  time.Duration
	CheckURLs        []string
	EgressURL        string
	EgressInterval   time.Duration
	PreferPath       string
	Logger           *slog.Logger
	OnStatus         func(Status)
	// Now overrides the clock used for restart_interval. Tests advance it.
	Now func() time.Time
}

// BackendStatus is one row of the status file.
type BackendStatus struct {
	ID       string `json:"id"`
	Priority int    `json:"priority"`
	Alive    bool   `json:"alive"`
	Endpoint string `json:"endpoint,omitempty"`
}

// Status is what vpnpa status prints.
type Status struct {
	Listen     string          `json:"listen,omitempty"`
	HTTPListen string          `json:"http_listen,omitempty"`
	Current    string          `json:"current,omitempty"`
	Preference string          `json:"preference"`
	EgressIP   string          `json:"egress_ip,omitempty"`
	Backends   []BackendStatus `json:"backends"`
}

type health struct {
	alive       bool
	okStreak    int
	failStreak  int
	nextRestart time.Time
	// restarting is set while Down/Up of a non-current backend is in progress
	// so a probe cannot select that backend and then close it.
	restarting bool
}

type currentBox struct {
	b backend.Backend
}

// Sticky implements dialer.Dialer over a fixed set of backends.
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

// New builds a balancer. Backends are not constructed here.
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
	// Copy so a later mutation of the caller's slice cannot race with probes.
	// An empty list is the default pair: check_urls replaces the list only
	// when the caller actually provides URLs.
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

// Run probes until ctx is cancelled. The first cycle runs immediately.
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

// SetBackends swaps the list used by later cycles. An unchanged instance
// keeps its health. The current id is kept when it is still present and alive.
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
			// A replaced instance keeps "alive" so the current id stays
			// selected, but streaks start over: it is a new tunnel.
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

// DialContext sends the connection to the current backend only.
// A dial error does not change the selection; it requests an extra probe.
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

// Snapshot returns a copy of the published state.
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
	// A cancelled run must not record timeouts as real failures: that would
	// restart tunnels while the process is stopping.
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
		// A probe started before SetBackends belongs to the old instance.
		// Applying it would mark the replacement unhealthy or Up the removed tunnel.
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
			// The current backend is not closed by a probe. restart_interval
			// applies only after it is no longer current.
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

// restartWantedLocked reports whether a non-current unhealthy backend is due
// for its single Down+Up. The current backend is never included.
func (s *Sticky) restartWantedLocked(h *health, id string) bool {
	if h == nil || h.alive || h.restarting || isCurrentID(s.current, id) {
		return false
	}
	if h.failStreak < s.opt.FailThreshold {
		return false
	}
	return h.nextRestart.IsZero() || s.restartDue(h.nextRestart)
}

// ProbeNow runs a single probe cycle. The background Run loop is not required.
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
	// Reserve the interval before Down so a concurrent cycle cannot queue
	// another restart of the same backend.
	if h.nextRestart.IsZero() || s.restartDue(h.nextRestart) {
		h.nextRestart = s.now().Add(s.opt.RestartInterval)
	}
	s.mu.Unlock()

	// finished is set once this call has cleared the flag itself. The defer
	// covers every earlier return and must not clear a newer restart.
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
	// The instance may have been replaced while Down ran. Up of the removed
	// tunnel would bring back a device the process already dropped.
	s.mu.Lock()
	same := s.sameInstanceLocked(b)
	s.mu.Unlock()
	if !same {
		return
	}
	if err := b.Up(ctx); err != nil {
		s.opt.Logger.Warn("ошибка поднятия бэкенда", "backend", b.ID(), "err", safeErr(err))
	}
	// Up can block on the network. Reload may have swapped the instance
	// while it ran; the old device must not stay up beside the new one.
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
	// Clear the flag before reselect so a recovered backend can be chosen
	// when nothing else is alive. It was not current, so this cannot close
	// the tunnel that was serving user traffic.
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
	// Always publish the concrete value. Same id can be a new instance;
	// DialContext reads this pointer, not s.current.
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
	// restarting backends are mid Down/Up. Selecting one would point new
	// dials at a device the probe is about to close.
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
	// The fetch used a sampled backend. If it is no longer current, keep the
	// previous IP instead of publishing an address from the wrong tunnel.
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

// safeErr is a log string with vpn:// URIs and URL userinfo removed.
func safeErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	s = vpnURI.ReplaceAllString(s, "[redacted-uri]")
	s = urlUser.ReplaceAllString(s, "://REDACTED@")
	return s
}
