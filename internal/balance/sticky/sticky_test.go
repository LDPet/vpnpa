package sticky

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/LDPet/vpnpa/internal/backend"
	"github.com/LDPet/vpnpa/internal/dialer"
)

const probeAddr = "probe.invalid:9"

type fake struct {
	id       string
	priority int
	endpoint string

	mu         sync.Mutex
	failProbe  bool
	failUser   bool
	downs      int
	ups        int
	userDials  int
	probeDials int
	onProbe    func() error
	userConns  []*trackConn
}

type trackConn struct {
	net.Conn
	mu     sync.Mutex
	closed bool
}

func (c *trackConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *trackConn) wasClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (f *fake) ID() string       { return f.id }
func (f *fake) Priority() int    { return f.priority }
func (f *fake) Endpoint() string { return f.endpoint }

func (f *fake) Up(context.Context) error {
	f.mu.Lock()
	f.ups++
	f.mu.Unlock()
	return nil
}

func (f *fake) Down(context.Context) error {
	f.mu.Lock()
	f.downs++
	f.mu.Unlock()
	return nil
}

func (f *fake) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	f.mu.Lock()
	onProbe := f.onProbe
	failProbe := f.failProbe
	failUser := f.failUser
	f.mu.Unlock()
	if address == probeAddr {
		if onProbe != nil {
			if err := onProbe(); err != nil {
				return nil, err
			}
		}
		f.mu.Lock()
		f.probeDials++
		f.mu.Unlock()
		if failProbe {
			return nil, errors.New("probe failed")
		}
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}
	if failUser {
		return nil, errors.New("vpn://SUPERSECRETKEY dial failed")
	}
	a, b := net.Pipe()
	tracked := &trackConn{Conn: a}
	f.mu.Lock()
	f.userDials++
	f.userConns = append(f.userConns, tracked)
	f.mu.Unlock()
	_ = b
	return tracked, nil
}

func (f *fake) downsN() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.downs
}

func (f *fake) upsN() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ups
}

func (f *fake) userDialsN() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.userDials
}

func (f *fake) probeDialsN() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.probeDials
}

func testOpts(t *testing.T) (Options, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return Options{
		CheckInterval:    time.Hour,
		CheckTimeout:     time.Second,
		FailThreshold:    3,
		RecoverThreshold: 2,
		RestartInterval:  time.Hour,
		CheckURLs:        []string{"tcp://" + probeAddr},
		EgressURL:        "http://127.0.0.1:1/ip",
		EgressInterval:   time.Hour,
		Logger:           log,
	}, &buf
}

func healthy(t *testing.T, s *Sticky, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		s.ProbeNow(ctx)
	}
}

func TestStartPicksHighestPriority(t *testing.T) {
	t.Parallel()
	opt, _ := testOpts(t)
	low := &fake{id: "low", priority: 10}
	high := &fake{id: "high", priority: 100}
	s := New([]backend.Backend{low, high}, opt)
	healthy(t, s, 2)
	if got := s.Snapshot().Current; got != "high" {
		t.Fatalf("current=%s", got)
	}
}

func TestRecoveredHigherDoesNotPreempt(t *testing.T) {
	t.Parallel()
	opt, _ := testOpts(t)
	high := &fake{id: "high", priority: 100}
	low := &fake{id: "low", priority: 10}
	s := New([]backend.Backend{high, low}, opt)
	healthy(t, s, 2)
	high.mu.Lock()
	high.failProbe = true
	high.mu.Unlock()
	healthy(t, s, 3)
	if got := s.Snapshot().Current; got != "low" {
		t.Fatalf("after failure current=%s", got)
	}
	high.mu.Lock()
	high.failProbe = false
	high.mu.Unlock()
	healthy(t, s, 2)
	if got := s.Snapshot().Current; got != "low" {
		t.Fatalf("recovered higher took over, current=%s", got)
	}
}

func TestSwitchOnlyAfterFailThreshold(t *testing.T) {
	t.Parallel()
	opt, _ := testOpts(t)
	high := &fake{id: "high", priority: 100}
	low := &fake{id: "low", priority: 10}
	s := New([]backend.Backend{high, low}, opt)
	healthy(t, s, 2)
	high.mu.Lock()
	high.failProbe = true
	high.mu.Unlock()
	s.ProbeNow(context.Background())
	if got := s.Snapshot().Current; got != "high" {
		t.Fatalf("one failure switched to %s", got)
	}
	healthy(t, s, 2)
	if got := s.Snapshot().Current; got != "low" {
		t.Fatalf("current=%s", got)
	}
}

func TestOneOfTwoURLsKeepsProbeSuccessful(t *testing.T) {
	t.Parallel()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	goodHits := 0
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		goodHits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer good.Close()
	opt, _ := testOpts(t)
	opt.CheckURLs = []string{bad.URL, good.URL}
	opt.RecoverThreshold = 1
	pass := &passthrough{id: "only", priority: 1}
	s := New([]backend.Backend{pass}, opt)
	s.ProbeNow(context.Background())
	if s.Snapshot().Current != "only" {
		t.Fatalf("probe with one 204 did not mark backend alive: %+v", s.Snapshot())
	}
	if goodHits == 0 {
		t.Fatal("second URL was not used")
	}
}

func TestRecoverThreshold(t *testing.T) {
	t.Parallel()
	opt, _ := testOpts(t)
	opt.RecoverThreshold = 2
	b := &fake{id: "b", priority: 1}
	s := New([]backend.Backend{b}, opt)
	s.ProbeNow(context.Background())
	if s.Snapshot().Current != "" {
		t.Fatal("alive before recover_threshold")
	}
	s.ProbeNow(context.Background())
	if s.Snapshot().Current != "b" {
		t.Fatalf("current=%s", s.Snapshot().Current)
	}
}

func TestNoHealthyBackend(t *testing.T) {
	t.Parallel()
	opt, _ := testOpts(t)
	b := &fake{id: "b", priority: 1, failProbe: true}
	s := New([]backend.Backend{b}, opt)
	healthy(t, s, 3)
	_, err := s.DialContext(context.Background(), "tcp", "example.com:80")
	if !errors.Is(err, dialer.ErrNoHealthyBackend) {
		t.Fatalf("err=%v", err)
	}
}

func TestUserDialErrorDoesNotSwitch(t *testing.T) {
	t.Parallel()
	opt, _ := testOpts(t)
	high := &fake{id: "high", priority: 100}
	low := &fake{id: "low", priority: 10}
	s := New([]backend.Backend{high, low}, opt)
	healthy(t, s, 2)
	high.mu.Lock()
	high.failUser = true
	high.mu.Unlock()
	if _, err := s.DialContext(context.Background(), "tcp", "example.com:80"); err == nil {
		t.Fatal("expected dial error")
	}
	s.ProbeNow(context.Background())
	if got := s.Snapshot().Current; got != "high" {
		t.Fatalf("dial error switched current to %s", got)
	}
}

func TestCurrentIsNotRestartedAtThreshold(t *testing.T) {
	t.Parallel()
	opt, _ := testOpts(t)
	high := &fake{id: "high", priority: 100}
	low := &fake{id: "low", priority: 10}
	s := New([]backend.Backend{high, low}, opt)
	healthy(t, s, 2)
	high.mu.Lock()
	high.failProbe = true
	high.mu.Unlock()
	healthy(t, s, 3)
	if s.Snapshot().Current != "low" {
		t.Fatalf("current=%s", s.Snapshot().Current)
	}
	if high.downsN() != 0 {
		t.Fatalf("current backend was Downed, downs=%d", high.downsN())
	}
}

func TestNonCurrentRestartOnceThenInterval(t *testing.T) {
	t.Parallel()
	clock := time.Unix(1_700_000_000, 0)
	opt, _ := testOpts(t)
	opt.Now = func() time.Time { return clock }
	opt.RestartInterval = time.Minute
	high := &fake{id: "high", priority: 100}
	low := &fake{id: "low", priority: 10}
	s := New([]backend.Backend{high, low}, opt)
	healthy(t, s, 2)
	low.mu.Lock()
	low.failProbe = true
	low.mu.Unlock()
	healthy(t, s, 3)
	if low.downsN() != 1 || low.upsN() != 1 {
		t.Fatalf("downs=%d ups=%d, want one Down+Up at threshold", low.downsN(), low.upsN())
	}
	if high.downsN() != 0 {
		t.Fatal("primary was restarted")
	}
	healthy(t, s, 5)
	if low.downsN() != 1 {
		t.Fatalf("restart repeated before interval, downs=%d", low.downsN())
	}
	clock = clock.Add(time.Minute)
	s.ProbeNow(context.Background())
	if low.downsN() != 2 {
		t.Fatalf("downs=%d after restart_interval, want 2", low.downsN())
	}
}

func TestFormerCurrentRestartsOnlyAfterInterval(t *testing.T) {
	t.Parallel()
	clock := time.Unix(1_700_000_000, 0)
	opt, _ := testOpts(t)
	opt.Now = func() time.Time { return clock }
	opt.RestartInterval = time.Minute
	high := &fake{id: "high", priority: 100}
	low := &fake{id: "low", priority: 10}
	s := New([]backend.Backend{high, low}, opt)
	healthy(t, s, 2)
	high.mu.Lock()
	high.failProbe = true
	high.mu.Unlock()
	healthy(t, s, 3)
	if s.Snapshot().Current != "low" {
		t.Fatalf("current=%s", s.Snapshot().Current)
	}
	if high.downsN() != 0 {
		t.Fatalf("Down happened in the same cycle, downs=%d", high.downsN())
	}
	healthy(t, s, 3)
	if high.downsN() != 0 {
		t.Fatalf("Down before restart_interval, downs=%d", high.downsN())
	}
	clock = clock.Add(time.Minute)
	s.ProbeNow(context.Background())
	if high.downsN() != 1 {
		t.Fatalf("downs=%d after interval", high.downsN())
	}
}

func TestSwitchLogHasIDsAndNoSecrets(t *testing.T) {
	t.Parallel()
	opt, buf := testOpts(t)
	high := &fake{id: "high", priority: 100, endpoint: "vpn://SUPERSECRETKEY"}
	low := &fake{id: "low", priority: 10, endpoint: "c2VjcmV0a2V5"}
	s := New([]backend.Backend{high, low}, opt)
	healthy(t, s, 2)
	high.mu.Lock()
	high.failProbe = true
	high.mu.Unlock()
	healthy(t, s, 3)
	text := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("переключение")) || !bytes.Contains(buf.Bytes(), []byte("high")) || !bytes.Contains(buf.Bytes(), []byte("low")) {
		t.Fatalf("log missing switch ids:\n%s", text)
	}
	for _, secret := range []string{"vpn://", "SUPERSECRETKEY", "c2VjcmV0a2V5"} {
		if bytes.Contains(buf.Bytes(), []byte(secret)) {
			t.Fatalf("log contains secret %q:\n%s", secret, text)
		}
	}
}

func TestPreferFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/prefer"
	opt, _ := testOpts(t)
	opt.PreferPath = path
	high := &fake{id: "high", priority: 100}
	low := &fake{id: "low", priority: 10}
	s := New([]backend.Backend{high, low}, opt)
	healthy(t, s, 2)
	if err := writeFile(path, "low\n"); err != nil {
		t.Fatal(err)
	}
	s.ProbeNow(context.Background())
	if s.Snapshot().Current != "low" || s.Snapshot().Preference != "low" {
		t.Fatalf("snapshot=%+v", s.Snapshot())
	}
	if err := writeFile(path, "auto\n"); err != nil {
		t.Fatal(err)
	}
	s.ProbeNow(context.Background())
	if s.Snapshot().Current != "low" {
		t.Fatalf("auto preempted current: %+v", s.Snapshot())
	}
	low.mu.Lock()
	low.failProbe = true
	low.mu.Unlock()
	healthy(t, s, 3)
	if s.Snapshot().Current != "high" {
		t.Fatalf("after prefer auto, failover current=%s", s.Snapshot().Current)
	}
}

func TestEgressIPKeptOnFailure(t *testing.T) {
	t.Parallel()
	var fail bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, "203.0.113.8\n")
	}))
	defer srv.Close()
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer okSrv.Close()
	opt, _ := testOpts(t)
	opt.RecoverThreshold = 1
	opt.CheckURLs = []string{okSrv.URL}
	opt.EgressURL = srv.URL
	pass := &passthrough{id: "only", priority: 1}
	s := New([]backend.Backend{pass}, opt)
	s.ProbeNow(context.Background())
	s.refreshEgress(context.Background())
	if s.Snapshot().EgressIP != "203.0.113.8" {
		t.Fatalf("egress=%q", s.Snapshot().EgressIP)
	}
	fail = true
	s.refreshEgress(context.Background())
	if s.Snapshot().EgressIP != "203.0.113.8" {
		t.Fatalf("egress cleared: %q", s.Snapshot().EgressIP)
	}
}

type passthrough struct {
	id       string
	priority int
}

func (p *passthrough) ID() string                 { return p.id }
func (p *passthrough) Priority() int              { return p.priority }
func (p *passthrough) Up(context.Context) error   { return nil }
func (p *passthrough) Down(context.Context) error { return nil }
func (p *passthrough) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

func TestDefaultCheckURLs(t *testing.T) {
	t.Parallel()
	s := New(nil, Options{})
	want := []string{
		"https://www.gstatic.com/generate_204",
		"https://cp.cloudflare.com/generate_204",
	}
	if len(s.opt.CheckURLs) != len(want) {
		t.Fatalf("urls=%v", s.opt.CheckURLs)
	}
	for i := range want {
		if s.opt.CheckURLs[i] != want[i] {
			t.Fatalf("urls=%v", s.opt.CheckURLs)
		}
	}
}

func TestCheckURLsReplaceTheList(t *testing.T) {
	t.Parallel()
	opt, _ := testOpts(t)
	opt.CheckURLs = []string{"tcp://" + probeAddr}
	s := New(nil, opt)
	if len(s.opt.CheckURLs) != 1 || s.opt.CheckURLs[0] != "tcp://"+probeAddr {
		t.Fatalf("urls=%v", s.opt.CheckURLs)
	}
}

func TestFirst204SkipsTheRest(t *testing.T) {
	t.Parallel()
	firstHits := 0
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstHits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer first.Close()
	secondHits := 0
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondHits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer second.Close()
	opt, _ := testOpts(t)
	opt.CheckURLs = []string{first.URL, second.URL}
	opt.RecoverThreshold = 1
	pass := &passthrough{id: "only", priority: 1}
	s := New([]backend.Backend{pass}, opt)
	s.ProbeNow(context.Background())
	if firstHits != 1 || secondHits != 0 {
		t.Fatalf("first=%d second=%d", firstHits, secondHits)
	}
	if s.Snapshot().Current != "only" {
		t.Fatalf("current=%s", s.Snapshot().Current)
	}
}

func TestNon204IsFailure(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	opt, _ := testOpts(t)
	opt.CheckURLs = []string{srv.URL}
	opt.RecoverThreshold = 1
	opt.FailThreshold = 1
	pass := &passthrough{id: "only", priority: 1}
	s := New([]backend.Backend{pass}, opt)
	s.ProbeNow(context.Background())
	if s.Snapshot().Current != "" {
		t.Fatalf("HTTP 200 marked backend alive: %+v", s.Snapshot())
	}
}

func TestSuccessResetsFailStreak(t *testing.T) {
	t.Parallel()
	opt, _ := testOpts(t)
	high := &fake{id: "high", priority: 100}
	low := &fake{id: "low", priority: 10}
	s := New([]backend.Backend{high, low}, opt)
	healthy(t, s, 2)
	high.mu.Lock()
	high.failProbe = true
	high.mu.Unlock()
	s.ProbeNow(context.Background())
	s.ProbeNow(context.Background())
	high.mu.Lock()
	high.failProbe = false
	high.mu.Unlock()
	s.ProbeNow(context.Background())
	high.mu.Lock()
	high.failProbe = true
	high.mu.Unlock()
	s.ProbeNow(context.Background())
	s.ProbeNow(context.Background())
	if got := s.Snapshot().Current; got != "high" {
		t.Fatalf("streak was not reset, current=%s", got)
	}
	s.ProbeNow(context.Background())
	if got := s.Snapshot().Current; got != "low" {
		t.Fatalf("current=%s", got)
	}
}

func TestPreferSkipsUnhealthy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/prefer"
	opt, _ := testOpts(t)
	opt.PreferPath = path
	high := &fake{id: "high", priority: 100}
	low := &fake{id: "low", priority: 10}
	s := New([]backend.Backend{high, low}, opt)
	healthy(t, s, 2)
	low.mu.Lock()
	low.failProbe = true
	low.mu.Unlock()
	healthy(t, s, 3)
	if err := writeFile(path, "low\n"); err != nil {
		t.Fatal(err)
	}
	s.ProbeNow(context.Background())
	if got := s.Snapshot().Current; got != "high" {
		t.Fatalf("unhealthy prefer became current=%s", got)
	}
	if low.downsN() < 1 {
		t.Fatal("unhealthy standby was not restarted once")
	}
}

func TestDialErrorLogHasNoSecret(t *testing.T) {
	t.Parallel()
	opt, buf := testOpts(t)
	high := &fake{id: "high", priority: 1}
	s := New([]backend.Backend{high}, opt)
	healthy(t, s, 2)
	high.mu.Lock()
	high.failUser = true
	high.mu.Unlock()
	if _, err := s.DialContext(context.Background(), "tcp", "example.com:80"); err == nil {
		t.Fatal("expected dial error")
	}
	if bytes.Contains(buf.Bytes(), []byte("vpn://")) || bytes.Contains(buf.Bytes(), []byte("SUPERSECRETKEY")) {
		t.Fatalf("dial log leaked secret:\n%s", buf.String())
	}
}

func TestDialErrorRequestsOneProbe(t *testing.T) {
	t.Parallel()
	opt, _ := testOpts(t)
	opt.CheckInterval = time.Hour
	opt.RecoverThreshold = 1
	high := &fake{id: "high", priority: 1}
	s := New([]backend.Backend{high}, opt)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Snapshot().Current == "high" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if s.Snapshot().Current != "high" {
		t.Fatal("run did not select high")
	}
	before := high.probeDialsN()
	high.mu.Lock()
	high.failUser = true
	high.mu.Unlock()
	if _, err := s.DialContext(context.Background(), "tcp", "example.com:80"); err == nil {
		t.Fatal("expected dial error")
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if high.probeDialsN() > before {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if high.probeDialsN() <= before {
		t.Fatal("dial error did not request a probe")
	}
	if s.Snapshot().Current != "high" {
		t.Fatalf("dial error switched current to %s", s.Snapshot().Current)
	}
}

func TestProbeDoesNotCloseUserConn(t *testing.T) {
	t.Parallel()
	opt, _ := testOpts(t)
	high := &fake{id: "high", priority: 100}
	low := &fake{id: "low", priority: 10}
	s := New([]backend.Backend{high, low}, opt)
	healthy(t, s, 2)
	c, err := s.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	high.mu.Lock()
	high.failProbe = true
	high.mu.Unlock()
	s.ProbeNow(context.Background())
	s.ProbeNow(context.Background())
	if high.userConns[0].wasClosed() {
		t.Fatal("probe closed the user connection")
	}
	if high.downsN() != 0 {
		t.Fatalf("probe Down'd current, downs=%d", high.downsN())
	}
}

func TestSetBackendsRetargetsCurrent(t *testing.T) {
	t.Parallel()
	opt, _ := testOpts(t)
	opt.RecoverThreshold = 1
	old := &fake{id: "vpn", priority: 100}
	low := &fake{id: "low", priority: 10}
	s := New([]backend.Backend{old, low}, opt)
	s.ProbeNow(context.Background())
	neu := &fake{id: "vpn", priority: 100}
	s.SetBackends([]backend.Backend{neu, low})
	if got := s.Snapshot().Current; got != "vpn" {
		t.Fatalf("current=%s, want the same id", got)
	}
	if _, err := s.DialContext(context.Background(), "tcp", "example.com:80"); err != nil {
		t.Fatal(err)
	}
	if neu.userDialsN() != 1 || old.userDialsN() != 0 {
		t.Fatalf("new dials=%d old dials=%d", neu.userDialsN(), old.userDialsN())
	}
	if old.downsN() != 0 || neu.downsN() != 0 || old.upsN() != 0 || neu.upsN() != 0 {
		t.Fatalf("sticky bounced backends old down/up=%d/%d neu down/up=%d/%d", old.downsN(), old.upsN(), neu.downsN(), neu.upsN())
	}
}

func TestStaleProbeDoesNotTouchReplacement(t *testing.T) {
	t.Parallel()
	opt, _ := testOpts(t)
	opt.RecoverThreshold = 1
	opt.FailThreshold = 1
	old := &fake{id: "vpn", priority: 100}
	low := &fake{id: "low", priority: 10}
	s := New([]backend.Backend{old, low}, opt)
	s.ProbeNow(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	old.mu.Lock()
	old.onProbe = func() error {
		once.Do(func() { close(started) })
		<-release
		return errors.New("stale probe")
	}
	old.mu.Unlock()
	done := make(chan struct{})
	go func() {
		s.ProbeNow(context.Background())
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("probe did not start")
	}
	neu := &fake{id: "vpn", priority: 100}
	s.SetBackends([]backend.Backend{neu, low})
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("probe did not finish")
	}
	if got := s.Snapshot().Current; got != "vpn" {
		t.Fatalf("stale probe moved current to %q", got)
	}
	if old.downsN() != 0 || old.upsN() != 0 {
		t.Fatalf("stale probe restarted removed backend downs=%d ups=%d", old.downsN(), old.upsN())
	}
	if neu.downsN() != 0 || neu.upsN() != 0 {
		t.Fatalf("replacement was restarted downs=%d ups=%d", neu.downsN(), neu.upsN())
	}
	alive := false
	for _, b := range s.Snapshot().Backends {
		if b.ID == "vpn" {
			alive = b.Alive
		}
	}
	if !alive {
		t.Fatal("stale failure marked the replacement unhealthy")
	}
}

func TestNeverAliveRestartsOnceUntilInterval(t *testing.T) {
	t.Parallel()
	clock := time.Unix(1_700_000_000, 0)
	opt, _ := testOpts(t)
	opt.Now = func() time.Time { return clock }
	opt.RestartInterval = time.Minute
	opt.FailThreshold = 3
	b := &fake{id: "b", priority: 1, failProbe: true}
	s := New([]backend.Backend{b}, opt)
	for i := 0; i < 2; i++ {
		s.ProbeNow(context.Background())
	}
	if b.downsN() != 0 {
		t.Fatalf("restart before threshold, downs=%d", b.downsN())
	}
	s.ProbeNow(context.Background())
	if b.downsN() != 1 || b.upsN() != 1 {
		t.Fatalf("downs=%d ups=%d, want one restart at threshold", b.downsN(), b.upsN())
	}
	for i := 0; i < 10; i++ {
		s.ProbeNow(context.Background())
	}
	if b.downsN() != 1 {
		t.Fatalf("restart storm, downs=%d", b.downsN())
	}
	clock = clock.Add(time.Minute)
	s.ProbeNow(context.Background())
	if b.downsN() != 2 {
		t.Fatalf("downs=%d after interval", b.downsN())
	}
}

func TestEgressFailureDoesNotFailProbe(t *testing.T) {
	t.Parallel()
	var fail bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, "203.0.113.9\n")
	}))
	defer srv.Close()
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer okSrv.Close()
	opt, _ := testOpts(t)
	opt.RecoverThreshold = 1
	opt.FailThreshold = 1
	opt.CheckURLs = []string{okSrv.URL}
	opt.EgressURL = srv.URL
	pass := &passthrough{id: "only", priority: 1}
	s := New([]backend.Backend{pass}, opt)
	s.ProbeNow(context.Background())
	s.refreshEgress(context.Background())
	fail = true
	s.refreshEgress(context.Background())
	s.ProbeNow(context.Background())
	if s.Snapshot().Current != "only" || s.Snapshot().EgressIP != "203.0.113.9" {
		t.Fatalf("snapshot=%+v", s.Snapshot())
	}
}

func TestNoHealthyDoesNotDialBackend(t *testing.T) {
	t.Parallel()
	opt, _ := testOpts(t)
	b := &fake{id: "b", priority: 1, failProbe: true}
	s := New([]backend.Backend{b}, opt)
	healthy(t, s, 3)
	_, err := s.DialContext(context.Background(), "tcp", "example.com:80")
	if !errors.Is(err, dialer.ErrNoHealthyBackend) {
		t.Fatalf("err=%v", err)
	}
	if b.userDialsN() != 0 {
		t.Fatalf("unhealthy balancer dialed the backend %d times", b.userDialsN())
	}
}

func TestInitialSwitchReasonIsStart(t *testing.T) {
	t.Parallel()
	opt, buf := testOpts(t)
	b := &fake{id: "only", priority: 1}
	s := New([]backend.Backend{b}, opt)
	healthy(t, s, 2)
	if !bytes.Contains(buf.Bytes(), []byte("reason=start")) {
		t.Fatalf("log:\n%s", buf.String())
	}
}

func TestConcurrentDialAndProbe(t *testing.T) {
	t.Parallel()
	opt, _ := testOpts(t)
	opt.Logger = slog.New(slog.DiscardHandler)
	high := &fake{id: "high", priority: 100}
	low := &fake{id: "low", priority: 10}
	s := New([]backend.Backend{high, low}, opt)
	healthy(t, s, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				c, err := s.DialContext(ctx, "tcp", "example.com:80")
				if err != nil {
					continue
				}
				_ = c.Close()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 20; j++ {
			high.mu.Lock()
			high.failProbe = j%4 == 0
			high.mu.Unlock()
			s.ProbeNow(ctx)
		}
	}()
	wg.Wait()
}
