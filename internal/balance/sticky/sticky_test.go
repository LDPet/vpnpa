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

	mu        sync.Mutex
	failProbe bool
	failUser  bool
	downs     int
	ups       int
	userDials int
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
	defer f.mu.Unlock()
	if address == probeAddr {
		if f.failProbe {
			return nil, errors.New("probe failed")
		}
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}
	if f.failUser {
		return nil, errors.New("user dial failed")
	}
	f.userDials++
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
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
