package cf_http_ratelimiter

import (
	"context"
	"strings"
	"testing"
	"time"

	cf "github.com/caerus-framework/caerus-framework"
	cf_observability "github.com/caerus-framework/caerus-framework-observability"
	cf_valkey_state "github.com/caerus-framework/caerus-framework-valkey-state"
)

func TestComponentContract(t *testing.T) {
	r := New()
	if r.Name() != ComponentName {
		t.Fatalf("Name() = %q", r.Name())
	}
	if r.GetInitOrderStage() != ComponentStage {
		t.Fatalf("stage = %q", r.GetInitOrderStage())
	}
	var _ cf.CaerusComponent = r
	if err := r.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHealthAndMetricsBeforeInit(t *testing.T) {
	r := New()
	if err := r.Health(context.Background()); err == nil {
		t.Fatal("Health before Init should fail")
	}
	if ms := r.Metrics(); ms != nil {
		t.Fatalf("Metrics before Init = %+v", ms)
	}
	var _ cf.HealthProvider = r
	var _ cf_observability.MetricsProvider = r
}

func TestGetDependencies(t *testing.T) {
	r := New()
	deps := r.GetDependencies()
	if len(deps) != 2 || deps[0] != cf_valkey_state.ComponentName || deps[1] != "logs" {
		t.Fatalf("GetDependencies() = %v, want [valkey-state logs]", deps)
	}
	named := New(WithStateName("sessions"))
	deps = named.GetDependencies()
	if deps[0] != "sessions" {
		t.Fatalf("named = %v", deps)
	}
}

func TestInitRequiresState(t *testing.T) {
	r := New()
	err := r.Init(context.Background(), cf.New())
	if err == nil || !strings.Contains(err.Error(), "valkey-state") {
		t.Fatalf("Init error = %v, want valkey-state missing", err)
	}
}

func TestAllowMemoryViaState(t *testing.T) {
	st := memoryState(t)
	r := New(WithWaitJitterMax(0))
	initLimiter(t, r, st)
	if err := r.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	a, err := r.Allow(ctx, "k", 2, time.Minute)
	if err != nil || !a.Allowed || a.Count != 1 {
		t.Fatalf("first Allow = %+v err=%v", a, err)
	}
	b, err := r.Allow(ctx, "k", 2, time.Minute)
	if err != nil || !b.Allowed {
		t.Fatalf("second = %+v err=%v", b, err)
	}
	c, err := r.Allow(ctx, "k", 2, time.Minute)
	if err != nil || c.Allowed {
		t.Fatalf("third should deny: %+v err=%v", c, err)
	}
	if err := r.Reset(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	d, err := r.Allow(ctx, "k", 2, time.Minute)
	if err != nil || !d.Allowed || d.Count != 1 {
		t.Fatalf("after reset = %+v err=%v", d, err)
	}
}

func TestAllowRejectsBadWindow(t *testing.T) {
	st := memoryState(t)
	r := New()
	initLimiter(t, r, st)
	if _, err := r.Allow(context.Background(), "k", 1, 0); err == nil {
		t.Fatal("window 0 should error")
	}
}

func TestAllowEmptyKey(t *testing.T) {
	st := memoryState(t)
	r := New()
	initLimiter(t, r, st)
	if _, err := r.Allow(context.Background(), "", 1, time.Minute); err == nil {
		t.Fatal("empty key should error")
	}
}

func TestStorageMemoryFallbackRejected(t *testing.T) {
	st := memoryState(t)
	r := New()
	initLimiter(t, r, st)
	_, err := r.AllowWithPolicy(context.Background(), "k", 1, time.Minute, StorageMemoryFallback)
	if err != ErrMemoryFallbackDisabled {
		t.Fatalf("err = %v", err)
	}
}

func TestFailOpen(t *testing.T) {
	st := cf_valkey_state.New() // requires valkey, no client
	r := New()
	fw := cf.New()
	_ = fw.AddComponent(st)
	_ = fw.AddComponent(r)
	// state Init fails without valkey — use memory state instead and
	// FailClosed/Open only when state errors. Empty-key already tested.
	st = memoryState(t)
	r = New()
	initLimiter(t, r, st)
	res, err := r.AllowWithPolicy(context.Background(), "k", 1, time.Minute, StorageFailOpen)
	if err != nil || !res.Allowed {
		t.Fatalf("fail-open happy path = %+v %v", res, err)
	}
}

func TestLimitZeroDisables(t *testing.T) {
	st := memoryState(t)
	r := New()
	initLimiter(t, r, st)
	res, err := r.Allow(context.Background(), "k", 0, time.Minute)
	if err != nil || !res.Allowed {
		t.Fatalf("disabled = %+v %v", res, err)
	}
}
