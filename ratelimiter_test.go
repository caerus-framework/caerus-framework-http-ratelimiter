package cf_http_ratelimiter

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cf "github.com/caerus-framework/caerus-framework"
	cf_observability "github.com/caerus-framework/caerus-framework-observability"
	cf_valkey "github.com/caerus-framework/caerus-framework-valkey"
)

func TestComponentContract(t *testing.T) {
	r := New()
	if r.Name() != ComponentName {
		t.Fatalf("Name() = %q, want %q", r.Name(), ComponentName)
	}
	if r.GetInitOrderStage() != ComponentStage {
		t.Fatalf("GetInitOrderStage() = %q, want %q", r.GetInitOrderStage(), ComponentStage)
	}
	var _ cf.CaerusComponent = r
	if err := r.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown before Init: %v", err)
	}
}

func TestHealthAndMetricsBeforeInit(t *testing.T) {
	r := New()
	if err := r.Health(context.Background()); err == nil {
		t.Fatal("Health before Init should fail")
	}
	if ms := r.Metrics(); ms != nil {
		t.Fatalf("Metrics before Init = %+v, want nil", ms)
	}
	var _ cf.HealthProvider = r
	var _ cf_observability.MetricsProvider = r
}

func TestNewDefaults(t *testing.T) {
	r := New()
	if r.keyPrefix != defaultKeyPrefix {
		t.Fatalf("keyPrefix = %q, want %q", r.keyPrefix, defaultKeyPrefix)
	}
	if r.maxKeyLength != defaultMaxKeyLength {
		t.Fatalf("maxKeyLength = %d, want %d", r.maxKeyLength, defaultMaxKeyLength)
	}
	if r.memoryMaxEntries != defaultMemoryMaxEntries {
		t.Fatalf("memoryMaxEntries = %d, want %d", r.memoryMaxEntries, defaultMemoryMaxEntries)
	}
	if r.waitJitterMax != defaultWaitJitterMax {
		t.Fatalf("waitJitterMax = %v, want %v", r.waitJitterMax, defaultWaitJitterMax)
	}
	if !r.metricsEnabled {
		t.Fatal("metricsEnabled should default to true")
	}
	if r.memoryBackend {
		t.Fatal("memoryBackend should default to false (valkey is the default backend)")
	}
	if r.HashIPKeys() {
		t.Fatal("HashIPKeys should default to false")
	}
}

func TestNewWithName(t *testing.T) {
	r := New(WithName("sessions"))
	if r.Name() != "sessions" {
		t.Fatalf("Name() = %q, want sessions", r.Name())
	}
}

func TestWithConfigOverridesOptions(t *testing.T) {
	on := true
	r := New(
		WithKeyPrefix("app"),
		WithMaxKeyLength(100),
		WithMemoryMaxEntries(50),
		WithConfig(Config{
			KeyPrefix:           "cfg",
			MaxKeyLength:        200,
			MemoryMaxEntries:    80,
			MetricsEnabled:      &on,
			MemoryMapFullPolicy: "deny",
			WaitJitterMaxSec:    ptrFloat(0),
		}),
	)
	if r.keyPrefix != "cfg" {
		t.Fatalf("keyPrefix = %q, want cfg", r.keyPrefix)
	}
	if r.maxKeyLength != 200 {
		t.Fatalf("maxKeyLength = %d, want 200", r.maxKeyLength)
	}
	if r.memoryMaxEntries != 80 {
		t.Fatalf("memoryMaxEntries = %d, want 80", r.memoryMaxEntries)
	}
	if !r.metricsEnabled {
		t.Fatal("metricsEnabled should be true from config")
	}
	if r.mapFullPolicy != MapFullDeny {
		t.Fatalf("mapFullPolicy = %v, want MapFullDeny", r.mapFullPolicy)
	}
	if r.waitJitterMax != 0 {
		t.Fatalf("waitJitterMax = %v, want 0", r.waitJitterMax)
	}
}

func TestWithConfigTrimsKeyPrefixColon(t *testing.T) {
	r := New(WithKeyPrefix("rl:"))
	if r.keyPrefix != "rl" {
		t.Fatalf("keyPrefix = %q, want rl", r.keyPrefix)
	}
}

func TestGetDependencies(t *testing.T) {
	r := New()
	deps := r.GetDependencies()
	if len(deps) != 2 {
		t.Fatalf("GetDependencies() = %v, want [valkey logs]", deps)
	}
	if deps[0] != cf_valkey.ComponentName || deps[1] != "logs" {
		t.Fatalf("GetDependencies() = %v, want [valkey logs]", deps)
	}
	var _ cf.Dependencies = r

	named := New(WithValkeyName("cache"))
	deps = named.GetDependencies()
	if len(deps) != 2 || deps[0] != "cache" {
		t.Fatalf("GetDependencies() with named peer = %v, want [cache logs]", deps)
	}

	withSrc := New(WithConfigSource("http-ratelimiter", "config/http-ratelimiter.json"))
	deps = withSrc.GetDependencies()
	if len(deps) != 3 || deps[2] != "configuration" {
		t.Fatalf("GetDependencies() with source = %v, want [valkey logs configuration]", deps)
	}

	mem := New(WithMemoryBackend())
	deps = mem.GetDependencies()
	if len(deps) != 1 || deps[0] != "logs" {
		t.Fatalf("memory-backend GetDependencies() = %v, want [logs]", deps)
	}
}

func TestInitRequiresValkey(t *testing.T) {
	r := New()
	err := r.Init(context.Background(), cf.New())
	if err == nil {
		t.Fatal("Init without a valkey component should fail")
	}
	if !strings.Contains(err.Error(), `valkey component "valkey" is not registered`) {
		t.Fatalf("Init error = %v, want a valkey-not-registered error", err)
	}
}

func TestInitWithNamedValkeyMissing(t *testing.T) {
	r := New(WithValkeyName("cache"))
	err := r.Init(context.Background(), cf.New())
	if err == nil {
		t.Fatal("Init with a missing named valkey should fail")
	}
	if !strings.Contains(err.Error(), `valkey component "cache" is not registered`) {
		t.Fatalf("Init error = %v, want a cache-not-registered error", err)
	}
}

func TestInitRequiresValkeyInitialized(t *testing.T) {
	fw := cf.New()
	if err := fw.AddComponent(cf_valkey.New()); err != nil {
		t.Fatalf("AddComponent: %v", err)
	}
	r := New()
	err := r.Init(context.Background(), fw)
	if err == nil {
		t.Fatal("Init against an uninitialized valkey should fail")
	}
	if !strings.Contains(err.Error(), "is not initialized") {
		t.Fatalf("Init error = %v, want a valkey-not-initialized error", err)
	}
}

func TestInitMemoryBackendSucceedsWithoutValkey(t *testing.T) {
	r := New(WithMemoryBackend())
	if err := r.Init(context.Background(), cf.New()); err != nil {
		t.Fatalf("memory-backend Init: %v", err)
	}
	if err := r.Health(context.Background()); err != nil {
		t.Fatalf("Health after memory Init: %v", err)
	}
	if ms := r.Metrics(); ms == nil {
		t.Fatal("Metrics after memory Init should be non-nil")
	}
	if err := r.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := r.Health(context.Background()); err == nil {
		t.Fatal("Health after Shutdown should fail")
	}
	if ms := r.Metrics(); ms != nil {
		t.Fatalf("Metrics after Shutdown = %+v, want nil", ms)
	}
}

func TestMetricsDisabledReturnsNil(t *testing.T) {
	r := New(WithMemoryBackend(), WithMetricsEnabled(false))
	if err := r.Init(context.Background(), cf.New()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if ms := r.Metrics(); ms != nil {
		t.Fatalf("Metrics with metrics_enabled=false = %+v, want nil", ms)
	}
}

func newMemoryRL(t *testing.T, opts ...Option) *RateLimiter {
	t.Helper()
	all := append([]Option{WithMemoryBackend()}, opts...)
	r := New(all...)
	if err := r.Init(context.Background(), cf.New()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = r.Shutdown(context.Background()) })
	return r
}

func TestAllowCountsAndDenies(t *testing.T) {
	r := newMemoryRL(t)
	ctx := context.Background()
	for i := int64(1); i <= 3; i++ {
		res, err := r.Allow(ctx, "login:alice", 3, time.Minute)
		if err != nil {
			t.Fatalf("Allow: %v", err)
		}
		if !res.Allowed || res.Count != i {
			t.Fatalf("call %d = %+v, want allowed count %d", i, res, i)
		}
	}
	res, err := r.Allow(ctx, "login:alice", 3, time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if res.Allowed {
		t.Fatal("4th call should be denied")
	}
	if res.ResetIn <= 0 {
		t.Fatalf("ResetIn = %v, want > 0", res.ResetIn)
	}
}

func TestAllowReset(t *testing.T) {
	r := newMemoryRL(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := r.Allow(ctx, "login:bob", 5, time.Minute); err != nil {
			t.Fatalf("Allow: %v", err)
		}
	}
	res, _ := r.Allow(ctx, "login:bob", 5, time.Minute)
	if res.Allowed {
		t.Fatal("6th call should be denied")
	}
	if err := r.Reset(ctx, "login:bob"); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	res, err := r.Allow(ctx, "login:bob", 5, time.Minute)
	if err != nil {
		t.Fatalf("Allow after Reset: %v", err)
	}
	if !res.Allowed || res.Count != 1 {
		t.Fatalf("after Reset = %+v, want allowed count 1", res)
	}
}

func TestAllowLimitZeroShortCircuits(t *testing.T) {
	r := newMemoryRL(t)
	ctx := context.Background()
	res, err := r.Allow(ctx, "login:carol", 0, time.Minute)
	if err != nil {
		t.Fatalf("Allow with limit 0: %v", err)
	}
	if !res.Allowed || res.Count != 0 {
		t.Fatalf("Allow with limit 0 = %+v, want allowed, uncounted", res)
	}
	if r.memory.Len() != 0 {
		t.Fatalf("limit<=0 must not touch the map, len = %d", r.memory.Len())
	}
	// Only disabled_total rises — no allows, no denies.
	var disabled, allows float64
	for _, m := range r.Metrics() {
		switch m.Name {
		case "http_ratelimiter_disabled_total":
			disabled = m.Value
		case "http_ratelimiter_allows_total":
			allows = m.Value
		}
	}
	if disabled != 1 {
		t.Fatalf("disabled_total = %v, want 1", disabled)
	}
	if allows != 0 {
		t.Fatalf("allows_total = %v, want 0 (disabled is not an allow)", allows)
	}

	res, err = r.AllowWithPolicy(ctx, "login:carol", 0, time.Minute, StorageFailClosed)
	if err != nil {
		t.Fatalf("AllowWithPolicy with limit 0: %v", err)
	}
	if !res.Allowed {
		t.Fatal("AllowWithPolicy with limit 0 should allow")
	}
}

func TestAllowEmptyKeyRejected(t *testing.T) {
	r := newMemoryRL(t)
	_, err := r.Allow(context.Background(), "", 5, time.Minute)
	if err == nil {
		t.Fatal("empty key should error")
	}
	if r.rejectedEmpty.Load() != 1 {
		t.Fatalf("rejectedEmpty = %d, want 1", r.rejectedEmpty.Load())
	}
	if err := r.Reset(context.Background(), ""); err == nil {
		t.Fatal("Reset with empty key should error")
	}
	if _, err := r.Peek(context.Background(), ""); err == nil {
		t.Fatal("Peek with empty key should error")
	}
}

func TestAllowKeyTooLongRejected(t *testing.T) {
	r := newMemoryRL(t, WithMaxKeyLength(16))
	long := strings.Repeat("a", 17)
	_, err := r.Allow(context.Background(), long, 5, time.Minute)
	if err == nil {
		t.Fatal("oversized key should error, not truncate")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Fatalf("error = %v, want too-long message", err)
	}
	if r.rejectedLong.Load() != 1 {
		t.Fatalf("rejectedLong = %d, want 1", r.rejectedLong.Load())
	}
}

func TestPeekDoesNotIncrement(t *testing.T) {
	r := newMemoryRL(t)
	ctx := context.Background()
	if _, err := r.Allow(ctx, "k", 5, time.Minute); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	res, err := r.Peek(ctx, "k")
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if res.Count != 1 {
		t.Fatalf("Peek count = %d, want 1 (no increment)", res.Count)
	}
	if res.Allowed {
		t.Fatal("Peek.Allowed should always be false (no limit to compare against)")
	}
	// Allow again: count must be 2, not 3.
	res, err = r.Allow(ctx, "k", 5, time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if res.Count != 2 {
		t.Fatalf("count after Allow = %d, want 2", res.Count)
	}
}

func TestWaitGrantsOnce(t *testing.T) {
	r := newMemoryRL(t, WithWaitJitterMax(0))
	ctx := context.Background()
	// Fill the window: limit 1, one slot taken.
	if _, err := r.Allow(ctx, "forge:rest:42", 1, 120*time.Millisecond); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	start := time.Now()
	if err := r.Wait(ctx, "forge:rest:42", 1, 120*time.Millisecond); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 100*time.Millisecond {
		t.Fatalf("Wait returned too fast (%v); it should have slept ~the window", elapsed)
	}
	// After the grant, the counter is at 1 (the slot we consumed), not 2+.
	res, _ := r.Peek(ctx, "forge:rest:42")
	if res.Count != 1 {
		t.Fatalf("count after Wait = %d, want 1 (exactly one grant)", res.Count)
	}
}

func TestWaitDoesNotSpinIncrement(t *testing.T) {
	r := newMemoryRL(t, WithWaitJitterMax(0))
	ctx := context.Background()
	if _, err := r.Allow(ctx, "k", 1, 80*time.Millisecond); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	// A spinning Allow loop would push the counter far past 2 during the wait.
	if err := r.Wait(ctx, "k", 1, 80*time.Millisecond); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	res, _ := r.Peek(ctx, "k")
	if res.Count > 2 {
		t.Fatalf("count after Wait = %d; Wait must not spin-increment (1 fill + 1 grant expected)", res.Count)
	}
}

func TestWaitContextCanceled(t *testing.T) {
	r := newMemoryRL(t, WithWaitJitterMax(0))
	if _, err := r.Allow(context.Background(), "k", 1, time.Hour); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := r.Wait(ctx, "k", 1, time.Hour)
	if err == nil {
		t.Fatal("Wait should fail when ctx is done")
	}
	if r.waitsCanceled.Load() != 1 {
		t.Fatalf("waitsCanceled = %d, want 1", r.waitsCanceled.Load())
	}
}

func TestWaitLimitZeroReturnsImmediately(t *testing.T) {
	r := newMemoryRL(t)
	if err := r.Wait(context.Background(), "k", 0, time.Minute); err != nil {
		t.Fatalf("Wait with limit 0: %v", err)
	}
	if r.disabled.Load() != 1 {
		t.Fatalf("disabled = %d, want 1", r.disabled.Load())
	}
}

func TestWaitDelayFuncAborts(t *testing.T) {
	r := newMemoryRL(t)
	if _, err := r.Allow(context.Background(), "k", 1, time.Hour); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	applied := &atomic.Bool{}
	abortErr := context.DeadlineExceeded
	r.waitDelayFunc = func(ctx context.Context, key string, base, jittered time.Duration) (time.Duration, error) {
		applied.Store(true)
		if key != "k" {
			t.Errorf("waitDelayFunc key = %q, want k", key)
		}
		return 0, abortErr
	}
	err := r.Wait(context.Background(), "k", 1, time.Hour)
	if err != abortErr {
		t.Fatalf("Wait error = %v, want the callback error", err)
	}
	if !applied.Load() {
		t.Fatal("WaitDelayFunc should have been called")
	}
	if r.waitsErr.Load() != 1 {
		t.Fatalf("waitsErr = %d, want 1", r.waitsErr.Load())
	}
}

func TestWaitDelayFuncChoosesSleep(t *testing.T) {
	r := newMemoryRL(t, WithWaitJitterMax(time.Second))
	if _, err := r.Allow(context.Background(), "k", 1, 200*time.Millisecond); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	var baseGot, jitteredGot time.Duration
	r.waitDelayFunc = func(ctx context.Context, key string, base, jittered time.Duration) (time.Duration, error) {
		baseGot, jitteredGot = base, jittered
		return jittered, nil
	}
	start := time.Now()
	if err := r.Wait(context.Background(), "k", 1, 200*time.Millisecond); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if baseGot <= 0 || baseGot > 200*time.Millisecond {
		t.Fatalf("base = %v, want within (0, window]", baseGot)
	}
	if jitteredGot < baseGot {
		t.Fatalf("jittered = %v < base %v (jitter adds, never subtracts)", jitteredGot, baseGot)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("Wait returned too fast (%v)", elapsed)
	}
}

func TestAllowWithPolicyFailOpenOnStoreError(t *testing.T) {
	// A valkey-backend limiter that was never Init'd produces store errors.
	r := New()
	res, err := r.AllowWithPolicy(context.Background(), "k", 5, time.Minute, StorageFailOpen)
	if err != nil {
		t.Fatalf("FailOpen should swallow the store error, got %v", err)
	}
	if !res.Allowed {
		t.Fatal("FailOpen should report Allowed=true")
	}
	if r.fbOpen.Load() != 1 {
		t.Fatalf("fbOpen = %d, want 1", r.fbOpen.Load())
	}
	if r.storageErrors.Load() != 1 {
		t.Fatalf("storageErrors = %d, want 1", r.storageErrors.Load())
	}
}

func TestAllowWithPolicyFailClosedOnStoreError(t *testing.T) {
	r := New()
	_, err := r.AllowWithPolicy(context.Background(), "k", 5, time.Minute, StorageFailClosed)
	if err == nil {
		t.Fatal("FailClosed should return the store error")
	}
	if r.fbClosed.Load() != 1 {
		t.Fatalf("fbClosed = %d, want 1", r.fbClosed.Load())
	}
}

func TestAllowWithPolicyMemoryFallbackOnStoreError(t *testing.T) {
	r := New(WithMemoryMaxEntries(100))
	res, err := r.AllowWithPolicy(context.Background(), "k", 2, time.Minute, StorageMemoryFallback)
	if err != nil {
		t.Fatalf("MemoryFallback should not error: %v", err)
	}
	if !res.Allowed || res.Count != 1 {
		t.Fatalf("fallback result = %+v, want allowed count 1", res)
	}
	if r.fbMemory.Load() != 1 {
		t.Fatalf("fbMemory = %d, want 1", r.fbMemory.Load())
	}
	// Second call takes the fallback limit to 2; third is denied.
	if _, err := r.AllowWithPolicy(context.Background(), "k", 2, time.Minute, StorageMemoryFallback); err != nil {
		t.Fatalf("AllowWithPolicy: %v", err)
	}
	res, err = r.AllowWithPolicy(context.Background(), "k", 2, time.Minute, StorageMemoryFallback)
	if err != nil {
		t.Fatalf("AllowWithPolicy: %v", err)
	}
	if res.Allowed {
		t.Fatal("3rd fallback call should be denied")
	}
}

func TestOnConfigReloadAppliesTunables(t *testing.T) {
	r := New(WithMemoryBackend(), WithConfigSource("http-ratelimiter", "config/http-ratelimiter.json"))
	r.initialized.Store(true)
	on := true
	r.OnConfigReload("http-ratelimiter", &Config{
		KeyPrefix:           "cfg",
		MaxKeyLength:        128,
		MemoryMaxEntries:    42,
		MemoryMapFullPolicy: "deny",
		MetricsEnabled:      &on,
		WaitJitterMaxSec:    ptrFloat(2),
	})
	if r.keyPrefix != "cfg" {
		t.Fatalf("keyPrefix = %q, want cfg", r.keyPrefix)
	}
	if r.maxKeyLength != 128 {
		t.Fatalf("maxKeyLength = %d, want 128", r.maxKeyLength)
	}
	if r.memoryMaxEntries != 42 {
		t.Fatalf("memoryMaxEntries = %d, want 42", r.memoryMaxEntries)
	}
	if r.mapFullPolicy != MapFullDeny {
		t.Fatalf("mapFullPolicy = %v, want MapFullDeny", r.mapFullPolicy)
	}
	if r.waitJitterMax != 2*time.Second {
		t.Fatalf("waitJitterMax = %v, want 2s", r.waitJitterMax)
	}
	if r.reloads.Load() != 1 {
		t.Fatalf("reloads = %d, want 1", r.reloads.Load())
	}

	// A reload for a different source is ignored.
	r.OnConfigReload("other", &Config{KeyPrefix: "x"})
	if r.keyPrefix != "cfg" {
		t.Fatalf("foreign-source reload changed keyPrefix to %q", r.keyPrefix)
	}
}

func TestUnknownMapFullPolicyDefaultsAllow(t *testing.T) {
	r := New()
	r.applyConfig(Config{MemoryMapFullPolicy: "banana"})
	if r.mapFullPolicy != MapFullAllow {
		t.Fatalf("mapFullPolicy = %v, want MapFullAllow for unknown value", r.mapFullPolicy)
	}
}

func TestKeyHelper(t *testing.T) {
	r := New()
	if k := r.Key("login:abc"); k != "rl:login:abc" {
		t.Fatalf("Key = %q, want rl:login:abc", k)
	}
	empty := New(WithKeyPrefix(""))
	if k := empty.Key("login:abc"); k != "login:abc" {
		t.Fatalf("Key without prefix = %q, want login:abc", k)
	}
}

func TestMetricsCatalogue(t *testing.T) {
	r := newMemoryRL(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := r.Allow(ctx, "m", 3, time.Minute); err != nil {
			t.Fatalf("Allow: %v", err)
		}
	}
	if _, err := r.Allow(ctx, "m", 3, time.Minute); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	_, _ = r.Peek(ctx, "m")
	_ = r.Reset(ctx, "other")
	_, _ = r.Allow(ctx, "", 3, time.Minute)
	_, _ = r.Allow(ctx, strings.Repeat("x", 300), 3, time.Minute)
	_, _ = r.Allow(ctx, "off", 0, time.Minute)

	want := map[string]float64{
		"http_ratelimiter_allows_total":         3,
		"http_ratelimiter_denies_total":         1,
		"http_ratelimiter_resets_total":         1,
		"http_ratelimiter_peeks_total":          1,
		"http_ratelimiter_disabled_total":       1,
		"http_ratelimiter_memory_entries":       1,
		"http_ratelimiter_info":                 1,
		"http_ratelimiter_config_reloads_total": 0,
	}
	got := map[string]float64{}
	for _, m := range r.Metrics() {
		key := m.Name
		if m.Name == "http_ratelimiter_key_rejected_total" {
			if m.Labels["reason"] == "empty" {
				key = "http_ratelimiter_key_rejected_empty"
			}
		}
		got[key] += m.Value
	}
	for name, exp := range want {
		if got[name] != exp {
			t.Fatalf("metric %s = %v, want %v (got %v)", name, got[name], exp, got)
		}
	}
	if got["http_ratelimiter_key_rejected_total"] != 0 && got["http_ratelimiter_key_rejected_empty"] != 1 {
		t.Fatalf("key rejected metrics = %v", got)
	}
	var memEntries int
	for _, m := range r.Metrics() {
		if m.Name == "http_ratelimiter_memory_entries" {
			memEntries = int(m.Value)
		}
	}
	if memEntries != 1 {
		t.Fatalf("memory_entries = %d, want 1", memEntries)
	}
}

func ptrFloat(f float64) *float64 { return &f }
