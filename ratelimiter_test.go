package cf_http_ratelimiter

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cf "github.com/caerus-framework/caerus-framework"
	cf_configuration "github.com/caerus-framework/caerus-framework-configuration"
	cf_logs "github.com/caerus-framework/caerus-framework-logs"
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
	if !r.requireValkey {
		t.Fatal("requireValkey should default to true")
	}
	if r.useMemoryFallback || r.forceMemory {
		t.Fatal("use_memory_fallback/force_memory should default to false")
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
	inmem := true
	r := New(
		WithKeyPrefix("app"),
		WithMaxKeyLength(100),
		WithMemoryMaxEntries(50),
		WithConfig(Config{
			KeyPrefix:            "cfg",
			MaxKeyLength:         200,
			MemoryMaxEntries:     80,
			MetricsEnabled:       &on,
			UseMemoryFallback:    &inmem,
			MemoryMapFullPolicy:  "deny",
			WaitMissingTTLPolicy: "proceed",
			WaitJitterMaxSec:     ptrFloat(0),
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
	if !r.useMemoryFallback {
		t.Fatal("useMemoryFallback should be true from config")
	}
	if r.mapFullPolicy != MapFullDeny || !r.mapFullPolicySet {
		t.Fatalf("mapFullPolicy = %v set=%v, want MapFullDeny set", r.mapFullPolicy, r.mapFullPolicySet)
	}
	if r.waitMissingTTLPolicy != MissingTTLProceed || !r.waitMissingTTLPolicyOK {
		t.Fatalf("waitMissingTTLPolicy = %v ok=%v", r.waitMissingTTLPolicy, r.waitMissingTTLPolicyOK)
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

	mem := New(WithoutValkeyPeer(), WithUseMemoryFallback(true))
	deps = mem.GetDependencies()
	if len(deps) != 1 || deps[0] != "logs" {
		t.Fatalf("WithoutValkeyPeer GetDependencies() = %v, want [logs]", deps)
	}
}

func TestInitRequiresWaitMissingTTLPolicy(t *testing.T) {
	r := New()
	err := r.Init(context.Background(), cf.New())
	if err == nil {
		t.Fatal("Init without wait_missing_ttl_policy should fail")
	}
	if !strings.Contains(err.Error(), "wait_missing_ttl_policy") {
		t.Fatalf("Init error = %v, want wait_missing_ttl_policy", err)
	}
}

func TestInitRequiresValkey(t *testing.T) {
	r := New(WithWaitMissingTTLPolicy("proceed"))
	err := r.Init(context.Background(), cf.New())
	if err == nil {
		t.Fatal("Init without a valkey component should fail")
	}
	if !strings.Contains(err.Error(), `valkey component "valkey" is not registered`) {
		t.Fatalf("Init error = %v, want a valkey-not-registered error", err)
	}
}

func TestInitWithNamedValkeyMissing(t *testing.T) {
	r := New(WithValkeyName("cache"), WithWaitMissingTTLPolicy("error"))
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
	r := New(WithWaitMissingTTLPolicy("proceed"))
	err := r.Init(context.Background(), fw)
	if err == nil {
		t.Fatal("Init against an uninitialized valkey should fail")
	}
	if !strings.Contains(err.Error(), "is not initialized") {
		t.Fatalf("Init error = %v, want a valkey-not-initialized error", err)
	}
}

func TestInitMemoryOnlySucceedsWithoutValkey(t *testing.T) {
	r := New(memoryOnlyOpts()...)
	if err := r.Init(context.Background(), cf.New()); err != nil {
		t.Fatalf("memory-only Init: %v", err)
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

func TestInitWithoutValkeyRequiresUseMemoryFallback(t *testing.T) {
	r := New(WithoutValkeyPeer(), WithWaitMissingTTLPolicy("proceed"))
	err := r.Init(context.Background(), cf.New())
	if err == nil {
		t.Fatal("WithoutValkeyPeer without use_memory_fallback should fail Init")
	}
	if !strings.Contains(err.Error(), "use_memory_fallback") {
		t.Fatalf("Init error = %v, want use_memory_fallback mention", err)
	}
}

func TestInitUseMemoryFallbackRequiresMapFullPolicy(t *testing.T) {
	r := New(WithoutValkeyPeer(), WithUseMemoryFallback(true), WithWaitMissingTTLPolicy("proceed"))
	err := r.Init(context.Background(), cf.New())
	if err == nil {
		t.Fatal("use_memory_fallback without memory_map_full_policy should fail Init")
	}
	if !strings.Contains(err.Error(), "memory_map_full_policy") {
		t.Fatalf("Init error = %v, want memory_map_full_policy", err)
	}
}

func TestMetricsDisabledReturnsNil(t *testing.T) {
	r := New(append(memoryOnlyOpts(), WithMetricsEnabled(false))...)
	if err := r.Init(context.Background(), cf.New()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if ms := r.Metrics(); ms != nil {
		t.Fatalf("Metrics with metrics_enabled=false = %+v, want nil", ms)
	}
}

func memoryOnlyOpts() []Option {
	return []Option{
		WithoutValkeyPeer(),
		WithUseMemoryFallback(true),
		WithMemoryMapFullPolicy("allow"),
		WithWaitMissingTTLPolicy("proceed"),
	}
}

func testFW(t *testing.T) *cf.CaerusFramework {
	t.Helper()
	fw := cf.New()
	if err := fw.AddComponent(cf_logs.New(cf_logs.WithWriter(io.Discard))); err != nil {
		t.Fatalf("AddComponent logs: %v", err)
	}
	return fw
}

func newMemoryRL(t *testing.T, opts ...Option) *RateLimiter {
	t.Helper()
	all := append(memoryOnlyOpts(), opts...)
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
	r := New(WithMemoryMaxEntries(100), WithUseMemoryFallback(true), WithMemoryMapFullPolicy("allow"))
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

func TestAllowWithPolicyMemoryFallbackRequiresUseMemoryFallback(t *testing.T) {
	r := New()
	_, err := r.AllowWithPolicy(context.Background(), "k", 2, time.Minute, StorageMemoryFallback)
	if !errors.Is(err, ErrMemoryFallbackDisabled) {
		t.Fatalf("error = %v, want ErrMemoryFallbackDisabled", err)
	}
}

func TestAllowWithPolicyOptsMemoryOverride(t *testing.T) {
	r := New(WithMemoryMaxEntries(100), WithUseMemoryFallback(true), WithMemoryMapFullPolicy("allow"))
	// Coarser fallback limit of 1: second call denied.
	res, err := r.AllowWithPolicyOpts(context.Background(), "k", 10, time.Minute, StorageMemoryFallback, MemoryFallbackConfig{
		Limit: 1,
	})
	if err != nil {
		t.Fatalf("AllowWithPolicyOpts: %v", err)
	}
	if !res.Allowed {
		t.Fatal("first call should allow")
	}
	res, err = r.AllowWithPolicyOpts(context.Background(), "k", 10, time.Minute, StorageMemoryFallback, MemoryFallbackConfig{
		Limit: 1,
	})
	if err != nil {
		t.Fatalf("AllowWithPolicyOpts: %v", err)
	}
	if res.Allowed {
		t.Fatal("second call should deny under override Limit=1")
	}
}

func TestOnConfigReloadAppliesTunables(t *testing.T) {
	r := New(append(memoryOnlyOpts(), WithConfigSource("http-ratelimiter", "config/http-ratelimiter.json"))...)
	r.initialized.Store(true)
	on := true
	inmem := true
	r.OnConfigReload("http-ratelimiter", &Config{
		KeyPrefix:            "cfg",
		MaxKeyLength:         128,
		MemoryMaxEntries:     42,
		UseMemoryFallback:    &inmem,
		MemoryMapFullPolicy:  "deny",
		WaitMissingTTLPolicy: "error",
		MetricsEnabled:       &on,
		WaitJitterMaxSec:     ptrFloat(2),
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
	if r.waitMissingTTLPolicy != MissingTTLError {
		t.Fatalf("waitMissingTTLPolicy = %v, want error", r.waitMissingTTLPolicy)
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

func TestOnConfigReloadRejectsInvalidPolicy(t *testing.T) {
	r := New(memoryOnlyOpts()...)
	r.configSource = "http-ratelimiter"
	r.initialized.Store(true)
	r.OnConfigReload("http-ratelimiter", &Config{
		WaitMissingTTLPolicy: "banana",
		UseMemoryFallback:    ptrBool(true),
		MemoryMapFullPolicy:  "allow",
	})
	if r.waitMissingTTLPolicy != MissingTTLProceed {
		t.Fatalf("invalid reload should keep last-good proceed, got %v", r.waitMissingTTLPolicy)
	}
	if r.reloads.Load() != 0 {
		t.Fatalf("rejected reload should not increment reloads")
	}
}

func TestUnknownMapFullPolicyNotSet(t *testing.T) {
	r := New()
	r.applyConfig(Config{MemoryMapFullPolicy: "banana"})
	if r.mapFullPolicySet {
		t.Fatal("unknown memory_map_full_policy must not mark policy as set")
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

func TestOptionConstructorsApply(t *testing.T) {
	delay := func(context.Context, string, time.Duration, time.Duration) (time.Duration, error) {
		return time.Millisecond, nil
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	r := New(
		WithLogger(logger),
		WithForceMemory(true),
		WithUseMemoryFallback(true),
		WithWaitDelayFunc(delay),
		WithConfigSource("http-ratelimiter", "config/rl.yaml",
			WithSourceEnvPrefix("RL_"),
			WithSourceFormat(cf_configuration.FormatYAML),
		),
		WithoutValkeyPeer(),
		WithMemoryMapFullPolicy("allow"),
		WithWaitMissingTTLPolicy("proceed"),
	)
	if !r.loggerSet || r.logger == nil {
		t.Fatal("WithLogger should set loggerSet")
	}
	if !r.ForceMemory() || !r.UseMemoryFallback() {
		t.Fatal("force_memory / use_memory_fallback options not applied")
	}
	if r.waitDelayFunc == nil {
		t.Fatal("WithWaitDelayFunc should set waitDelayFunc")
	}
	if r.configSource != "http-ratelimiter" || r.configPath != "config/rl.yaml" {
		t.Fatalf("config source = %q path %q", r.configSource, r.configPath)
	}
	if r.srcEnvPrefix != "RL_" || !r.srcFormatSet || r.srcFormat != cf_configuration.FormatYAML {
		t.Fatalf("source options: prefix=%q formatSet=%v format=%v", r.srcEnvPrefix, r.srcFormatSet, r.srcFormat)
	}
}

func TestWaitDelayAndMemoryMaxEntriesHelpers(t *testing.T) {
	r := newMemoryRL(t, WithWaitJitterMax(0), WithMemoryMaxEntries(42))
	if got := r.memoryMaxEntriesValue(); got != 42 {
		t.Fatalf("memoryMaxEntriesValue = %d, want 42", got)
	}
	r.memoryMaxEntries = 0
	if got := r.memoryMaxEntriesValue(); got != defaultMemoryMaxEntries {
		t.Fatalf("memoryMaxEntriesValue default = %d, want %d", got, defaultMemoryMaxEntries)
	}

	d, err := r.waitDelay(context.Background(), "k", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("waitDelay: %v", err)
	}
	if d != 50*time.Millisecond {
		t.Fatalf("waitDelay with jitterMax=0 = %v, want 50ms", d)
	}

	r2 := newMemoryRL(t, WithWaitJitterMax(time.Second))
	d2, err := r2.waitDelay(context.Background(), "k", time.Second)
	if err != nil {
		t.Fatalf("waitDelay jittered: %v", err)
	}
	if d2 < time.Second || d2 > time.Second+100*time.Millisecond {
		t.Fatalf("waitDelay jittered = %v, want in [1s, 1.1s]", d2)
	}

	called := false
	d3, err := r2.waitDelayOpts(context.Background(), "k", time.Second, WaitOptions{
		DelayFunc: func(ctx context.Context, key string, base, jittered time.Duration) (time.Duration, error) {
			called = true
			return 5 * time.Millisecond, nil
		},
	})
	if err != nil || !called || d3 != 5*time.Millisecond {
		t.Fatalf("waitDelayOpts DelayFunc: called=%v d=%v err=%v", called, d3, err)
	}
}

func TestRegisterConfigSources(t *testing.T) {
	r := New()
	if err := r.RegisterConfigSources(cf_configuration.New()); err != nil {
		t.Fatalf("no source bound should be no-op: %v", err)
	}
	if err := r.RegisterConfigSources("not-config"); err == nil {
		t.Fatal("wrong type should error")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "rl.json")
	if err := os.WriteFile(path, []byte(`{"key_prefix":"fromreg"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r = New(WithConfigSource("http-ratelimiter", path))
	conf := cf_configuration.New()
	if err := r.RegisterConfigSources(conf); err != nil {
		t.Fatalf("RegisterConfigSources: %v", err)
	}
	yamlPath := filepath.Join(dir, "rl.yaml")
	if err := os.WriteFile(yamlPath, []byte("key_prefix: yamlpref\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rYAML := New(WithConfigSource("rl-yaml", yamlPath))
	if err := rYAML.RegisterConfigSources(cf_configuration.New()); err != nil {
		t.Fatalf("RegisterConfigSources yaml: %v", err)
	}
}

func TestHealthMemoryPathAndClientErrors(t *testing.T) {
	r := newMemoryRL(t)
	if err := r.Health(context.Background()); err != nil {
		t.Fatalf("memory-path Health should be nil: %v", err)
	}
	if _, err := r.client(); err == nil {
		t.Fatal("client() on memory-only chassis should error (no valkey peer)")
	}
	_ = r.Shutdown(context.Background())
	if err := r.Health(context.Background()); err == nil {
		t.Fatal("Health after Shutdown should fail")
	}
	if _, err := r.Peek(context.Background(), "k"); err == nil {
		t.Fatal("Peek after Shutdown should fail")
	}
	if err := r.Reset(context.Background(), "k"); err == nil {
		t.Fatal("Reset after Shutdown should fail")
	}
}

func TestForceMemoryInitWithDegradedValkey(t *testing.T) {
	fw := testFW(t)
	vk := cf_valkey.New(
		cf_valkey.WithAddress("127.0.0.1:1"),
		cf_valkey.WithPingTimeout(200*time.Millisecond),
		cf_valkey.WithDegradedMode(true),
		cf_valkey.WithHealthWhenDegraded("not_ready"),
	)
	if err := fw.AddComponent(vk); err != nil {
		t.Fatalf("AddComponent valkey: %v", err)
	}
	r := New(
		WithForceMemory(true),
		WithUseMemoryFallback(true),
		WithMemoryMapFullPolicy("allow"),
		WithWaitMissingTTLPolicy("proceed"),
	)
	if err := fw.AddComponent(r); err != nil {
		t.Fatalf("AddComponent limiter: %v", err)
	}
	if err := fw.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	t.Cleanup(func() { _ = fw.Shutdown(context.Background()) })

	if !r.useMemoryPath() {
		t.Fatal("force_memory + dead valkey should use memory path")
	}
	if err := r.Health(context.Background()); err != nil {
		t.Fatalf("limiter Health on sticky path: %v", err)
	}
	res, err := r.Allow(context.Background(), "breakglass", 2, time.Minute)
	if err != nil || !res.Allowed {
		t.Fatalf("Allow on sticky path: res=%+v err=%v", res, err)
	}
	var force, inmem float64
	for _, m := range r.Metrics() {
		switch m.Name {
		case "http_ratelimiter_force_memory":
			force = m.Value
		case "http_ratelimiter_use_memory_fallback":
			inmem = m.Value
		}
	}
	if force != 1 || inmem != 1 {
		t.Fatalf("force_memory=%v use_memory_fallback=%v, want 1/1", force, inmem)
	}
}

func TestInitLoadsConfigFromSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "http-ratelimiter.json")
	body := `{
  "key_prefix": "fromfile",
  "use_memory_fallback": true,
  "force_memory": false,
  "memory_map_full_policy": "deny",
  "wait_missing_ttl_policy": "error",
  "memory_max_entries": 77,
  "max_key_length": 120
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	fw := testFW(t)
	if err := fw.AddComponent(cf_configuration.New()); err != nil {
		t.Fatalf("AddComponent configuration: %v", err)
	}
	r := New(
		WithoutValkeyPeer(),
		WithConfigSource("http-ratelimiter", path),
		WithUseMemoryFallback(true),
		WithMemoryMapFullPolicy("allow"),
		WithWaitMissingTTLPolicy("proceed"),
	)
	if err := fw.AddComponent(r); err != nil {
		t.Fatalf("AddComponent: %v", err)
	}
	if err := fw.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	t.Cleanup(func() { _ = fw.Shutdown(context.Background()) })

	if r.keyPrefix != "fromfile" {
		t.Fatalf("keyPrefix = %q, want fromfile (applyConfigFromSource)", r.keyPrefix)
	}
	if r.memoryMaxEntries != 77 {
		t.Fatalf("memoryMaxEntries = %d, want 77", r.memoryMaxEntries)
	}
	if r.mapFullPolicy != MapFullDeny {
		t.Fatalf("mapFullPolicy = %v, want deny from file", r.mapFullPolicy)
	}
	if r.waitMissingTTLPolicy != MissingTTLError {
		t.Fatalf("waitMissingTTLPolicy = %v, want error from file", r.waitMissingTTLPolicy)
	}
}

func TestInitConfigSourceMissingConfiguration(t *testing.T) {
	r := New(
		WithoutValkeyPeer(),
		WithUseMemoryFallback(true),
		WithMemoryMapFullPolicy("allow"),
		WithWaitMissingTTLPolicy("proceed"),
		WithConfigSource("http-ratelimiter", "nope.json"),
	)
	fw := cf.New()
	if err := r.Init(context.Background(), fw); err == nil {
		t.Fatal("Init with unbound config source should fail")
	}
}

func TestOnConfigReloadForceMemoryFlip(t *testing.T) {
	r := newMemoryRL(t)
	r.configSource = "http-ratelimiter"
	on := true
	force := true
	r.OnConfigReload("http-ratelimiter", &Config{
		UseMemoryFallback:    &on,
		ForceMemory:          &force,
		MemoryMapFullPolicy:  "allow",
		WaitMissingTTLPolicy: "proceed",
	})
	if !r.ForceMemory() {
		t.Fatal("reload should enable force_memory")
	}
	if !r.useMemoryPath() {
		t.Fatal("force_memory reload should keep/prefer memory path")
	}
}

func TestWaitOptsPerCallDelayFunc(t *testing.T) {
	r := newMemoryRL(t, WithWaitJitterMax(0))
	if _, err := r.Allow(context.Background(), "k", 1, time.Hour); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	err := r.WaitOpts(context.Background(), "k", 1, time.Hour, WaitOptions{
		DelayFunc: func(context.Context, string, time.Duration, time.Duration) (time.Duration, error) {
			return 0, context.Canceled
		},
	})
	if err != context.Canceled {
		t.Fatalf("WaitOpts = %v, want context.Canceled from DelayFunc", err)
	}
}

func TestPeekMemoryPathAndDoubleInit(t *testing.T) {
	r := newMemoryRL(t)
	ctx := context.Background()
	if _, err := r.Allow(ctx, "p", 5, time.Minute); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	res, err := r.Peek(ctx, "p")
	if err != nil || res.Count != 1 {
		t.Fatalf("Peek = %+v err=%v, want count 1", res, err)
	}
	if err := r.Init(ctx, cf.New()); err != nil {
		t.Fatalf("second Init: %v", err)
	}
}

func TestInitIdempotentAlreadyInitialized(t *testing.T) {
	r := New(memoryOnlyOpts()...)
	fw := cf.New()
	if err := r.Init(context.Background(), fw); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := r.Init(context.Background(), fw); err != nil {
		t.Fatalf("re-Init: %v", err)
	}
	_ = r.Shutdown(context.Background())
}

func ptrFloat(f float64) *float64 { return &f }

func ptrBool(b bool) *bool { return &b }
