package cf_http_ratelimiter

import (
	"context"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cf "github.com/caerus-framework/caerus-framework"
	cf_logs "github.com/caerus-framework/caerus-framework-logs"
	cf_valkey "github.com/caerus-framework/caerus-framework-valkey"
	"github.com/valkey-io/valkey-go"
)

func setupLimiter(t *testing.T, opts ...Option) (*RateLimiter, valkey.Client) {
	t.Helper()
	addr := os.Getenv("VALKEY_ADDR")
	if addr == "" {
		t.Skip("VALKEY_ADDR not set; skipping integration test")
	}
	fw := cf.New()
	if err := fw.AddComponent(cf_logs.New(cf_logs.WithWriter(io.Discard))); err != nil {
		t.Fatalf("AddComponent logs: %v", err)
	}
	vk := cf_valkey.New(
		cf_valkey.WithAddress(addr),
		cf_valkey.WithKeyPrefix("http-ratelimiter-test"),
	)
	if err := fw.AddComponent(vk); err != nil {
		t.Fatalf("AddComponent valkey: %v", err)
	}
	r := New(opts...)
	if err := fw.AddComponent(r); err != nil {
		t.Fatalf("AddComponent ratelimiter: %v", err)
	}
	if err := fw.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	t.Cleanup(func() { _ = fw.Shutdown(context.Background()) })

	raw := vk.Client()
	if err := raw.Do(context.Background(), raw.B().Flushdb().Build()).Error(); err != nil {
		t.Fatalf("Flushdb: %v", err)
	}
	return r, raw
}

func pttl(t *testing.T, raw valkey.Client, key string) time.Duration {
	t.Helper()
	resp := raw.Do(context.Background(), raw.B().Pttl().Key(key).Build())
	if resp.Error() != nil {
		t.Fatalf("Pttl: %v", resp.Error())
	}
	ms, err := resp.AsInt64()
	if err != nil {
		t.Fatalf("Pttl AsInt64: %v", err)
	}
	return time.Duration(ms) * time.Millisecond
}

func TestIntegrationLuaAllowWindow(t *testing.T) {
	r, _ := setupLimiter(t)
	ctx := context.Background()
	for i := int64(1); i <= 3; i++ {
		res, err := r.Allow(ctx, "login:user@example.com", 3, 60*time.Second)
		if err != nil {
			t.Fatalf("Allow: %v", err)
		}
		if !res.Allowed || res.Count != i {
			t.Fatalf("call %d = %+v, want allowed count %d", i, res, i)
		}
		if res.ResetIn <= 0 || res.ResetIn > 60*time.Second {
			t.Fatalf("ResetIn = %v, want within window", res.ResetIn)
		}
	}
	res, err := r.Allow(ctx, "login:user@example.com", 3, 60*time.Second)
	if err != nil {
		t.Fatalf("Allow (over): %v", err)
	}
	if res.Allowed || res.Count != 4 {
		t.Fatalf("4th call = %+v, want denied count 4", res)
	}
}

func TestIntegrationLuaPTTLNoExtend(t *testing.T) {
	r, raw := setupLimiter(t)
	ctx := context.Background()
	if _, err := r.Allow(ctx, "k", 10, 2*time.Second); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	key := r.Key("k")
	first := pttl(t, raw, key)
	if first <= 0 || first > 2*time.Second {
		t.Fatalf("first PTTL = %v, want ~2s", first)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := r.Allow(ctx, "k", 10, 2*time.Second); err != nil {
		t.Fatalf("Allow (second): %v", err)
	}
	// PEXPIRE must only run on the first increment: PTTL must not be reset.
	second := pttl(t, raw, key)
	if second > first {
		t.Fatalf("PTTL extended: first %v, second %v (fixed-window must not slide)", first, second)
	}
	if second < 1100*time.Millisecond {
		t.Fatalf("second PTTL = %v, want still ~1.5s (only decremented)", second)
	}
}

func TestIntegrationPeekAndReset(t *testing.T) {
	r, raw := setupLimiter(t)
	ctx := context.Background()

	res, err := r.Peek(ctx, "fresh")
	if err != nil {
		t.Fatalf("Peek on missing key: %v", err)
	}
	if res.Count != 0 || res.ResetIn != 0 {
		t.Fatalf("Peek on missing = %+v, want zero", res)
	}

	if _, err := r.Allow(ctx, "burst", 10, 2*time.Second); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	// Peek reads the counter without incrementing.
	res, err = r.Peek(ctx, "burst")
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if res.Count != 1 {
		t.Fatalf("Peek count = %d, want 1", res.Count)
	}
	if d := pttl(t, raw, r.Key("burst")); d <= 0 || d > 2*time.Second {
		t.Fatalf("PTTL after peek = %v, want ~2s", d)
	}
	// Peek again: still 1.
	res, err = r.Peek(ctx, "burst")
	if err != nil {
		t.Fatalf("Peek (2nd): %v", err)
	}
	if res.Count != 1 {
		t.Fatalf("Peek count after 2nd peek = %d, want 1 (no increment)", res.Count)
	}

	if err := r.Reset(ctx, "burst"); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	res, err = r.Peek(ctx, "burst")
	if err != nil {
		t.Fatalf("Peek after reset: %v", err)
	}
	if res.Count != 0 {
		t.Fatalf("Peek count after reset = %d, want 0", res.Count)
	}
	// Reset is idempotent on a missing key.
	if err := r.Reset(ctx, "burst"); err != nil {
		t.Fatalf("Reset on missing key: %v", err)
	}
}

func TestIntegrationWindowReset(t *testing.T) {
	r, _ := setupLimiter(t)
	ctx := context.Background()
	if _, err := r.Allow(ctx, "ip:1.2.3.4", 1, 200*time.Millisecond); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	time.Sleep(350 * time.Millisecond)
	res, err := r.Allow(ctx, "ip:1.2.3.4", 1, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("Allow after reset: %v", err)
	}
	if !res.Allowed || res.Count != 1 {
		t.Fatalf("after window reset = %+v, want allowed count 1", res)
	}
}

func TestIntegrationAtomicity(t *testing.T) {
	r, _ := setupLimiter(t)
	ctx := context.Background()
	const n = 25
	var wg sync.WaitGroup
	var allowed atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := r.Allow(ctx, "burst", 100, time.Minute)
			if err != nil {
				t.Errorf("Allow: %v", err)
				return
			}
			if res.Allowed {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != n {
		t.Fatalf("allowed = %d, want %d", allowed.Load(), n)
	}
	res, err := r.Allow(ctx, "burst", 100, time.Minute)
	if err != nil {
		t.Fatalf("final Allow: %v", err)
	}
	if res.Count != n+1 {
		t.Fatalf("final count = %d, want %d", res.Count, n+1)
	}
}

func TestIntegrationMemoryFallbackUnderValkey(t *testing.T) {
	r, raw := setupLimiter(t)
	ctx := context.Background()

	if _, err := r.Allow(ctx, "k", 10, time.Minute); err != nil {
		t.Fatalf("Allow before outage: %v", err)
	}
	// Simulate the store going away by closing the peer's client.
	raw.Close()
	res, err := r.AllowWithPolicy(ctx, "k", 2, time.Minute, StorageMemoryFallback)
	if err != nil {
		t.Fatalf("MemoryFallback: %v", err)
	}
	if !res.Allowed || res.Count != 1 {
		t.Fatalf("fallback result = %+v, want allowed count 1", res)
	}
	if _, err := r.AllowWithPolicy(ctx, "k", 2, time.Minute, StorageMemoryFallback); err != nil {
		t.Fatalf("AllowWithPolicy: %v", err)
	}
	res, err = r.AllowWithPolicy(ctx, "k", 2, time.Minute, StorageMemoryFallback)
	if err != nil {
		t.Fatalf("AllowWithPolicy: %v", err)
	}
	if res.Allowed {
		t.Fatal("3rd fallback call should be denied (fallback limit 2)")
	}
	if r.fbMemory.Load() == 0 {
		t.Fatal("fbMemory counter should be set")
	}
}

func TestIntegrationHealthAndMetrics(t *testing.T) {
	r, _ := setupLimiter(t)
	ctx := context.Background()
	if err := r.Health(ctx); err != nil {
		t.Fatalf("Health after init: %v", err)
	}
	if ms := r.Metrics(); ms == nil {
		t.Fatal("Metrics after init should be non-nil")
	}
	if _, err := r.Allow(ctx, "m", 5, time.Minute); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	found := false
	for _, m := range r.Metrics() {
		if m.Name == "http_ratelimiter_allows_total" && m.Value == 1 {
			found = true
		}
	}
	if !found {
		t.Fatal("allows_total should be 1 after one Allow")
	}
}
