package cf_http_ratelimiter

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cf "github.com/caerus-framework/caerus-framework"
	cf_logs "github.com/caerus-framework/caerus-framework-logs"
	cf_valkey "github.com/caerus-framework/caerus-framework-valkey"
	cf_valkey_state "github.com/caerus-framework/caerus-framework-valkey-state"
	"github.com/valkey-io/valkey-go"
)

func setupLimiter(t *testing.T) (*RateLimiter, *cf_valkey.CFValkey, valkey.Client) {
	t.Helper()
	addr := os.Getenv("VALKEY_ADDR")
	if addr == "" {
		t.Skip("VALKEY_ADDR not set; skipping integration test")
	}
	fw := cf.New()
	if err := fw.AddComponent(cf_logs.New(cf_logs.WithWriter(io.Discard))); err != nil {
		t.Fatalf("logs: %v", err)
	}
	vk := cf_valkey.New(
		cf_valkey.WithAddress(addr),
		cf_valkey.WithKeyPrefix("http-ratelimiter-test"),
	)
	if err := fw.AddComponent(vk); err != nil {
		t.Fatalf("valkey: %v", err)
	}
	st := cf_valkey_state.New()
	if err := fw.AddComponent(st); err != nil {
		t.Fatalf("state: %v", err)
	}
	r := New()
	if err := fw.AddComponent(r); err != nil {
		t.Fatalf("limiter: %v", err)
	}
	if err := fw.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	t.Cleanup(func() { _ = fw.Shutdown(context.Background()) })
	raw := vk.Client()
	if err := raw.Do(context.Background(), raw.B().Flushdb().Build()).Error(); err != nil {
		t.Fatalf("Flushdb: %v", err)
	}
	return r, vk, raw
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
	r, _, _ := setupLimiter(t)
	ctx := context.Background()
	for i := int64(1); i <= 3; i++ {
		res, err := r.Allow(ctx, "login:user@example.com", 3, 60*time.Second)
		if err != nil {
			t.Fatalf("Allow: %v", err)
		}
		if !res.Allowed || res.Count != i {
			t.Fatalf("call %d = %+v", i, res)
		}
	}
	res, err := r.Allow(ctx, "login:user@example.com", 3, 60*time.Second)
	if err != nil || res.Allowed || res.Count != 4 {
		t.Fatalf("4th = %+v err=%v", res, err)
	}
}

func TestIntegrationLuaPTTLNoExtend(t *testing.T) {
	r, vk, raw := setupLimiter(t)
	ctx := context.Background()
	if _, err := r.Allow(ctx, "k", 10, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	key := vk.Key("rl", "k")
	first := pttl(t, raw, key)
	time.Sleep(500 * time.Millisecond)
	if _, err := r.Allow(ctx, "k", 10, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	second := pttl(t, raw, key)
	if second > first {
		t.Fatalf("PTTL extended: %v -> %v", first, second)
	}
}

func TestIntegrationPeekAndReset(t *testing.T) {
	r, _, _ := setupLimiter(t)
	ctx := context.Background()
	res, err := r.Peek(ctx, "fresh")
	if err != nil || res.Count != 0 {
		t.Fatalf("Peek missing = %+v %v", res, err)
	}
	if _, err := r.Allow(ctx, "burst", 10, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	res, err = r.Peek(ctx, "burst")
	if err != nil || res.Count != 1 {
		t.Fatalf("Peek = %+v %v", res, err)
	}
	if err := r.Reset(ctx, "burst"); err != nil {
		t.Fatal(err)
	}
	res, err = r.Peek(ctx, "burst")
	if err != nil || res.Count != 0 {
		t.Fatalf("after reset = %+v %v", res, err)
	}
}

func TestIntegrationAtomicity(t *testing.T) {
	r, _, _ := setupLimiter(t)
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
		t.Fatalf("allowed = %d", allowed.Load())
	}
}

func TestIntegrationMissingTTLProceed(t *testing.T) {
	r, vk, raw := setupLimiter(t)
	ctx := context.Background()
	logical := "orphan"
	storeKey := vk.Key("rl", logical)
	if err := raw.Do(ctx, raw.B().Set().Key(storeKey).Value("3").Build()).Error(); err != nil {
		t.Fatal(err)
	}
	res, err := r.Peek(ctx, logical)
	if err != nil || res.Count != 0 {
		t.Fatalf("after scrub Peek = %+v %v", res, err)
	}
	res, err = r.Allow(ctx, logical, 5, time.Minute)
	if err != nil || !res.Allowed || res.Count != 1 {
		t.Fatalf("Allow after scrub = %+v %v", res, err)
	}
}

func TestIntegrationMissingTTLError(t *testing.T) {
	r, vk, raw := setupLimiter(t)
	ctx := context.Background()
	logical := "orphan-err"
	storeKey := vk.Key("rl", logical)
	if err := raw.Do(ctx, raw.B().Set().Key(storeKey).Value("2").Build()).Error(); err != nil {
		t.Fatal(err)
	}
	errPol := MissingTTLError
	err := r.WaitOpts(ctx, logical, 1, time.Minute, WaitOptions{MissingTTLPolicy: &errPol})
	if !errors.Is(err, ErrMissingTTL) {
		t.Fatalf("WaitOpts = %v, want ErrMissingTTL", err)
	}
}

func TestIntegrationHealthAndMetrics(t *testing.T) {
	r, _, _ := setupLimiter(t)
	ctx := context.Background()
	if err := r.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Allow(ctx, "m", 5, time.Minute); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range r.Metrics() {
		if m.Name == "http_ratelimiter_allows_total" && m.Value == 1 {
			found = true
		}
	}
	if !found {
		t.Fatal("allows_total should be 1")
	}
}
