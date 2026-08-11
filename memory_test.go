package cf_http_ratelimiter

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"
)

func memoryCfg(max int) MemoryFallbackConfig {
	return MemoryFallbackConfig{MaxEntries: max, WhenMapFull: MapFullAllow}
}

func TestMemoryLimiterCounts(t *testing.T) {
	m := newMemoryLimiter()
	ctx := context.Background()
	for i := int64(1); i <= 3; i++ {
		res, err := m.Allow(ctx, "k", 3, time.Minute, memoryCfg(10))
		if err != nil {
			t.Fatalf("Allow: %v", err)
		}
		if !res.Allowed || res.Count != i {
			t.Fatalf("call %d = %+v, want allowed count %d", i, res, i)
		}
	}
	res, err := m.Allow(ctx, "k", 3, time.Minute, memoryCfg(10))
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if res.Allowed {
		t.Fatal("4th call should be denied")
	}
	if res.Count != 4 {
		t.Fatalf("count = %d, want 4", res.Count)
	}
}

func TestMemoryLimiterWindowReset(t *testing.T) {
	m := newMemoryLimiter()
	ctx := context.Background()
	if _, err := m.Allow(ctx, "k", 1, 100*time.Millisecond, memoryCfg(10)); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	res, err := m.Allow(ctx, "k", 1, 100*time.Millisecond, memoryCfg(10))
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !res.Allowed || res.Count != 1 {
		t.Fatalf("after window reset = %+v, want allowed count 1", res)
	}
}

func TestMemoryLimiterPeek(t *testing.T) {
	m := newMemoryLimiter()
	ctx := context.Background()
	if res := m.Peek(ctx, "k"); res.Count != 0 || res.ResetIn != 0 {
		t.Fatalf("Peek on missing key = %+v, want zero", res)
	}
	if _, err := m.Allow(ctx, "k", 5, time.Minute, memoryCfg(10)); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if res := m.Peek(ctx, "k"); res.Count != 1 || res.ResetIn <= 0 {
		t.Fatalf("Peek after allow = %+v, want count 1 with ResetIn", res)
	}
	// Peek must not increment.
	if res := m.Peek(ctx, "k"); res.Count != 1 {
		t.Fatalf("Peek incremented? count = %d, want 1", res.Count)
	}
}

func TestMemoryLimiterReset(t *testing.T) {
	m := newMemoryLimiter()
	ctx := context.Background()
	if _, err := m.Allow(ctx, "k", 5, time.Minute, memoryCfg(10)); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	m.Reset(ctx, "k")
	if res := m.Peek(ctx, "k"); res.Count != 0 {
		t.Fatalf("Peek after Reset = %+v, want zero", res)
	}
}

func TestMemoryLimiterMapFullAllow(t *testing.T) {
	m := newMemoryLimiter()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := m.Allow(ctx, "k"+strconv.Itoa(i), 10, time.Minute, memoryCfg(3)); err != nil {
			t.Fatalf("Allow: %v", err)
		}
	}
	res, err := m.Allow(ctx, "k-new", 10, time.Minute, memoryCfg(3))
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !res.Allowed {
		t.Fatal("new key on full map should be allowed under MapFullAllow")
	}
	if m.FullAllow() != 1 {
		t.Fatalf("FullAllow = %d, want 1", m.FullAllow())
	}
	if m.FullDeny() != 0 {
		t.Fatalf("FullDeny = %d, want 0", m.FullDeny())
	}
}

func TestMemoryLimiterMapFullDeny(t *testing.T) {
	m := newMemoryLimiter()
	ctx := context.Background()
	cfg := MemoryFallbackConfig{MaxEntries: 3, WhenMapFull: MapFullDeny}
	for i := 0; i < 3; i++ {
		if _, err := m.Allow(ctx, "k"+strconv.Itoa(i), 10, time.Minute, cfg); err != nil {
			t.Fatalf("Allow: %v", err)
		}
	}
	res, err := m.Allow(ctx, "k-new", 10, time.Minute, cfg)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if res.Allowed {
		t.Fatal("new key on full map should be denied under MapFullDeny")
	}
	if m.FullDeny() != 1 {
		t.Fatalf("FullDeny = %d, want 1", m.FullDeny())
	}
}

func TestMemoryLimiterLen(t *testing.T) {
	m := newMemoryLimiter()
	ctx := context.Background()
	if m.Len() != 0 {
		t.Fatalf("Len = %d, want 0", m.Len())
	}
	for i := 0; i < 5; i++ {
		if _, err := m.Allow(ctx, "k"+strconv.Itoa(i), 10, time.Minute, memoryCfg(10)); err != nil {
			t.Fatalf("Allow: %v", err)
		}
	}
	if m.Len() != 5 {
		t.Fatalf("Len = %d, want 5", m.Len())
	}
	m.Reset(ctx, "k0")
	if m.Len() != 4 {
		t.Fatalf("Len after reset = %d, want 4", m.Len())
	}
}

func TestMemoryLimiterConcurrent(t *testing.T) {
	m := newMemoryLimiter()
	ctx := context.Background()
	const n = 100
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Allow(ctx, "burst", 1000, time.Minute, memoryCfg(1000)); err != nil {
				t.Errorf("Allow: %v", err)
			}
		}()
	}
	wg.Wait()
	res := m.Peek(ctx, "burst")
	if res.Count != n {
		t.Fatalf("count = %d, want %d (no lost updates)", res.Count, n)
	}
}
