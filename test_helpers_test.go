package cf_http_ratelimiter

import (
	"context"
	"testing"

	cf "github.com/caerus-framework/caerus-framework"
	cf_valkey_state "github.com/caerus-framework/caerus-framework-valkey-state"
)

func memoryState(t *testing.T) *cf_valkey_state.CFState {
	t.Helper()
	return cf_valkey_state.New(
		cf_valkey_state.WithoutValkeyPeer(),
		cf_valkey_state.WithForceMemory(true),
		cf_valkey_state.WithUseMemoryFallback(true),
		cf_valkey_state.WithMemoryMapFullPolicy("allow"),
	)
}

func initLimiter(t *testing.T, rl *RateLimiter, st *cf_valkey_state.CFState) {
	t.Helper()
	fw := cf.New()
	if err := fw.AddComponent(st); err != nil {
		t.Fatalf("AddComponent state: %v", err)
	}
	if err := fw.AddComponent(rl); err != nil {
		t.Fatalf("AddComponent limiter: %v", err)
	}
	ctx := context.Background()
	if err := st.Init(ctx, fw); err != nil {
		t.Fatalf("state Init: %v", err)
	}
	if err := rl.Init(ctx, fw); err != nil {
		t.Fatalf("limiter Init: %v", err)
	}
	t.Cleanup(func() {
		_ = rl.Shutdown(ctx)
		_ = st.Shutdown(ctx)
	})
}
