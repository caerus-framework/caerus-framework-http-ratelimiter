package cf_http_ratelimiter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cf "github.com/caerus-framework/caerus-framework"
)

func memRL(t *testing.T) *RateLimiter {
	t.Helper()
	r := New(
		WithoutValkeyPeer(),
		WithUseMemoryFallback(true),
		WithMemoryMapFullPolicy("allow"),
		WithWaitMissingTTLPolicy("proceed"),
		WithWaitJitterMax(0),
	)
	if err := r.Init(context.Background(), cf.New()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = r.Shutdown(context.Background()) })
	return r
}

type stubDenied struct {
	called bool
	status int
	res    Result
}

func TestMiddlewareRequiresOnStoreError(t *testing.T) {
	r := memRL(t)
	_, err := Middleware(MiddlewareConfig{Limiter: r, Window: time.Minute, KeyFunc: RemoteAddrKey})
	if err == nil {
		t.Fatal("Middleware without OnStoreError should error")
	}
	if !strings.Contains(err.Error(), "OnStoreError") {
		t.Fatalf("error = %v, want OnStoreError mention", err)
	}
}

func TestMiddlewareValidationErrors(t *testing.T) {
	r := memRL(t)
	pol := StorageFailOpen
	cases := []struct {
		name string
		cfg  MiddlewareConfig
		want string
	}{
		{"nil limiter", MiddlewareConfig{OnStoreError: &pol}, "Limiter"},
		{"zero window", MiddlewareConfig{Limiter: r, Window: 0, OnStoreError: &pol, KeyFunc: RemoteAddrKey}, "Window"},
		{"negative window", MiddlewareConfig{Limiter: r, Window: -time.Second, OnStoreError: &pol, KeyFunc: RemoteAddrKey}, "Window"},
		{"nil keyfunc", MiddlewareConfig{Limiter: r, Window: time.Minute, OnStoreError: &pol}, "KeyFunc"},
	}
	for _, tc := range cases {
		if _, err := Middleware(tc.cfg); err == nil {
			t.Fatalf("%s: expected error", tc.name)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: error = %q, want mention of %q", tc.name, err.Error(), tc.want)
		}
	}
}

func TestMiddlewareAllowsAndDenies(t *testing.T) {
	r := memRL(t)
	pol := StorageFailOpen
	var denied stubDenied
	mw, err := Middleware(MiddlewareConfig{
		Limiter:      r,
		Limit:        2,
		Window:       time.Minute,
		KeyFunc:      func(r *http.Request) string { return "k:" + r.URL.Path },
		OnStoreError: &pol,
		OnDenied: func(w http.ResponseWriter, _ *http.Request, res Result, status int) {
			denied.called = true
			denied.status = status
			denied.res = res
			http.Error(w, "too many", status)
		},
	})
	if err != nil {
		t.Fatalf("Middleware: %v", err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/a", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d status = %d, want 200", i+1, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/a", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd status = %d, want 429", rec.Code)
	}
	if !denied.called {
		t.Fatal("OnDenied not called on the 3rd request")
	}
	if denied.status != http.StatusTooManyRequests {
		t.Fatalf("OnDenied status = %d, want 429", denied.status)
	}
	if denied.res.Allowed {
		t.Fatal("OnDenied should receive an unallowed Result")
	}
}

func TestMiddlewareDefaultOnDenied(t *testing.T) {
	r := memRL(t)
	pol := StorageFailOpen
	mw, err := Middleware(MiddlewareConfig{
		Limiter:      r,
		Limit:        1,
		Window:       time.Minute,
		KeyFunc:      func(r *http.Request) string { return "k" },
		OnStoreError: &pol,
	})
	if err != nil {
		t.Fatalf("Middleware: %v", err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Too Many Requests") {
		t.Fatalf("default OnDenied body = %q, want a 429 text", body)
	}
}

func TestMiddlewareLimitZeroAllowsAll(t *testing.T) {
	r := memRL(t)
	pol := StorageFailOpen
	mw, err := Middleware(MiddlewareConfig{
		Limiter:      r,
		Limit:        0,
		Window:       time.Minute,
		KeyFunc:      func(r *http.Request) string { return "k" },
		OnStoreError: &pol,
	})
	if err != nil {
		t.Fatalf("Middleware: %v", err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d status = %d, want 200", i+1, rec.Code)
		}
	}
}

func TestMiddlewareDefaultKeyFuncRemoteAddr(t *testing.T) {
	r := memRL(t)
	pol := StorageFailOpen
	mw, err := Middleware(MiddlewareConfig{
		Limiter:      r,
		Limit:        1,
		Window:       time.Minute,
		KeyFunc:      RemoteAddrKey,
		OnStoreError: &pol,
	})
	if err != nil {
		t.Fatalf("Middleware: %v", err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:4444"
	h.ServeHTTP(httptest.NewRecorder(), req)
	// Same IP → denied.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.0.0.1:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req2)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("same IP again status = %d, want 429 (key is the stripped host, not the port)", rec.Code)
	}
	// Different IP → allowed.
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.RemoteAddr = "10.0.0.2:4444"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req3)
	if rec.Code != http.StatusOK {
		t.Fatalf("different IP status = %d, want 200", rec.Code)
	}
}

func TestMiddlewareRetryAfterMatchesWindow(t *testing.T) {
	r := memRL(t)
	pol := StorageFailOpen
	mw, err := Middleware(MiddlewareConfig{
		Limiter:      r,
		Limit:        1,
		Window:       2 * time.Hour,
		KeyFunc:      func(r *http.Request) string { return "k" },
		OnStoreError: &pol,
	})
	if err != nil {
		t.Fatalf("Middleware: %v", err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if retry := rec.Header().Get("Retry-After"); retry != "7200" {
		t.Fatalf("Retry-After = %q, want 7200", retry)
	}
}

func TestMiddlewareMemoryFallbackRequiresUseMemoryFallback(t *testing.T) {
	r := New()
	pol := StorageMemoryFallback
	_, err := Middleware(MiddlewareConfig{
		Limiter:      r,
		Limit:        2,
		Window:       time.Minute,
		KeyFunc:      func(r *http.Request) string { return "k" },
		OnStoreError: &pol,
	})
	if err == nil {
		t.Fatal("Middleware with MemoryFallback and use_memory_fallback=false should error")
	}
	if !strings.Contains(err.Error(), "use_memory_fallback") {
		t.Fatalf("error = %v, want use_memory_fallback mention", err)
	}
}

func TestMiddlewareMemoryFallbackOnStoreError(t *testing.T) {
	// A valkey-backend limiter with no store (never Init'd): middleware should
	// fall back to the in-memory map under StorageMemoryFallback.
	r := New(WithMemoryMaxEntries(100), WithUseMemoryFallback(true), WithMemoryMapFullPolicy("allow"), WithWaitJitterMax(0))
	pol := StorageMemoryFallback
	mw, err := Middleware(MiddlewareConfig{
		Limiter:      r,
		Limit:        2,
		Window:       time.Minute,
		KeyFunc:      func(r *http.Request) string { return "k" },
		OnStoreError: &pol,
	})
	if err != nil {
		t.Fatalf("Middleware: %v", err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d status = %d, want 200", i+1, rec.Code)
		}
	}
	if r.fbMemory.Load() == 0 {
		t.Fatal("memory-fallback policy should have fired (fbMemory counter)")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd status = %d, want 429 from fallback", rec.Code)
	}
}

func TestMiddlewareFailClosedOnStoreError(t *testing.T) {
	r := New() // no memory, no Init → store always errors
	pol := StorageFailClosed
	mw, err := Middleware(MiddlewareConfig{
		Limiter:      r,
		Limit:        10,
		Window:       time.Minute,
		KeyFunc:      func(r *http.Request) string { return "k" },
		OnStoreError: &pol,
	})
	if err != nil {
		t.Fatalf("Middleware: %v", err)
	}
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if r.fbClosed.Load() == 0 {
		t.Fatal("fail-closed policy should have fired (fbClosed counter)")
	}
	if retry := rec.Header().Get("Retry-After"); retry != "1" {
		t.Fatalf("Retry-After = %q, want 1", retry)
	}
}

func TestMiddlewareFailOpenOnStoreError(t *testing.T) {
	r := New() // no memory, no Init → store always errors
	pol := StorageFailOpen
	mw, err := Middleware(MiddlewareConfig{
		Limiter:      r,
		Limit:        10,
		Window:       time.Minute,
		KeyFunc:      func(r *http.Request) string { return "k" },
		OnStoreError: &pol,
	})
	if err != nil {
		t.Fatalf("Middleware: %v", err)
	}
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fail-open)", rec.Code)
	}
	if r.fbOpen.Load() == 0 {
		t.Fatal("fail-open policy should have fired (fbOpen counter)")
	}
}
