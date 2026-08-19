# caerus-framework-http-ratelimiter

[![CI](https://github.com/caerus-framework/caerus-framework-http-ratelimiter/actions/workflows/ci.yml/badge.svg)](https://github.com/caerus-framework/caerus-framework-http-ratelimiter/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/caerus-framework/caerus-framework-http-ratelimiter/graph/badge.svg)](https://codecov.io/gh/caerus-framework/caerus-framework-http-ratelimiter)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Caerus Framework HTTP Rate Limiter. **Fixed-window** counting for inbound
middleware (429 + `Retry-After`, never sleep) and outbound `Wait`. The
**counter store** is `caerus-framework-valkey-state` (Lua on a valkey peer, or
that module’s sticky-note map). This package does **not** import `valkey-go`,
does not `Eval`, and does not own a second map.

**Choosing this module means configuring fail-open vs fail-closed per call
site** when **state already failed**. There is no silent fail-open.
`StorageMemoryFallback` is removed: Valkey vs memory is
`valkey-state.json` → `rate_limit`.

## What it is (and is not — yet)

| Is | Is not |
|---|---|
| **Fixed-window** counting with a Valkey `INCR` + `PEXPIRE` (TTL only set on the first increment) | Sliding window, token bucket, or leaky bucket (see below) |
| A stdlib `func(http.Handler) http.Handler` middleware plus `Allow`/`Reset`/`Peek`/`Wait` primitives | A router, a WAF, or a per-endpoint policy engine |
| A way to **pace your own outbound calls** (`Wait`: peek + interruptible sleep + jitter + allow once) | A way to slow down HTTP responses for attackers — answer **429 + Retry-After** instead |
| A rule about "how often" something may happen | A lock about "who owns it right now" — that is a different concern (see Recipe B) |

### Fixed window vs the others (same story, four machines)

Imagine the rule: **“at most 30 requests every 60 seconds.”**
Four common machines can enforce a sentence like that. They are **not** the
same machine. This module ships only the first.

| Machine | Picture for a 14-year-old | What “30 per 60s” really means | Nice part | Ugly part | This module? |
|---|---|---|---|---|---|
| **Fixed window** | A kitchen timer. When the first request arrives, you start a 60s countdown and put a tally mark for every request. When the timer hits zero, you throw the paper away and start over on the next request. | At most 30 tallies **inside one 60s timer run**. The timer is tied to that key’s TTL (here: set on the first `INCR`). | Dead simple. One counter + one expiry. Cheap in Valkey (`INCR` + `PEXPIRE`). Easy to reason about and to implement with Lua. | **Boundary burst:** use 30 at 0:59, timer ends, use 30 again at 1:00 → ~60 in two seconds that *cross* the boundary. The calendar does not care about your feeling of “one minute.” | **Yes — this is what we ship.** |
| **Sliding window** | A moving picture frame on a timeline. You always look at “the last 60 seconds from *now*,” not “the box that started when I first clicked.” | At most 30 requests whose timestamps fall inside the trailing 60s. | Matches how humans say “per minute.” Softens the fixed-window boundary spike. | Needs more memory or clever math (store timestamps, or approximate with weighted previous+current windows). Heavier than one counter. | **Not yet** |
| **Token bucket** | A jar of coins. Coins drip into the jar at a steady rate (refill). Each request spends one coin. If the jar is empty, you wait or get denied. The jar has a max size (burst). | Average rate ≈ refill speed; short bursts up to the jar size are allowed. | Great for “usually 30/min, but a small burst is OK.” Natural fit for pacing (`Wait` until a coin exists). | You must pick **rate + burst** carefully. Two numbers, not one “limit per window.” Harder to explain to product people. | **Not yet** |
| **Leaky bucket** | A funnel. Requests pour into the top; they leave the bottom at a **constant** drip. If you pour too fast, the funnel overflows (deny) or the queue grows. | Outflow is smooth; spikes get queued or dropped so the *exit* rate stays flat. | Excellent when the thing behind you hates bursts (legacy API, fragile DB). | Often adds **queueing delay**. Can feel unfair (“I arrived first but wait”). Easy to confuse with token bucket (related math, different story). | **Not yet** |

**What this module means today by “fixed window”:** for a key, the counter
resets when its TTL expires. Limit `30` and window `60s` means “at most 30
while this timer is alive,” **not** “at most 30 in every rolling wall-clock
minute.” If you need true rolling minutes or smooth drip rates, that is a
later algorithm — not a config toggle on this one.

**Why start here:** auth-style login lockouts and IP caps usually want a
simple shared counter, not a traffic-shaping lab. Fixed window + Valkey is
the smallest honest story that works across replicas. Sliding / token /
leaky can wait until a product actually needs their shape.

## Behaviour schemes

Canonical teaching diagrams for this module. **Inbound never sleeps;
outbound `Wait` may.**

### Layers — who owns what

```mermaid
flowchart TB
  M["MODULE settings<br/>http-ratelimiter.json<br/>metrics, hash_ip_keys, jitter"]
  A["APP settings<br/>myservice.json / myapirequestor.json<br/>loginLimit, ipLimit, …"]
  C["CALL SITE code<br/>OnStoreError, KeyFunc,<br/>this route's limit/window"]
  M --> A --> C
```

### Inbound HTTP (middleware) — never sleeps

```mermaid
flowchart TD
  R[request] --> K["KeyFunc(r) → logical key<br/>TRUSTED identity only"]
  K --> L{limit ≤ 0?}
  L -->|yes| D["ALLOW — no store<br/>disabled_total++"]
  L -->|no| V{validate key}
  V -->|fail| RJ["error / reject<br/>key_rejected_total"]
  V -->|ok| S["primary store<br/>valkey-state Allow"]
  S -->|OK| C{Count ≤ limit?}
  S -->|store ERROR| P["OnStoreError REQUIRED"]
  C -->|yes| N[next handler]
  C -->|no| DENY["429 + Retry-After<br/>no sleep"]
  P --> FO[FailOpen → ALLOW warn]
  P --> FC[FailClosed → DENY/503]
```

### Outbound `Wait` — may sleep

```mermaid
flowchart TD
  W["Wait(key, limit, window)"] --> Peek[Peek]
  Peek --> Q{"Count < limit?"}
  Q -->|yes| Allow[Allow once]
  Allow -->|OK| Done[return OK]
  Allow -->|denied| Reset[use ResetIn]
  Reset --> Sleep
  Q -->|no| Sleep["sleep ResetIn + jitter<br/>honour ctx"]
  Sleep --> Peek
```

### Where counters live

```mermaid
flowchart TD
  K[logical key] --> S["valkey-state Allow/Peek/Reset"]
  S --> V["Valkey Lua<br/>shared across replicas<br/>normal prod"]
  S --> M["In-process map per pod<br/>rate_limit.use_memory_fallback / force_memory<br/>multi-replica = split counters"]
```

Sticky-note switches and DegradedMode live on **valkey-state** (`rate_limit` in
`valkey-state.json`), not on this module. See that README. The limiter only
chooses FailOpen vs FailClosed after state already returned an error.

### One-line model

| Path | Behaviour |
|---|---|
| **Inbound** | count → deny fast (429) → **never sleep** |
| **Outbound** | count → sleep until slot → Allow once |
| **FailOpen** / **FailClosed** | after state error: let through / deny-or-503 |

## Wiring

Two wiring shapes. Prefer the **app-owned** shape. The limiter **always**
depends on **valkey-state** (component `Name()`, default `"valkey-state"`).
Valkey is state’s peer, not the limiter’s.

### Golden path (app-owned consumer)

`main` declares valkey + valkey-state + limiter + the app class:

```go
fw := cf.New(&cf.FrameworkOptions{
	Logs:          &cf.LogsSettings{Format: "json", Level: "info", ConfigSource: "logs"},
	Observability: &cf.ObservabilitySettings{Bind: ":9090", ConfigSource: "observability"},
	Components: []cf.CaerusComponent{
		cf_valkey.New(cf_valkey.WithConfigSource("valkey", "config/valkey.json"),
			cf_valkey.WithKeyPrefix("myservice:")),
		cf_valkey_state.New(cf_valkey_state.WithConfigSource("valkey-state", "config/valkey-state.json")),
		cf_http_ratelimiter.New(
			cf_http_ratelimiter.WithConfigSource("http-ratelimiter", "config/http-ratelimiter.json"),
		),
		app.New(),
	},
})
```

The app resolves the **limiter** pointer at `Init` and lists
`cf_http_ratelimiter.ComponentName` in `GetDependencies`. It never lists
`"valkey"` for the limiter’s sake. Logical keys go to `Allow` / `Middleware`;
state builds `rl:` via unexported `rlKey`.

```go
func (a *App) GetDependencies() []string {
	return []string{cf_http_ratelimiter.ComponentName}
}
```

### Simple path — GH App / memory-only (no valkey)

There is **no** `WithoutValkeyPeer` on the limiter. State omits the fridge:

```go
st := cf_valkey_state.New(
	cf_valkey_state.WithoutValkeyPeer(),
	cf_valkey_state.WithForceMemory(true),
	cf_valkey_state.WithUseMemoryFallback(true),
	cf_valkey_state.WithMemoryMapFullPolicy("allow"),
	cf_valkey_state.WithConfigSource("valkey-state", "config/valkey-state.json"),
)
rl := cf_http_ratelimiter.New(
	cf_http_ratelimiter.WithConfigSource("http-ratelimiter", "config/http-ratelimiter.json"),
)
// Components: st, rl, http, app — no valkey
```

`CreateSession` on that state instance errors. Ready can be green (not mixed).

### Simple `main`-level wiring

```go
fw := cf.New()
fw.AddComponent(cf_logs.New(cf_logs.WithWriter(os.Stdout)))
fw.AddComponent(cf_valkey.New(cf_valkey.WithAddress("127.0.0.1:6379")))
fw.AddComponent(cf_valkey_state.New())
fw.AddComponent(cf_http_ratelimiter.New())
```

The limiter is `ConfigSourceRegistrar`-self-sufficient. `OnStoreError` is only
**fail-open** or **fail-closed**. Memory is not a limiter policy.

### Component name vs configuration source name

These are two different strings that happen to match by default. Keep them
apart in your head:

| Concept | Value | Who uses it |
|---|---|---|
| **Component name** | `"http-ratelimiter"` (`ComponentName`) | Framework registry, `GetDependencies`, `Get`/`GetByName`, logs level settings |
| **Config source name** | `"http-ratelimiter"` (from `WithConfigSource`) | File path flag `--http-ratelimiter`, env prefix `HTTP_RATELIMITER_`, `OnConfigReload`'s `source` string |

If you name a limiter instance with `WithName("sessions")`, depend on
`"sessions"` in `GetDependencies` — but keep the source name whatever
`WithConfigSource` says.

## API

### Result

```go
type Result struct {
	Allowed bool          // Count <= limit (only meaningful from Allow/AllowWithPolicy)
	Count   int64         // counter value after this call
	ResetIn time.Duration // time until the window resets (for Retry-After)
}
```

### Allow / Reset / Peek

- **`Allow(ctx, key, limit, window)`** — increments the counter for `key` and
  reports whether `Count <= limit`. Use it for inbound checks you do inside a
  handler (login lockout, register limit) where the middleware's fixed shape
  does not fit. Storage errors are returned to the caller; policy belongs to
  the call site (use `AllowWithPolicy` or the middleware).
- **`Reset(ctx, key)`** — deletes the counter (successful login / admin
  unlock). Missing keys are a no-op (idempotent).
- **`Peek(ctx, key)`** — reads count + remaining TTL without incrementing.
  `Allowed` is always false (there is no limit to compare against). Useful for
  dashboards and pre-flight checks.
- **`Wait(ctx, key, limit, window)`** — blocks until a single `Allow` would
  succeed, then performs that one `Allow`. For **outbound** self-pacing (see
  [Outbound / Wait](#outbound--wait)). Honors `ctx` cancellation.

`limit <= 0` short-circuits every one of these: rate limiting is **off for that
call** — always allowed, no storage access, counted only in
`http_ratelimiter_disabled_total`. It is neither an allow nor a deny; it is
"this call asked for no limit." Alert on it rising in prod: it usually means a
config value (e.g. `loginLimit: 0`) silently disabled the limiter.

### Keys

Keys are logical strings: a prefix plus an opaque identity, e.g.
`"login:" + hex`, `"ip:" + ip`, `"externalapi:rest:42"`. The valkey-state
peer places the valkey `Key()` prefix and an unexported `rl:` segment
underneath, so apps never hardcode full Redis key names.

**Max logical key length is enforced** (default **256 bytes**): empty or
oversized keys are **rejected with an error, never truncated**, and counted in
`http_ratelimiter_key_rejected_empty_total` /
`http_ratelimiter_key_rejected_long_total` **before** any
storage access. 256 bytes comfortably fits `login:` + 64 hex chars
(HMAC-SHA256) or `ip:` + an IPv6 address, and rejects accidental dumps.
Override with `WithMaxKeyLength(n)` or `max_key_length` (reloadable).

## Outbound / Wait

`Wait` is for when **we** are the client (Recipe B — MyAPIRequestor calling ExternalAPIWeCall). It
does **not** spin-increment: it peeks at the counter, sleeps until the window
resets (plus a small jitter to avoid thundering-herd, ~10% capped at 1s by
default), then performs exactly **one** `Allow`. If the context is done it
returns the context error without granting.

```go
key := fmt.Sprintf("externalapi:rest:%d", installationID)
if err := rl.Wait(ctx, key, cfg.ExternalAPI.RESTLimit, time.Minute); err != nil {
	return err // ctx canceled or wait failed
}
// now make the HTTP call to ExternalAPIWeCall; still honor ExternalAPIWeCall's own
// X-RateLimit-* / Retry-After headers in your HTTP client
```

The sleep is **interruptible** (it observes `ctx`), and the pause decision is
fully configurable:

- `WithWaitJitterMax(d)` / `wait_jitter_max_sec: 0` disables jitter
  (deterministic tests);
- `WithWaitDelayFunc(fn)` lets the app decide the sleep — cap it, disable it,
  or abort with an error instead of waiting.

### What sleep is not

| Not this | Reality |
|---|---|
| A way to delay HTTP responses to slow attackers | Return **429**; optional WAF/Ingress |
| Holding a login request open until unlock | Return 429/403; the client retries later |
| Replacing a vendor's own rate-limit sleep | Still read their `Retry-After`/`X-RateLimit-*` after calls; that may sleep in the **outbound client**, separate from this module |

For **inbound** HTTP, never sleep in the handler: answer `429` with a
`Retry-After` header (the middleware does this automatically) so server
goroutines are not held open.

## Storage-error policy

The limiter talks to **valkey-state**. When **that** call already failed
(Valkey and sticky notes both unusable, or memory disabled), the call site
needs a rule:

| Rule | Plain English |
|---|---|
| **`StorageFailOpen`** | "Store failed → let them in anyway." Site stays up; attackers also get in with no limits. |
| **`StorageFailClosed`** | "Store failed → nobody gets in." Safer; real users may see 429/503. |

**`StorageMemoryFallback` is an error.** Valkey vs sticky notes is
`valkey-state.json` → `rate_limit`, not a per-call policy.

**Why "unset" is dangerous:** in Go, `StorageFailOpen` is the zero value of
the enum, so "forgot the field" and "I chose FailOpen" look identical. A
junior can copy middleware, omit `OnStoreError`, and silently ship an unlocked
door. So:

- `Middleware` **errors** if `OnStoreError` is nil (or is MemoryFallback).
- `AllowWithPolicy(ctx, key, limit, window, policy)` **always** takes an
  explicit policy argument — there is no overload that defaults it.

The default `OnDenied` response is plain text: `429` with `Retry-After` set from
`Result.ResetIn` (rounded up, so the client never retries early). A FailClosed
store error answers `503` with `Retry-After: 1` — the limiter itself is down,
not the caller. Provide `OnDenied` for fully custom bodies/status/logging.

**Opt-in (default off):**

| `MiddlewareConfig` field | Default | When set |
|---|---|---|
| `ErrorWriter` | nil (plain `http.Error`) | Pass `problem.ErrorWriter` from `caerus-framework-http/problem` so 429/503 bodies match other `cf_http` middleware (RFC 9457 JSON). Codes: `RATE_LIMIT_EXCEEDED`, `RATE_LIMIT_STORE_UNAVAILABLE`. |
| `RateLimitHeaders` | `false` | Sets `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` (Unix seconds) on allowed **and** denied responses. `Retry-After` is still set on denials. |

```go
import (
	cf_http "github.com/caerus-framework/caerus-framework-http"
	"github.com/caerus-framework/caerus-framework-http/problem"
)

pol := cf_http_ratelimiter.StorageFailOpen
mw, err := cf_http_ratelimiter.Middleware(cf_http_ratelimiter.MiddlewareConfig{
	Limiter:          rl,
	Limit:            30,
	Window:           time.Minute,
	KeyFunc:          ipKeyFunc,
	OnStoreError:     &pol,
	ErrorWriter:      problem.ErrorWriter, // opt-in — not the default
	RateLimitHeaders: true,                // opt-in — not the default
})
```

### `Allow` / `Wait` vs middleware on store errors

These three paths are **intentionally different**. Middleware is HTTP-facing and
forces an explicit policy; direct API callers own their own error handling.

| Path | Store unreachable / error | Who decides |
|---|---|---|
| **`Middleware`** | `OnStoreError` required: FailOpen → request proceeds; FailClosed → **503** (+ optional `ErrorWriter` / headers). | You set `OnStoreError` on `MiddlewareConfig`. |
| **`Allow` / `AllowWithPolicy`** | Returns `(Result{}, err)` — raw store error. Policy only applies when you call `AllowWithPolicy` (FailOpen → `Allowed: true`; FailClosed → error). | Handler / outbound client inspects `err` and `res.Allowed`. |
| **`Wait` / `WaitOpts`** | Returns `error` immediately on peek or allow failure — **does not sleep through** store outages. | Caller retries or backs off; no built-in FailOpen/FailClosed on `Wait` today. |

Wrong vs right:

```text
Wrong: "Wait will fail-open like middleware when Valkey is down."
Right: Wait returns err — use middleware for inbound HTTP; use AllowWithPolicy
       in handlers; use Wait only when your caller can handle store errors.

Wrong: "Allow without WithPolicy is safe when the store fails."
Right: Allow returns the raw err — use AllowWithPolicy with an explicit policy
       when store failure must map to allow/deny.
```

## Config and options

### Config (`config/http-ratelimiter.json`)

Module settings — file/env/flags drive these; per-call limits and windows stay
caller-supplied (the app owns its own policy on its own config source).

| Field | Env | Default | Meaning |
|---|---|---|---|
| `metrics_enabled` | `HTTP_RATELIMITER_METRICS_ENABLED` | `true` | `Metrics()` returns `nil` when false (pointer so "omitted" ≠ "off") |
| `hash_ip_keys` | `HTTP_RATELIMITER_HASH_IP_KEYS` | `false` | app-facing toggle: apps should HMAC IPs in `KeyFunc` when true (see Key material) |
| `max_key_length` | `HTTP_RATELIMITER_MAX_KEY_LENGTH` | `256` | max logical key bytes; oversize is rejected, never truncated |
| `wait_jitter_max_sec` | `HTTP_RATELIMITER_WAIT_JITTER_MAX_SEC` | ~10% of reset, capped 1s | max extra `Wait` sleep; `0` disables jitter |

Counter memory, `force_memory`, map-full, and missing-TTL live on
**valkey-state** (`rate_limit`), not here.

Tunables reload live (`OnConfigReload`). There is **no** connection rebuild —
the valkey peer owns client rotation; state owns the store.

### Options

| Option | Description |
|---|---|
| `WithConfig(Config)` | static config snapshot; non-zero fields override option-set defaults |
| `WithConfigSource(name, path, …)` | bind a configuration source (registers it via `ConfigSourceRegistrar`; declares a `configuration` dep). `WithSourceEnvPrefix`, `WithSourceFormat` available |
| `WithName(name)` | custom component name for multiple instances (default `"http-ratelimiter"`) |
| `WithStateName(name)` | bind to a valkey-state component with the given name (default `"valkey-state"`) |
| `WithLogger(*slog.Logger)` | explicit logger override; defaults to the framework `logs` component logger (re-delivered on `logs` `Reconfigure`), falling back to `slog.Default()` |
| `WithMaxKeyLength(n)` | maximum logical key bytes (default `256`) |
| `WithMetricsEnabled(bool)` | toggle the metrics catalogue (default on) |
| `WithWaitJitterMax(d)` | cap `Wait` jitter (default `1s`); `0` disables |
| `WithWaitDelayFunc(fn)` | app-supplied pause/abort decision for `Wait` |

Default `EnvPrefix` is `HTTP_RATELIMITER_` (from the source name). `main`
declares the limiter with `WithConfigSource` and runs `RunWithSignals` — no
`Getenv`, no `ParseFlags`.

## Key material

Keys must not carry raw PII when avoidable. HMAC-SHA256 your identity before
building the key — this module ships the helper so apps do not reinvent it:

```go
h, err := cf_http_ratelimiter.NewKeyHasher(secret) // secret is app-owned (pepper / rate_limit_key_secret)
if err != nil {
	return err
}
loginKey := "login:" + h.Hash(normalizedEmail) // emails are ALWAYS hashed by convention
```

| Identity | Default | Configurable |
|---|---|---|
| Emails / usernames (login lockout) | **Always hash** (`login:` + 64 hex) | secret from app config |
| IPs (middleware `KeyFunc`) | Plain IP for ops debugging (`ip:203.0.113.4`) | `hash_ip_keys: true` → hash the same way |
| Installation IDs / non-PII (MyAPIRequestor → ExternalAPIWeCall) | Plain OK (`externalapi:rest:42`) | hash optional |

**`hash_ip_keys` does not auto-hash.** The module stores the flag and exposes
`RateLimiter.HashIPKeys()` so your app config can read it — but **your
`KeyFunc` must call `KeyHasher.Hash` (or `HashKey`) when the flag is true.
Middleware never reads client headers for you.

Wrong vs right:

```text
Wrong: set "hash_ip_keys": true in http-ratelimiter.json and expect middleware
       to HMAC RemoteAddr automatically.

Right: read hash_ip_keys (or your app copy of it) inside KeyFunc:
       if hash { return "ip:" + hasher.Hash(ip) }; return "ip:" + ip
```

**Never log secrets or pre-hash identities.** After hashing, keys stay short
and fit the default 256-byte `MaxKeyLength`.

## Starter recipes

These are the two shapes, in plain language:

| Recipe character | What it is | Direction |
|---|---|---|
| **MyService** | A made-up service that **receives** HTTP requests from browsers/clients (login, register, …) — *an app that accepts requests* (you are the server) | **Inbound** — middleware + handler `Allow`/`Reset` |
| **MyAPIRequestor** | A made-up worker **we run** that **calls out** to some external HTTP API — *an app we call from* / *our process calling someone else* (you are the client for the paced calls). The external API here is a dummy named **ExternalAPIWeCall** — not a real vendor brand | **Outbound** `Wait`/`Allow` when we call others; optional inbound webhook middleware |

**MyAPIRequestor is not ExternalAPIWeCall. MyAPIRequestor is the Caerus app. ExternalAPIWeCall is whoever we call.**

Numbers below are sensible first values, not sacred — tune from metrics.

### Recipe A — MyService (receives requests; K8s, Valkey + Echo)

MyService is a login/account HTTP API. Clients hit `/api/session/*`. We blunt IP
floods, lock accounts after bad passwords, and stay up if Valkey blips.

| Call site | Policy to start with | Why |
|---|---|---|
| IP middleware on public `/api/session/*` | **`StorageFailOpen`** | prefer taking logins over 503ing everyone when Valkey is down |
| Register | **`StorageFailOpen`** | same availability bias |
| Login lockout | **`StorageFailClosed`** (enable sticky notes on **valkey-state** `rate_limit` if you still want a per-pod cap when Valkey blips) | key = `login:` + **HMAC hash of email** (never raw email in Valkey) |
| Map full (fallback) | **explicit** `allow` or `deny` | no silent default |
| On success | **`Reset` the same hashed key** | clear the counter so a successful user is not half-locked |
| IP keys | plain or hashed | start plain for ops; set `hash_ip_keys: true` when Valkey is shared / privacy-sensitive |

`config/http-ratelimiter.json` (HTTP leftovers):

```json
{
  "metrics_enabled": true,
  "hash_ip_keys": false,
  "max_key_length": 256
}
```

`config/valkey-state.json` (counter store — start here for memory):

```json
{
  "rate_limit": {
    "use_memory_fallback": true,
    "force_memory": false,
    "memory_max_entries": 10000,
    "memory_map_full_policy": "allow"
  }
}
```

MyService's own product policy on its own config source (not this component config. Developer invents own for his own app component) (illustrative —
`config/myservice.json`):

```json
{
  "rateLimit": {
    "loginLimit": 5,
    "loginWindowMinutes": 15,
    "registerLimit": 5,
    "registerWindowMinutes": 60,
    "ipLimit": 30,
    "ipWindowSeconds": 60
  },
  "rateLimitPolicies": {
    "ipOnStoreError": "fail_open",
    "loginOnStoreError": "fail_closed",
    "hashIpKeys": false
  },
  "rateLimitKeySecret": "(from secret mount — HMAC key for login/IP hashing)"
}
```

Wiring sketch (Echo) — IP group. For problem JSON + headers, add
`ErrorWriter: problem.ErrorWriter` and `RateLimitHeaders: true` (both opt-in):

```go
pol := cf_http_ratelimiter.StorageFailOpen
stdMW, err := cf_http_ratelimiter.Middleware(cf_http_ratelimiter.MiddlewareConfig{
	Limiter: a.rl,
	Limit:   cfg.RateLimit.IPLimit, // e.g. 30
	Window:  time.Duration(cfg.RateLimit.IPWindowSeconds) * time.Second,
	KeyFunc: func(r *http.Request) string {
		ip := realIP(r) // trusted IP only
		if cfg.RateLimitPolicies.HashIPKeys {
			return "ip:" + a.keyHasher.Hash(ip)
		}
		return "ip:" + ip
	},
	OnStoreError: &pol, // required — Middleware errors if nil
})
if err != nil {
	return err
}
public := e.Group("/api/session", echo.WrapMiddleware(stdMW))
```

Login lockout inside the handler — **always hash email**; pass
`StorageFailClosed` (not `memory_fallback` — memory is on valkey-state):

```go
loginKey := "login:" + a.keyHasher.Hash(normalizedEmail)
res, err := a.rl.AllowWithPolicy(ctx, loginKey,
	int64(cfg.RateLimit.LoginLimit),
	time.Duration(cfg.RateLimit.LoginWindowMinutes)*time.Minute,
	cf_http_ratelimiter.StorageFailClosed,
)
if err != nil {
	// log it; the policy already decided what to do
}
if !res.Allowed {
	return echo.NewHTTPError(http.StatusTooManyRequests, "temporarily locked")
}
// … verify password …
if success {
	_ = a.rl.Reset(ctx, loginKey)
}
```

Give the **valkey** peer `WithKeyPrefix("myservice:")` on `caerus-framework-valkey`
(not the limiter) so state keys look like `myservice:rl:login:<hex>` — no raw
email in the keyspace. There is **no** limiter `key_prefix` setting; prefixing
is the valkey component's job.

### Routers — no stock adapters (Echo, Gin, chi, stdlib)

This module ships **stdlib** `func(http.Handler) http.Handler` only. There is
no `Echo()`, `Gin()`, or `Chi()` helper in the repo — same policy as
`caerus-framework-http` (see that module's router examples). Wrap once in your
app:

| Router | Wrap pattern |
|---|---|
| **stdlib / chi** | Use middleware directly: `r.Use(rateMW)` — chi accepts stdlib middleware. |
| **Echo** | `e.Use(echo.WrapMiddleware(rateMW))` or `e.Group("/api", echo.WrapMiddleware(rateMW))` |
| **Gin** | `r.Use(gin.WrapH(rateMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))))` — or apply on a route group the same way as other `cf_http` middleware |

Wrong vs right:

```text
Wrong: wait for cf_http_ratelimiter.Echo() in the limiter module.

Right: build Middleware(...) once, wrap with your router's stdlib adapter —
       identical to how cf_http RequestID / Recover are wired.
```

### Recipe B — MyAPIRequestor (we call out; K8s webhook + outbound client)

MyAPIRequestor is **our** background/HTTP service. It exposes `POST /hooks/events` for
an upstream to notify us, and then **our code calls an external HTTP API**
(dummy name: **ExternalAPIWeCall**) to do something over external service via their API / sync state. Rate limiting is mostly:
(1) protect the webhook, (2) **pace our outbound calls** with `Wait` so we do
not stampede ExternalAPIWeCall.

| Call site | Policy to start with | Why |
|---|---|---|
| `POST /hooks/events` middleware | **`StorageFailClosed`** (429 or 503 + Retry-After) | not end-user UX; upstream can retry; do not fail-open into the worker |
| Outbound ExternalAPIWeCall REST self-pace | `Wait`/`Allow` | **we** are the client — sleep/jitter until our ceiling allows another call |
| Local dry-run CLI | **Recipe C** (no valkey peer) | state `WithoutValkeyPeer` + `rate_limit` memory |
| Map full | **explicit** `allow` or `deny` on **valkey-state** | raise `memory_max_entries` if needed |

`config/http-ratelimiter.json`:

```json
{
  "metrics_enabled": true
}
```

`config/valkey-state.json`:

```json
{
  "rate_limit": {
    "use_memory_fallback": true,
    "force_memory": false,
    "memory_max_entries": 5000,
    "memory_map_full_policy": "allow"
  }
}
```

`config/myapirequestor.json` (product — illustrative):

```json
{
  "webhook": {
    "ipLimit": 120,
    "ipWindowSeconds": 60,
    "onStoreError": "fail_closed"
  },
  "externalApi": {
    "restLimit": 80,
    "restWindowSeconds": 60
  }
}
```

Webhook middleware (stdlib `ServeMux` / `cf_http` handler chain):

```go
closed := cf_http_ratelimiter.StorageFailClosed
rateMW, err := cf_http_ratelimiter.Middleware(cf_http_ratelimiter.MiddlewareConfig{
	Limiter: rl,
	Limit:   cfg.Webhook.IPLimit, // e.g. 120/min per trusted IP
	Window:  time.Minute,
	KeyFunc: func(r *http.Request) string { return "hook:ip:" + remoteIP(r) },
	OnStoreError: &closed, // required — errors if nil
})
if err != nil {
	return err
}
h := rateMW(webhookHandler)
// Order: MaxBytes → rate limit → HMAC verify → enqueue work
```

Outbound self-pace **inside our ExternalAPIWeCall client** (calls we make):

```go
// installationID = which ExternalAPIWeCall install we talk to — still our key material
key := fmt.Sprintf("externalapi:rest:%d", installationID)
if err := rl.Wait(ctx, key, cfg.ExternalAPI.RESTLimit, time.Minute); err != nil {
	return err // ctx canceled or wait failed
}
// then the HTTP call to ExternalAPIWeCall; still honor ExternalAPIWeCall's own rate-limit headers on the response
```

**One wave at a time is not this module.** Rate limits are "how often"; locks
are "who owns the wave." If you need a single wave to run at a time, use a
lock/lease, not the limiter.

### Recipe C — Local / CI (memory-only, without Valkey)

When the process has **no** valkey component, omit it on **valkey-state**, not
on the limiter:

```go
st := cf_valkey_state.New(
	cf_valkey_state.WithoutValkeyPeer(),
	cf_valkey_state.WithForceMemory(true),
	cf_valkey_state.WithUseMemoryFallback(true),
	cf_valkey_state.WithMemoryMapFullPolicy("allow"),
	cf_valkey_state.WithConfigSource("valkey-state", "config/valkey-state.json"),
)
rl := cf_http_ratelimiter.New(
	cf_http_ratelimiter.WithConfigSource("http-ratelimiter", "config/http-ratelimiter.json"),
)
```

Wrong: omit valkey from `Components` but leave state’s default valkey
dependency — `Validate` fails. Right: state’s `WithoutValkeyPeer` +
`rate_limit.use_memory_fallback=true` + explicit map-full policy. Do **not**
use memory-only as the sole backend for multi-replica MyService in production.

**Break-glass with Valkey wired but dead — not automatic.**  
By default Valkey Init is **hard**: unreachable store → that component’s Init
fails → the whole process does not finish Initialize. Nothing “auto-enables”
DegradedMode or `force_memory`. You must turn them on on purpose.

1. **Valkey** — allow Init without a live ping (`degraded_mode`).  
2. **valkey-state** — sticky-note primary when `Client()` is nil (`force_memory`),
   and usually enable the sticky engine (`use_memory_fallback`). Mixed processes
   (sessions + rate limit on one valkey) keep `/readyz` red unless you
   deliberately set `health_when_degraded: ready` on a **dedicated** instance.

`config/valkey.json`:

```json
{
  "addr": "valkey:6379",
  "degraded_mode": true,
  "health_when_degraded": "not_ready"
}
```

`config/valkey-state.json` (same process):

```json
{
  "rate_limit": {
    "use_memory_fallback": true,
    "force_memory": true,
    "memory_map_full_policy": "deny"
  }
}
```

Watch state’s memory / lame-mode metrics plus Valkey `degraded_mode` /
`degraded_unreachable` / `degraded_mode_uses_total`.

**Hot reload can save the day sometimes.** State and valkey reload from their
config sources (file change / `Reload` / SIGHUP — env alone does not wake a
running process). Ops can flip `rate_limit` switches and Valkey reconnect
settings live when the mounted file updates. That is often enough to ride out
a Valkey blip or walk back break-glass without a new image. It does **not**
replace a correct first deploy: if Valkey was hard-Init and never came up,
there was no process left to reload — you needed `degraded_mode` (or Recipe C)
already on for Initialize to finish.

## Middleware

```go
func Middleware(cfg MiddlewareConfig) (func(http.Handler) http.Handler, error)
```

`MiddlewareConfig` requires `Limiter`, `Window > 0`, a `KeyFunc`, and
`OnStoreError` (see [Storage-error policy](#storage-error-policy)). `Limit <= 0`
disables rate limiting for this middleware. Optional: `ErrorWriter` (RFC 9457
JSON via `problem.ErrorWriter`), `RateLimitHeaders`, `OnDenied`. The returned
middleware never sleeps: it answers immediately on denial.

**KeyFunc must use a trusted client identity.** Do not invent a clever
`X-Forwarded-For` parser here — use identity your ingress/mesh already
normalized (e.g. Echo `RealIP()` behind a correct proxy contract, or a mesh
header you trust). `RemoteAddrKey` strips the port from `r.RemoteAddr` and is a
footnote helper for local demos only, not production truth behind a load
balancer.

For GitHub-style webhooks, if you intend to throttle *abusers*, key on the
remote IP behind the ingress — **not** `X-GitHub-Delivery` (that header is for
idempotency/dedupe of a single delivery, a different concern).

## Metrics / health

`Health` reports unhealthy before `Init` and after `Shutdown`; after `Init` it
delegates to the valkey-state peer. `Metrics` returns `nil` when not
initialized (lazy pattern) or when `metrics_enabled: false`.

Common labels on all series: `component` (= `Name()`), `state` (= peer
`Name()`). Low-cardinality labels only — never raw keys, IPs, or emails.
Store-path gauges (memory vs Valkey) live on **valkey-state**.

| Name | Type | Extra labels | Meaning |
|---|---|---|---|
| `http_ratelimiter_info` | gauge (0/1) | — | 1 while initialized |
| `http_ratelimiter_allows_total` | counter | — | `Allow` / successful `Wait` grant (Allowed=true) |
| `http_ratelimiter_denies_total` | counter | — | Allowed=false (over limit) |
| `http_ratelimiter_resets_total` | counter | — | `Reset` calls |
| `http_ratelimiter_peeks_total` | counter | — | `Peek` calls |
| `http_ratelimiter_storage_errors_total` | counter | — | errors from valkey-state before FailOpen/FailClosed |
| `http_ratelimiter_fail_open_total` | counter | — | store error treated as allowed |
| `http_ratelimiter_fail_closed_total` | counter | — | store error returned to the caller |
| `http_ratelimiter_disabled_total` | counter | — | `limit <= 0` (limiter off for that call) |
| `http_ratelimiter_key_rejected_empty_total` | counter | — | empty logical key |
| `http_ratelimiter_key_rejected_long_total` | counter | — | logical key too long |

Alert on `http_ratelimiter_disabled_total` rising: it means something calls
`Allow` with `limit <= 0` (see the API section).

## Tests

Unit tests cover the component contract, key validation, `Wait`, middleware
validation/policy paths, and the metrics catalogue — no external service.
Counter Lua / sticky-note math lives in valkey-state tests. Integration tests
are gated on `VALKEY_ADDR`:

```bash
docker run -d --rm -p 6379:6379 --name v valkey/valkey:8
VALKEY_ADDR=127.0.0.1:6379 go test -race ./...
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
