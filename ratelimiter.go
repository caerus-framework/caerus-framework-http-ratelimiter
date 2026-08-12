// Package cf_http_ratelimiter is the Caerus Framework HTTP rate limiter
// component. It is an HTTP-plane helper: apps use it from middleware and
// handlers to count attempts ("this client / email / action has tried too many
// times") in a shared store and answer allow/deny plus "try again in N
// seconds". It is not a second HTTP server and it is not a router (no
// Echo/Gin/chi dependency).
//
// The same counter API is useful outside middleware too — e.g. a background
// worker calling Allow / Wait before bursts of outbound REST calls (see Wait).
package cf_http_ratelimiter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cf "github.com/caerus-framework/caerus-framework"
	cf_configuration "github.com/caerus-framework/caerus-framework-configuration"
	cf_logs "github.com/caerus-framework/caerus-framework-logs"
	cf_observability "github.com/caerus-framework/caerus-framework-observability"
	cf_valkey "github.com/caerus-framework/caerus-framework-valkey"
	"github.com/valkey-io/valkey-go"
)

const (
	// ComponentName is the framework component name for the http-ratelimiter
	// component. It is the identifier other components use in GetDependencies
	// to require it, and it also matches the default configuration source name
	// so files, env prefixes and flags line up ("http-ratelimiter",
	// config/http-ratelimiter.json, HTTP_RATELIMITER_, --http-ratelimiter).
	ComponentName = "http-ratelimiter"

	// ComponentStage is the stage data-layer components initialize in.
	ComponentStage = cf.Stage("data")
)

// Defaults for module settings. Limits and windows are caller-supplied per call;
// these are module-level tunables only.
const (
	// defaultKeyPrefix is the logical prefix the component puts between the
	// valkey peer's own key prefix and the caller's key. With a peer prefix of
	// "portal:" the full key becomes portal:rl:login:<hex>.
	defaultKeyPrefix = "rl"

	// defaultMaxKeyLength is the maximum byte length of the logical key passed
	// to Allow/Reset/Peek/Wait. Oversized keys are rejected, never truncated.
	defaultMaxKeyLength = 256

	// defaultMemoryMaxEntries is the hard cap on distinct keys in the
	// in-process map (force_memory / use_memory_fallback / MemoryFallback share one map).
	defaultMemoryMaxEntries = 10000

	// defaultWaitJitterMax caps the random extra sleep Wait adds to ResetIn.
	// Wait jitters ~10% of ResetIn up to this cap, so many workers do not wake
	// at the same millisecond. 0 disables jitter (deterministic tests).
	defaultWaitJitterMax = time.Second

	// defaultMetricsEnabled is the metrics_enabled default: metrics are on
	// while the component is initialized.
	defaultMetricsEnabled = true

	// luaAllow is an atomic fixed-window counter: INCR, set the expiry only on
	// the first increment (so a key never leaks without a TTL), then return the
	// count and the remaining time in the window.
	luaAllow = `local n = redis.call("INCR", KEYS[1])
if n == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return {n, redis.call("PTTL", KEYS[1])}`

	// luaPeek reads the counter and TTL without incrementing. A missing key
	// reports count 0, reset-in 0.
	luaPeek = `local c = redis.call("GET", KEYS[1])
local t = redis.call("PTTL", KEYS[1])
if not c then
  return {0, 0}
end
return {tonumber(c), t}`
)

// ErrMissingTTL is returned when a Valkey counter exists with count > 0 but no
// usable TTL (PTTL <= 0), after the key was scrubbed, and wait_missing_ttl_policy
// (or a WaitOptions override) is "error".
var ErrMissingTTL = errors.New("cf_http_ratelimiter: counter missing TTL")

// ErrMemoryFallbackDisabled is returned when a call site asks for
// StorageMemoryFallback but the component's use_memory_fallback capability is off.
var ErrMemoryFallbackDisabled = errors.New("cf_http_ratelimiter: StorageMemoryFallback requires use_memory_fallback=true")

// Result reports the outcome of an Allow or Peek call.
type Result struct {
	// Allowed is true when Count does not exceed the limit for the window.
	// From Peek it is always false: Peek has no limit to compare against.
	Allowed bool
	// Count is the (incremented, for Allow) request count within the window.
	Count int64
	// ResetIn is the time remaining until the window resets (for Retry-After).
	ResetIn time.Duration
}

// StorageErrorPolicy selects what happens when the primary store (Valkey)
// errors or is unavailable. It is the main safety switch for "Valkey is dead —
// what now?" and must be set explicitly per call site (AllowWithPolicy always
// takes one; Middleware errors if OnStoreError is unset). There is no silent
// FailOpen.
type StorageErrorPolicy int

const (
	// StorageFailOpen treats a store error as allowed. Site stays up;
	// attackers also get in with no limits. Typical for IP middleware on login
	// routes where availability wins.
	StorageFailOpen StorageErrorPolicy = iota
	// StorageFailClosed treats a store error as denied / returns an error.
	// Safer; real users may see 429/503 until the store is back. Typical for
	// webhook intake where failing open would feed an attacker.
	StorageFailClosed
	// StorageMemoryFallback uses the process-local memory limiter for that
	// call. Still some limits, only on this one server. Requires use_memory_fallback=true
	// on the component. Typical for login lockout where a coarse in-process
	// ceiling is better than none.
	StorageMemoryFallback
)

// MapFullPolicy is the "fallback/memory map hit its max distinct keys" policy.
// On MemoryFallbackConfig, the zero value (MapFullAllow) means "inherit the
// component's required memory_map_full_policy". After resolve, MapFullAllow
// allows the call without counting and MapFullDeny rejects it.
type MapFullPolicy int

const (
	// MapFullAllow allows a new key without counting when the map is full.
	// On MemoryFallbackConfig, the zero value also means "inherit component".
	MapFullAllow MapFullPolicy = iota
	// MapFullDeny rejects Allow for a new key when the cap is reached.
	MapFullDeny
)

// MissingTTLPolicy selects what happens after scrubbing a counter that has
// count > 0 but no usable TTL. It must be set explicitly on the component
// (wait_missing_ttl_policy); WaitOptions may override per call.
type MissingTTLPolicy int

const (
	// MissingTTLProceed continues after delete: Allow re-runs once; Wait does
	// not sleep and proceeds to Allow once; Peek returns an empty Result.
	MissingTTLProceed MissingTTLPolicy = iota + 1
	// MissingTTLError returns ErrMissingTTL after delete.
	MissingTTLError
)

// MemoryFallbackConfig sizes the in-process memory limiter used by the
// StorageMemoryFallback policy and by force_memory / memory-only mode. Zero
// fields fall back to the component's configured values; when those are also
// zero, the call's own limit/window are used.
type MemoryFallbackConfig struct {
	// MaxEntries is a hard cap on distinct keys. 0 uses the component's
	// configured memory_max_entries.
	MaxEntries int
	// WhenMapFull is the policy when a new key would exceed MaxEntries.
	// MapFullAllow (zero value) uses the component's configured
	// memory_map_full_policy; MapFullDeny always denies.
	WhenMapFull MapFullPolicy
	// Limit is an optional coarser ceiling when running on fallback only.
	// 0 uses the call's limit (or the component's memory_fallback_limit).
	Limit int64
	// Window is an optional coarser window when running on fallback only.
	// 0 uses the call's window (or the component's memory_fallback_window_sec).
	Window time.Duration
}

// WaitDelayFunc is called when Wait must pause before retrying Allow. base is
// the reset-in from the store (Peek/Allow); jittered is base plus the built-in
// jitter (if enabled). Return the duration to sleep (may be 0), or an error to
// abort Wait. A nil function sleeps jittered (or base when jitter is disabled)
// with ctx.
type WaitDelayFunc func(ctx context.Context, key string, base, jittered time.Duration) (sleep time.Duration, err error)

// WaitOptions overrides Wait behaviour for a single call. Nil pointer fields
// inherit the component defaults.
type WaitOptions struct {
	// MissingTTLPolicy overrides wait_missing_ttl_policy when non-nil.
	MissingTTLPolicy *MissingTTLPolicy
	// DelayFunc overrides the component WaitDelayFunc when non-nil. A non-nil
	// function that is itself nil-valued is not expressible; omit to inherit.
	DelayFunc WaitDelayFunc
	// delayFuncSet is true when DelayFunc was intentionally provided (including
	// a nil func to force the built-in jitter path). Set by WaitOpts helpers.
	delayFuncSet bool
}

// MiddlewareConfig configures the stdlib Middleware. OnStoreError is required
// (use a pointer so zero does not silently mean FailOpen); Middleware errors
// when it is nil — choosing this module means tuning store-error policy.
type MiddlewareConfig struct {
	// Limiter is the component instance. Required.
	Limiter *RateLimiter
	// Limit is the number of calls allowed per Window for each key. <= 0
	// disables rate limiting for this middleware (every call allowed).
	Limit int64
	// Window is the fixed window duration. Must be > 0.
	Window time.Duration
	// KeyFunc extracts the logical key from the request (e.g. a trusted IP,
	// "ip:"+ip). Required — do not invent a clever X-Forwarded-For parser
	// here; use identity your ingress/mesh already normalized.
	KeyFunc func(*http.Request) string
	// OnStoreError is the storage-error policy. Required.
	OnStoreError *StorageErrorPolicy
	// Memory sizes the memory fallback when OnStoreError == StorageMemoryFallback.
	// Wired into AllowWithPolicyOpts so per-route overrides apply.
	Memory MemoryFallbackConfig
	// OnDenied, when set, is called instead of the default 429/503 response.
	// status is http.StatusTooManyRequests for an over-limit denial, or
	// http.StatusServiceUnavailable for a FailClosed store error. Use it for
	// custom bodies, status codes, or logging.
	OnDenied func(w http.ResponseWriter, r *http.Request, res Result, status int)
}

// Config is the file/env-drivable module configuration. It holds module settings
// (key prefix, metrics, memory sizing, max key length, wait jitter) — not the
// per-call limits and windows, which stay caller-supplied (auth / gh-app keep
// their own policy on their own config sources).
type Config struct {
	// KeyPrefix is an extra logical prefix under the valkey peer's Key().
	// Example: peer prefix "auth:" + module prefix "rl" → auth:rl:<key>.
	// Default "rl".
	KeyPrefix string `json:"key_prefix,omitempty" yaml:"key_prefix,omitempty" env:"KEY_PREFIX"`
	// MetricsEnabled — pointer so "omitted" (default on) and an explicit false
	// are distinct. When false, Metrics() returns nil.
	MetricsEnabled *bool `json:"metrics_enabled,omitempty" yaml:"metrics_enabled,omitempty" env:"METRICS_ENABLED"`
	// UseMemoryFallback enables the sticky-note (in-process map) engine. Off → never
	// count in-process (MemoryFallback is illegal). Required true when the
	// process omits a valkey peer (WithoutValkeyPeer).
	UseMemoryFallback *bool `json:"use_memory_fallback,omitempty" yaml:"use_memory_fallback,omitempty" env:"USE_MEMORY_FALLBACK"`
	// ForceMemory is break-glass: use sticky notes even when Valkey is missing
	// a live client at Init, and prefer the memory path at runtime while set.
	// Pair with DegradedMode on the valkey component when Valkey is wired but
	// may be down at start. When both ForceMemory and UseMemoryFallback are on and
	// Valkey is healthy, lame_memory_mode screams.
	ForceMemory *bool `json:"force_memory,omitempty" yaml:"force_memory,omitempty" env:"FORCE_MEMORY"`
	// MemoryMaxEntries caps distinct keys in the in-process map. Default 10000.
	MemoryMaxEntries int `json:"memory_max_entries,omitempty" yaml:"memory_max_entries,omitempty" env:"MEMORY_MAX_ENTRIES"`
	// MemoryFallbackLimit is the optional coarser limit used when a call site
	// chooses StorageMemoryFallback. 0 → the call's own limit.
	MemoryFallbackLimit int64 `json:"memory_fallback_limit,omitempty" yaml:"memory_fallback_limit,omitempty" env:"MEMORY_FALLBACK_LIMIT"`
	// MemoryFallbackWindowSec is the optional coarser window (seconds) used
	// when a call site chooses StorageMemoryFallback. 0 → the call's own window.
	MemoryFallbackWindowSec float64 `json:"memory_fallback_window_sec,omitempty" yaml:"memory_fallback_window_sec,omitempty" env:"MEMORY_FALLBACK_WINDOW_SEC"`
	// MemoryMapFullPolicy must be "allow" or "deny" whenever use_memory_fallback or
	// force_memory is true (Init/reload fails otherwise). When both are false
	// the field may be empty (map unused).
	MemoryMapFullPolicy string `json:"memory_map_full_policy,omitempty" yaml:"memory_map_full_policy,omitempty" env:"MEMORY_MAP_FULL_POLICY"`
	// WaitMissingTTLPolicy must be "proceed" or "error" at Init. After scrubbing
	// a counter with count > 0 and no TTL: proceed continues (Allow once /
	// empty Peek); error returns ErrMissingTTL.
	WaitMissingTTLPolicy string `json:"wait_missing_ttl_policy,omitempty" yaml:"wait_missing_ttl_policy,omitempty" env:"WAIT_MISSING_TTL_POLICY"`
	// HashIPKeys is a documented toggle for apps: when true, apps should HMAC
	// IPs in their KeyFunc (the KeyHasher helper is provided). The component
	// exposes it via HashIPKeys(); it does not rewrite keys itself, because the
	// HMAC secret is app-owned. Emails/account ids are always hashed by
	// convention in the recipes.
	HashIPKeys *bool `json:"hash_ip_keys,omitempty" yaml:"hash_ip_keys,omitempty" env:"HASH_IP_KEYS"`
	// MaxKeyLength is the maximum byte length of the logical key (default 256).
	// 0 after load means "use the default", not unlimited — use the option or
	// config explicitly for a higher cap.
	MaxKeyLength int `json:"max_key_length,omitempty" yaml:"max_key_length,omitempty" env:"MAX_KEY_LENGTH"`
	// WaitJitterMaxSec caps the random extra sleep Wait adds to ResetIn.
	// 0 disables jitter. Omitted → the built-in default (~10% of ResetIn capped
	// at 1s).
	WaitJitterMaxSec *float64 `json:"wait_jitter_max_sec,omitempty" yaml:"wait_jitter_max_sec,omitempty" env:"WAIT_JITTER_MAX_SEC"`
}

// Option configures the rate limiter at construction time.
type Option func(*options)

type options struct {
	loaded       *Config // set by WithConfig; overrides option-set defaults
	configSource string  // named configuration source for live reload
	configPath   string  // source file path (module self-registration)
	srcEnvPrefix string  // source env overlay prefix (default: NAME_)
	srcFormat    cf_configuration.Format
	srcFormatSet bool
	name         string // custom component name; empty means use ComponentName
	valkeyName   string // valkey peer component name; empty means ComponentName
	logger       *slog.Logger
	loggerSet    bool // true when WithLogger was called explicitly

	requireValkey     bool // false when WithoutValkeyPeer; default true
	useMemoryFallback *bool
	forceMemory       *bool

	keyPrefix            string
	maxKeyLength         int
	memoryMaxEntries     int
	memoryMapFullPolicy  string
	waitMissingTTLPolicy string
	metricsEnabled       bool
	hashIPKeys           bool
	waitJitterMax        time.Duration
	waitDelayFunc        WaitDelayFunc
}

// SourceOption configures the self-registered configuration source created by
// WithConfigSource.
type SourceOption func(*sourceOptions)

type sourceOptions struct {
	envPrefix string
	format    cf_configuration.Format
	formatSet bool
}

// WithSourceEnvPrefix sets the environment overlay prefix for the source
// (default: the uppercase source name with "-" replaced by "_", plus "_").
// An empty prefix disables env overlay.
func WithSourceEnvPrefix(prefix string) SourceOption {
	return func(o *sourceOptions) { o.envPrefix = prefix }
}

// WithSourceFormat forces the file format instead of inferring it from the
// path extension (".yaml"/".yml" → YAML; anything else JSON).
func WithSourceFormat(f cf_configuration.Format) SourceOption {
	return func(o *sourceOptions) { o.format = f; o.formatSet = true }
}

// defaultSourceEnvPrefix derives an environment prefix from a source name.
func defaultSourceEnvPrefix(name string) string {
	return strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_"
}

// WithConfig sets a static configuration snapshot. Non-zero fields of cfg
// override the values set by the convenience options. Prefer WithConfigSource
// when using caerus-framework-configuration with hot-reload.
func WithConfig(cfg Config) Option {
	return func(o *options) { o.loaded = &cfg }
}

// WithConfigSource binds this component to a named configuration source and
// registers that source with the configuration component (via the framework's
// ConfigSourceRegistrar pass during argv absorption). Declares a dependency
// on "configuration".
func WithConfigSource(name, path string, opts ...SourceOption) Option {
	return func(o *options) {
		so := sourceOptions{envPrefix: defaultSourceEnvPrefix(name)}
		for _, opt := range opts {
			opt(&so)
		}
		o.configSource = name
		o.configPath = path
		o.srcEnvPrefix = so.envPrefix
		o.srcFormat = so.format
		o.srcFormatSet = so.formatSet
	}
}

// WithName sets a custom component name, allowing multiple rate-limiter
// instances in the same process. The default name is "http-ratelimiter"
// (ComponentName). Retrieve named instances with
// GetByName[*cf_http_ratelimiter.RateLimiter](fw, "sessions").
func WithName(name string) Option {
	return func(o *options) { o.name = name }
}

// WithValkeyName binds the limiter to a valkey component with the given name
// (WithName on the valkey side). The default is the valkey ComponentName
// ("valkey").
func WithValkeyName(name string) Option {
	return func(o *options) { o.valkeyName = name }
}

// WithLogger overrides the logger used for component diagnostics. By default
// the component logs through the framework logs component (declared in
// GetDependencies); WithLogger is an explicit override for tests and embedded
// use and wins over the framework logger. slog.Default() remains the fallback
// only when neither is available.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) { o.logger = logger; o.loggerSet = true }
}

// WithKeyPrefix sets the logical key prefix placed between the valkey peer's
// own key prefix and the caller's key (default "rl"). A trailing ":" is
// trimmed.
func WithKeyPrefix(prefix string) Option {
	return func(o *options) { o.keyPrefix = strings.TrimSuffix(prefix, ":") }
}

// WithMaxKeyLength sets the maximum byte length of the logical key (default
// 256). Oversized keys are rejected with an error, never truncated.
func WithMaxKeyLength(n int) Option {
	return func(o *options) { o.maxKeyLength = n }
}

// WithUseMemoryFallback enables or disables the sticky-note engine (use_memory_fallback). This is
// the capability flag: MemoryFallback and memory-only chassis need it on.
// It does not remove the valkey dependency — use WithoutValkeyPeer when the
// process omits valkey from the framework graph.
func WithUseMemoryFallback(enabled bool) Option {
	return func(o *options) { o.useMemoryFallback = &enabled }
}

// WithForceMemory enables or disables break-glass sticky-note primary
// (force_memory). When Valkey is wired but Client() is nil at Init, this must
// be true or Init fails. At runtime, force_memory prefers the memory path.
func WithForceMemory(enabled bool) Option {
	return func(o *options) { o.forceMemory = &enabled }
}

// WithoutValkeyPeer omits valkey from GetDependencies. Use when the process
// has no valkey component (laptop / single-replica sticky-note chassis). Init
// then requires use_memory_fallback=true. Wrong: omit valkey from Components but leave
// the default dependency — Validate fails. Right: WithoutValkeyPeer +
// WithUseMemoryFallback(true) + explicit memory_map_full_policy + wait_missing_ttl_policy.
func WithoutValkeyPeer() Option {
	return func(o *options) { o.requireValkey = false }
}

// WithMemoryMaxEntries sets the hard cap on distinct keys in the in-process
// map (default 10000).
func WithMemoryMaxEntries(n int) Option {
	return func(o *options) { o.memoryMaxEntries = n }
}

// WithMemoryMapFullPolicy seeds memory_map_full_policy ("allow" or "deny").
// Required at Init when use_memory_fallback or force_memory is true.
func WithMemoryMapFullPolicy(policy string) Option {
	return func(o *options) { o.memoryMapFullPolicy = policy }
}

// WithWaitMissingTTLPolicy seeds wait_missing_ttl_policy ("proceed" or
// "error"). Required at Init.
func WithWaitMissingTTLPolicy(policy string) Option {
	return func(o *options) { o.waitMissingTTLPolicy = policy }
}

// WithMetricsEnabled toggles the metrics catalogue. When disabled,
// Metrics() returns nil. Default: enabled.
func WithMetricsEnabled(enabled bool) Option {
	return func(o *options) { o.metricsEnabled = enabled }
}

// WithWaitJitterMax caps the random extra sleep Wait adds to ResetIn (default
// 1s, ~10% of ResetIn). 0 disables jitter for deterministic tests.
func WithWaitJitterMax(d time.Duration) Option {
	return func(o *options) { o.waitJitterMax = d }
}

// WithWaitDelayFunc installs an app-supplied callback that decides how long
// Wait sleeps before retrying Allow (or aborts it). A nil callback uses the
// built-in jittered sleep. See WaitDelayFunc.
func WithWaitDelayFunc(fn WaitDelayFunc) Option {
	return func(o *options) { o.waitDelayFunc = fn }
}

// RateLimiter is the caerus-framework-http-ratelimiter component. It counts
// attempts for logical keys in a shared store (a cf_valkey.CFValkey peer by
// default; an in-process map when force_memory / memory-only / MemoryFallback)
// and reports allow/deny plus time-until-reset. It holds the valkey peer
// component (never a client snapshot) and builds every command through the
// peer's live Client() and prefix-aware Key(), so reconnects and key prefixes
// stay consistent.
type RateLimiter struct {
	mu           sync.RWMutex
	configSource string
	configPath   string
	srcEnvPrefix string
	srcFormat    cf_configuration.Format
	srcFormatSet bool
	name         string
	valkeyName   string
	loggerSet    bool
	fw           *cf.CaerusFramework
	logsSub      *cf_logs.Subscription

	requireValkey     bool
	useMemoryFallback bool
	forceMemory       bool
	memoryMode        bool // true when operating without a usable valkey primary
	valkeyLive        bool // true when Init saw a live Client()
	memory            *memoryLimiter

	keyPrefix              string
	maxKeyLength           int
	memoryMaxEntries       int
	memoryFallbackLimit    int64
	memoryFallbackWindow   time.Duration
	mapFullPolicy          MapFullPolicy
	mapFullPolicySet       bool
	waitMissingTTLPolicy   MissingTTLPolicy
	waitMissingTTLPolicyOK bool
	metricsEnabled         bool
	hashIPKeys             bool
	waitJitterMax          time.Duration
	waitDelayFunc          WaitDelayFunc

	vk *cf_valkey.CFValkey // peer component, resolved at Init
	// initialized mirrors whether Init completed successfully. Used by Health
	// and Metrics; Shutdown clears it.
	initialized atomic.Bool

	logger *slog.Logger

	disabledOnce sync.Once

	allows        atomic.Uint64
	denies        atomic.Uint64
	resets        atomic.Uint64
	peeks         atomic.Uint64
	waitsOK       atomic.Uint64
	waitsCanceled atomic.Uint64
	waitsErr      atomic.Uint64
	waitSleepNS   atomic.Int64 // total nanoseconds slept inside Wait
	waitSleepCnt  atomic.Uint64
	storageErrors atomic.Uint64
	fbOpen        atomic.Uint64
	fbClosed      atomic.Uint64
	fbMemory      atomic.Uint64
	mapFullAllow  atomic.Uint64
	mapFullDeny   atomic.Uint64
	reloads       atomic.Uint64
	disabled      atomic.Uint64
	rejectedEmpty atomic.Uint64
	rejectedLong  atomic.Uint64
	memoryPath    atomic.Uint64
	missingTTL    atomic.Uint64
}

// New creates a rate-limiter component. The valkey peer (or memory path) is
// resolved at Init, not here.
func New(opts ...Option) *RateLimiter {
	o := options{
		logger:           slog.Default(),
		keyPrefix:        defaultKeyPrefix,
		maxKeyLength:     defaultMaxKeyLength,
		memoryMaxEntries: defaultMemoryMaxEntries,
		metricsEnabled:   defaultMetricsEnabled,
		waitJitterMax:    defaultWaitJitterMax,
		requireValkey:    true,
	}
	for _, opt := range opts {
		opt(&o)
	}
	c := &RateLimiter{
		configSource:     o.configSource,
		configPath:       o.configPath,
		srcEnvPrefix:     o.srcEnvPrefix,
		srcFormat:        o.srcFormat,
		srcFormatSet:     o.srcFormatSet,
		name:             o.name,
		valkeyName:       o.valkeyName,
		logger:           o.logger,
		loggerSet:        o.loggerSet,
		requireValkey:    o.requireValkey,
		memory:           newMemoryLimiter(),
		keyPrefix:        strings.TrimSuffix(o.keyPrefix, ":"),
		maxKeyLength:     o.maxKeyLength,
		memoryMaxEntries: o.memoryMaxEntries,
		metricsEnabled:   o.metricsEnabled,
		hashIPKeys:       o.hashIPKeys,
		waitJitterMax:    o.waitJitterMax,
		waitDelayFunc:    o.waitDelayFunc,
	}
	if o.useMemoryFallback != nil {
		c.useMemoryFallback = *o.useMemoryFallback
	}
	if o.forceMemory != nil {
		c.forceMemory = *o.forceMemory
	}
	if o.memoryMapFullPolicy != "" {
		c.applyMapFullPolicy(o.memoryMapFullPolicy)
	}
	if o.waitMissingTTLPolicy != "" {
		c.applyWaitMissingTTLPolicy(o.waitMissingTTLPolicy)
	}
	if o.loaded != nil {
		c.applyConfig(*o.loaded)
	}
	return c
}

// applyConfig overlays non-zero / non-nil fields of cfg onto the component's
// base settings. Callers must not hold the mutex.
func (c *RateLimiter) applyConfig(cfg Config) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.applyConfigLocked(cfg)
}

// applyConfigLocked is applyConfig with the mutex held.
func (c *RateLimiter) applyConfigLocked(cfg Config) {
	if cfg.KeyPrefix != "" {
		c.keyPrefix = strings.TrimSuffix(cfg.KeyPrefix, ":")
	}
	if cfg.MetricsEnabled != nil {
		c.metricsEnabled = *cfg.MetricsEnabled
	}
	if cfg.UseMemoryFallback != nil {
		c.useMemoryFallback = *cfg.UseMemoryFallback
	}
	if cfg.ForceMemory != nil {
		c.forceMemory = *cfg.ForceMemory
	}
	if cfg.MemoryMaxEntries > 0 {
		c.memoryMaxEntries = cfg.MemoryMaxEntries
	}
	if cfg.HashIPKeys != nil {
		c.hashIPKeys = *cfg.HashIPKeys
	}
	if cfg.MaxKeyLength > 0 {
		c.maxKeyLength = cfg.MaxKeyLength
	}
	if cfg.WaitJitterMaxSec != nil {
		sec := *cfg.WaitJitterMaxSec
		if sec <= 0 {
			c.waitJitterMax = 0
		} else {
			c.waitJitterMax = time.Duration(sec * float64(time.Second))
		}
	}
	if cfg.MemoryMapFullPolicy != "" {
		c.applyMapFullPolicy(cfg.MemoryMapFullPolicy)
	}
	if cfg.WaitMissingTTLPolicy != "" {
		c.applyWaitMissingTTLPolicy(cfg.WaitMissingTTLPolicy)
	}
	c.memoryFallbackLimit = cfg.MemoryFallbackLimit
	if cfg.MemoryFallbackWindowSec > 0 {
		c.memoryFallbackWindow = time.Duration(cfg.MemoryFallbackWindowSec * float64(time.Second))
	}
}

func (c *RateLimiter) applyMapFullPolicy(raw string) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "allow":
		c.mapFullPolicy = MapFullAllow
		c.mapFullPolicySet = true
	case "deny":
		c.mapFullPolicy = MapFullDeny
		c.mapFullPolicySet = true
	default:
		c.mapFullPolicySet = false
		c.mapFullPolicy = MapFullAllow
	}
}

func (c *RateLimiter) applyWaitMissingTTLPolicy(raw string) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "proceed":
		c.waitMissingTTLPolicy = MissingTTLProceed
		c.waitMissingTTLPolicyOK = true
	case "error":
		c.waitMissingTTLPolicy = MissingTTLError
		c.waitMissingTTLPolicyOK = true
	default:
		c.waitMissingTTLPolicyOK = false
		c.waitMissingTTLPolicy = 0
	}
}

// validateRequiredPolicies checks Init/reload invariants for explicit policies.
// Call with the mutex held.
func (c *RateLimiter) validateRequiredPolicies() error {
	if !c.waitMissingTTLPolicyOK {
		return errors.New(`cf_http_ratelimiter: wait_missing_ttl_policy is required ("proceed" or "error")`)
	}
	if c.useMemoryFallback || c.forceMemory {
		if !c.mapFullPolicySet {
			return errors.New(`cf_http_ratelimiter: memory_map_full_policy is required ("allow" or "deny") when use_memory_fallback or force_memory is true`)
		}
	}
	return nil
}

// Name implements cf.CaerusComponent. Returns the custom name set via WithName,
// or the default ComponentName ("http-ratelimiter") if no custom name was set.
func (c *RateLimiter) Name() string {
	if c.name != "" {
		return c.name
	}
	return ComponentName
}

// GetInitOrderStage implements cf.CaerusComponent.
func (c *RateLimiter) GetInitOrderStage() cf.Stage { return ComponentStage }

// GetDependencies implements cf.Dependencies. Always depends on logs, and on
// configuration when WithConfigSource is set. Depends on the valkey peer unless
// WithoutValkeyPeer was used (memory-only chassis). Peer names are fixed at
// construction, so the graph is stable before Init.
func (c *RateLimiter) GetDependencies() []string {
	deps := []string{cf_logs.ComponentName}
	if c.requireValkey {
		peer := cf_valkey.ComponentName
		if c.valkeyName != "" {
			peer = c.valkeyName
		}
		deps = append([]string{peer}, deps...)
	}
	if c.configSource != "" {
		deps = append(deps, cf_configuration.ComponentName)
	}
	return deps
}

// peerName returns the configured valkey peer name, or the valkey
// ComponentName when unset. Callers must not hold the mutex.
func (c *RateLimiter) peerName() string {
	if c.valkeyName != "" {
		return c.valkeyName
	}
	return cf_valkey.ComponentName
}

// UseMemoryFallback reports whether the sticky-note engine is enabled.
func (c *RateLimiter) UseMemoryFallback() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.useMemoryFallback
}

// ForceMemory reports whether break-glass sticky-note primary is enabled.
func (c *RateLimiter) ForceMemory() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.forceMemory
}

// Init implements cf.CaerusComponent. It subscribes to the framework logs
// component, applies the bound configuration source, validates required
// policies, and resolves the valkey peer when required.
func (c *RateLimiter) Init(ctx context.Context, fw *cf.CaerusFramework) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.initialized.Load() {
		return nil // already initialized
	}
	c.fw = fw
	if !c.loggerSet {
		if logs, ok := cf.Get[*cf_logs.Logs](fw); ok {
			c.logsSub = logs.OnReconfigureFor(c.Name(), func(l *slog.Logger) { c.logger = l })
		}
	}
	if c.configSource != "" {
		if err := c.applyConfigFromSource(); err != nil {
			return err
		}
	}
	if err := c.validateRequiredPolicies(); err != nil {
		return err
	}

	if !c.requireValkey {
		if !c.useMemoryFallback {
			return errors.New("cf_http_ratelimiter: WithoutValkeyPeer requires use_memory_fallback=true")
		}
		c.memoryMode = true
		c.valkeyLive = false
		c.logger.Warn("cf_http_ratelimiter: running without a valkey peer (use_memory_fallback sticky-note chassis) — not shared across replicas")
		c.initialized.Store(true)
		return nil
	}

	var vk *cf_valkey.CFValkey
	var ok bool
	if c.valkeyName == "" {
		vk, ok = cf.Get[*cf_valkey.CFValkey](fw)
	} else {
		vk, ok = cf.GetByName[*cf_valkey.CFValkey](fw, c.valkeyName)
	}
	if !ok {
		return fmt.Errorf("cf_http_ratelimiter: valkey component %q is not registered (add it to the framework, or use WithoutValkeyPeer + use_memory_fallback=true for sticky-note-only)", c.peerName())
	}
	c.vk = vk
	if vk.Client() == nil {
		if !c.forceMemory {
			return fmt.Errorf("cf_http_ratelimiter: valkey component %q is not initialized (enable DegradedMode on valkey and force_memory on the limiter for break-glass sticky notes)", c.peerName())
		}
		c.memoryMode = true
		c.valkeyLive = false
		c.logger.Error("cf_http_ratelimiter: force_memory — valkey peer has no live client since Init; using sticky-note path; not shared across replicas; pair DegradedMode + health_when_degraded deliberately")
		c.initialized.Store(true)
		return nil
	}
	c.valkeyLive = true
	c.memoryMode = false
	if c.forceMemory {
		c.memoryMode = true // runtime prefers memory while force_memory is on
		if c.useMemoryFallback {
			c.logger.Error("cf_http_ratelimiter: lame_memory_mode — force_memory and use_memory_fallback are on while valkey is healthy; sticky notes are weaker than shared Valkey")
		} else {
			c.logger.Warn("cf_http_ratelimiter: force_memory on with healthy valkey; using sticky-note path")
		}
	}
	c.initialized.Store(true)
	return nil
}

// applyConfigFromSource reloads the bound configuration source and overlays it
// onto the component's base settings. It must be called with the mutex held.
func (c *RateLimiter) applyConfigFromSource() error {
	conf, ok := cf.Get[*cf_configuration.Configuration](c.fw)
	if !ok {
		return errors.New("cf_http_ratelimiter: configuration component not registered")
	}
	loaded, ok := cf_configuration.Get[Config](conf, c.configSource)
	if !ok {
		return fmt.Errorf("cf_http_ratelimiter: configuration source %q not found", c.configSource)
	}
	c.applyConfigLocked(*loaded)
	return nil
}

// Shutdown implements cf.CaerusComponent. It unsubscribes the logs
// subscription and drops the valkey peer. Further use returns an error.
func (c *RateLimiter) Shutdown(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.logsSub != nil {
		c.logsSub.Unsubscribe()
		c.logsSub = nil
	}
	c.vk = nil
	c.memoryMode = false
	c.valkeyLive = false
	c.initialized.Store(false)
	return nil
}

// peer returns the resolved valkey peer component (nil before Init or after
// Shutdown).
func (c *RateLimiter) peer() *cf_valkey.CFValkey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.vk
}

// useMemoryPath reports whether Allow/Peek/Reset should use the in-process map
// as the primary path (force_memory or memory-only chassis).
func (c *RateLimiter) useMemoryPath() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.forceMemory || c.memoryMode
}

// client returns the peer's live valkey client. It follows the peer-pointer
// convention: the peer is re-read per use, so a client swap on config reload is
// picked up immediately.
func (c *RateLimiter) client() (valkey.Client, error) {
	vk := c.peer()
	if vk == nil {
		return nil, errors.New("cf_http_ratelimiter: component is not initialized")
	}
	cl := vk.Client()
	if cl == nil {
		return nil, errors.New("cf_http_ratelimiter: valkey client is not initialized")
	}
	return cl, nil
}

// Key builds the storage key for a logical key: the valkey peer's prefix-aware
// Key() plus this component's key prefix (e.g. portal:rl:login:<hex>). Before
// Init (memory mode or key-helper use) it falls back to a plain ":"-join.
func (c *RateLimiter) Key(logical string) string {
	c.mu.RLock()
	prefix := c.keyPrefix
	c.mu.RUnlock()
	vk := c.peer()
	if vk == nil {
		if prefix == "" {
			return logical
		}
		return prefix + ":" + logical
	}
	if prefix == "" {
		return vk.Key(logical)
	}
	return vk.Key(prefix, logical)
}

// maxLen returns the configured maximum logical key length.
func (c *RateLimiter) maxLen() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.maxKeyLength <= 0 {
		return defaultMaxKeyLength
	}
	return c.maxKeyLength
}

// validateKey enforces the logical key contract: non-empty and within
// MaxKeyLength bytes. Violations are errors (never truncated) and are counted
// in key_rejected_total. It runs before any storage access.
func (c *RateLimiter) validateKey(key string) error {
	switch {
	case key == "":
		c.rejectedEmpty.Add(1)
		return errors.New("cf_http_ratelimiter: empty key")
	case len(key) > c.maxLen():
		c.rejectedLong.Add(1)
		return fmt.Errorf("cf_http_ratelimiter: key too long (%d bytes, max %d)", len(key), c.maxLen())
	}
	return nil
}

// disabledCall implements the limit <= 0 short-circuit: rate limiting is off
// for this call, allow without touching storage, and count only
// disabled_total. A one-time warning surfaces the misconfiguration.
func (c *RateLimiter) disabledCall() Result {
	c.disabled.Add(1)
	c.disabledOnce.Do(func() {
		c.logger.Warn("cf_http_ratelimiter: Allow/Wait called with limit <= 0; rate limiting disabled for this call — check the caller's config")
	})
	return Result{Allowed: true}
}

// Allow increments the counter for key and reports whether Count <= limit
// inside window. An empty key or a key longer than MaxKeyLength is an error
// (no truncation). A limit <= 0 treats rate limiting as off for this call:
// always allowed, no storage access, counted only in disabled_total.
// Transport errors are returned to the caller — fail-open/fail-closed policy
// belongs to the app (see AllowWithPolicy and Middleware).
func (c *RateLimiter) Allow(ctx context.Context, key string, limit int64, window time.Duration) (Result, error) {
	if limit <= 0 {
		return c.disabledCall(), nil
	}
	if window <= 0 {
		window = time.Second
	}
	if err := c.validateKey(key); err != nil {
		return Result{}, err
	}
	return c.allowStorage(ctx, key, limit, window)
}

// allowValkey runs the fixed-window Lua counter against the peer's live client.
func (c *RateLimiter) allowValkey(ctx context.Context, key string, limit int64, window time.Duration) (Result, error) {
	client, err := c.client()
	if err != nil {
		c.storageErrors.Add(1)
		return Result{}, err
	}
	storeKey := c.Key(key)
	resp := client.Do(ctx, client.B().Eval().Script(luaAllow).
		Numkeys(1).
		Key(storeKey).
		Arg(strconv.FormatInt(window.Milliseconds(), 10)).
		Build())
	if resp.Error() != nil {
		c.storageErrors.Add(1)
		return Result{}, resp.Error()
	}
	vals, err := resp.AsIntSlice()
	if err != nil {
		c.storageErrors.Add(1)
		return Result{}, err
	}
	var count, pttl int64
	if len(vals) >= 1 {
		count = vals[0]
	}
	if len(vals) >= 2 {
		pttl = vals[1]
	}
	if count > 0 && pttl <= 0 {
		if err := c.handleMissingTTL(ctx, client, storeKey, false); err != nil {
			return Result{}, err
		}
		// proceed: scrubbed; run Allow once more on a fresh key.
		return c.allowValkey(ctx, key, limit, window)
	}
	res := Result{Count: count, ResetIn: window, Allowed: count <= limit}
	if pttl > 0 {
		res.ResetIn = time.Duration(pttl) * time.Millisecond
	}
	if res.Allowed {
		c.allows.Add(1)
	} else {
		c.denies.Add(1)
	}
	return res, nil
}

// allowMemory runs the fixed-window counter against the in-process map using
// the resolved fallback sizing.
func (c *RateLimiter) allowMemory(ctx context.Context, key string, limit int64, window time.Duration, fb MemoryFallbackConfig) (Result, error) {
	c.memoryPath.Add(1)
	if fb.MaxEntries <= 0 {
		fb.MaxEntries = c.memoryMaxEntriesValue()
	}
	if fb.WhenMapFull == MapFullAllow {
		fb.WhenMapFull = c.mapFullPolicyValue()
	}
	res, err := c.memory.Allow(ctx, key, limit, window, fb)
	if err != nil {
		return Result{}, err
	}
	if res.Allowed {
		c.allows.Add(1)
	} else {
		c.denies.Add(1)
	}
	return res, nil
}

// Reset deletes the counter for key (successful login / admin unlock). A
// missing key is a success (idempotent). The error string never includes the
// logical key (avoid leaking hashed identities into logs).
func (c *RateLimiter) Reset(ctx context.Context, key string) error {
	if err := c.validateKey(key); err != nil {
		return err
	}
	if c.useMemoryPath() {
		c.memory.Reset(ctx, key)
		c.resets.Add(1)
		return nil
	}
	client, err := c.client()
	if err != nil {
		c.storageErrors.Add(1)
		return err
	}
	if err := client.Do(ctx, client.B().Del().Key(c.Key(key)).Build()).Error(); err != nil {
		c.storageErrors.Add(1)
		return fmt.Errorf("cf_http_ratelimiter: reset failed: %w", err)
	}
	c.resets.Add(1)
	return nil
}

// Peek reads the current counter and TTL for key without incrementing it. A
// missing or expired key reports Count 0 and ResetIn 0. Allowed is always
// false (Peek has no limit to compare against). Used by Wait and useful for
// dashboards and pre-flight checks.
func (c *RateLimiter) Peek(ctx context.Context, key string) (Result, error) {
	if err := c.validateKey(key); err != nil {
		return Result{}, err
	}
	if c.useMemoryPath() {
		res := c.memory.Peek(ctx, key)
		c.peeks.Add(1)
		return res, nil
	}
	client, err := c.client()
	if err != nil {
		c.storageErrors.Add(1)
		return Result{}, err
	}
	storeKey := c.Key(key)
	resp := client.Do(ctx, client.B().Eval().Script(luaPeek).
		Numkeys(1).
		Key(storeKey).
		Build())
	if resp.Error() != nil {
		c.storageErrors.Add(1)
		return Result{}, resp.Error()
	}
	vals, err := resp.AsIntSlice()
	if err != nil {
		c.storageErrors.Add(1)
		return Result{}, err
	}
	var count, pttl int64
	if len(vals) >= 1 {
		count = vals[0]
	}
	if len(vals) >= 2 {
		pttl = vals[1]
	}
	if count > 0 && pttl <= 0 {
		if err := c.handleMissingTTL(ctx, client, storeKey, true); err != nil {
			return Result{}, err
		}
		c.peeks.Add(1)
		return Result{}, nil // proceed: scrubbed → empty peek
	}
	res := Result{Count: count}
	if pttl > 0 {
		res.ResetIn = time.Duration(pttl) * time.Millisecond
	}
	c.peeks.Add(1)
	return res, nil
}

// handleMissingTTL logs, counts, deletes the bad key, then applies the
// component missing-TTL policy (or returns ErrMissingTTL). peekOnly is unused
// beyond call-site clarity; policy is the same for Allow/Peek.
func (c *RateLimiter) handleMissingTTL(ctx context.Context, client valkey.Client, storeKey string, _ bool) error {
	c.missingTTL.Add(1)
	c.logger.Error("cf_http_ratelimiter: counter missing TTL; scrubbing key")
	_ = client.Do(ctx, client.B().Del().Key(storeKey).Build()).Error()
	policy := c.missingTTLPolicyValue()
	if policy == MissingTTLError {
		return ErrMissingTTL
	}
	return nil
}

func (c *RateLimiter) missingTTLPolicyValue() MissingTTLPolicy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.waitMissingTTLPolicy
}

// Wait blocks until a single Allow would succeed, then performs that Allow
// once, or returns when ctx is done. It must not keep calling Allow while
// denied (each Allow increments the counter): it peeks, sleeps on ResetIn plus
// a small jitter, then tries Allow once. Sleep is interruptible by ctx.
// A limit <= 0 returns immediately (limiter off for this call).
func (c *RateLimiter) Wait(ctx context.Context, key string, limit int64, window time.Duration) error {
	return c.WaitOpts(ctx, key, limit, window, WaitOptions{})
}

// WaitOpts is Wait with per-call overrides (missing-TTL policy, delay func).
func (c *RateLimiter) WaitOpts(ctx context.Context, key string, limit int64, window time.Duration, opts WaitOptions) error {
	if limit <= 0 {
		c.disabled.Add(1)
		c.disabledOnce.Do(func() {
			c.logger.Warn("cf_http_ratelimiter: Wait called with limit <= 0; rate limiting disabled for this call — check the caller's config")
		})
		return nil
	}
	if err := c.validateKey(key); err != nil {
		c.waitsErr.Add(1)
		return err
	}
	ttlPolicy := c.missingTTLPolicyValue()
	if opts.MissingTTLPolicy != nil {
		ttlPolicy = *opts.MissingTTLPolicy
	}
	for {
		peeked, err := c.peekForWait(ctx, key, ttlPolicy)
		if err != nil {
			c.waitsErr.Add(1)
			return err
		}
		if peeked.Count < limit {
			grant, err := c.Allow(ctx, key, limit, window)
			if err != nil {
				c.waitsErr.Add(1)
				return err
			}
			if grant.Allowed {
				c.waitsOK.Add(1)
				return nil
			}
			peeked = grant
		}
		if peeked.Count > 0 && peeked.ResetIn <= 0 {
			// Must not busy-loop: scrub path should have run in Peek/Allow.
			// If we still see this (race), apply policy again via Allow path.
			c.logger.Error("cf_http_ratelimiter: Wait saw ResetIn<=0 after peek; refusing busy-loop")
			c.missingTTL.Add(1)
			if ttlPolicy == MissingTTLError {
				c.waitsErr.Add(1)
				return ErrMissingTTL
			}
			continue // proceed → Allow once on next iteration
		}
		sleep, err := c.waitDelayOpts(ctx, key, peeked.ResetIn, opts)
		if err != nil {
			c.waitsErr.Add(1)
			return err
		}
		if err := sleepInterruptible(ctx, sleep); err != nil {
			c.waitsCanceled.Add(1)
			return err
		}
		c.waitSleepCnt.Add(1)
		c.waitSleepNS.Add(int64(sleep))
	}
}

// peekForWait is Peek with an optional missing-TTL policy override for the
// scrub decision. When the primary path is memory, Peek has no missing-TTL.
func (c *RateLimiter) peekForWait(ctx context.Context, key string, ttlPolicy MissingTTLPolicy) (Result, error) {
	if c.useMemoryPath() {
		res := c.memory.Peek(ctx, key)
		c.peeks.Add(1)
		return res, nil
	}
	client, err := c.client()
	if err != nil {
		c.storageErrors.Add(1)
		return Result{}, err
	}
	storeKey := c.Key(key)
	resp := client.Do(ctx, client.B().Eval().Script(luaPeek).
		Numkeys(1).
		Key(storeKey).
		Build())
	if resp.Error() != nil {
		c.storageErrors.Add(1)
		return Result{}, resp.Error()
	}
	vals, err := resp.AsIntSlice()
	if err != nil {
		c.storageErrors.Add(1)
		return Result{}, err
	}
	var count, pttl int64
	if len(vals) >= 1 {
		count = vals[0]
	}
	if len(vals) >= 2 {
		pttl = vals[1]
	}
	if count > 0 && pttl <= 0 {
		c.missingTTL.Add(1)
		c.logger.Error("cf_http_ratelimiter: counter missing TTL; scrubbing key")
		_ = client.Do(ctx, client.B().Del().Key(storeKey).Build()).Error()
		c.peeks.Add(1)
		if ttlPolicy == MissingTTLError {
			return Result{}, ErrMissingTTL
		}
		return Result{}, nil
	}
	res := Result{Count: count}
	if pttl > 0 {
		res.ResetIn = time.Duration(pttl) * time.Millisecond
	}
	c.peeks.Add(1)
	return res, nil
}

// waitDelay resolves the sleep duration for a Wait pause.
func (c *RateLimiter) waitDelay(ctx context.Context, key string, base time.Duration) (time.Duration, error) {
	return c.waitDelayOpts(ctx, key, base, WaitOptions{})
}

func (c *RateLimiter) waitDelayOpts(ctx context.Context, key string, base time.Duration, opts WaitOptions) (time.Duration, error) {
	c.mu.RLock()
	fn := c.waitDelayFunc
	jitterMax := c.waitJitterMax
	c.mu.RUnlock()
	if opts.delayFuncSet {
		fn = opts.DelayFunc
	} else if opts.DelayFunc != nil {
		fn = opts.DelayFunc
	}

	jittered := base
	if jitterMax > 0 && base > 0 {
		extra := time.Duration(float64(base) * 0.1)
		if extra > jitterMax {
			extra = jitterMax
		}
		if extra > 0 {
			jittered = base + time.Duration(rand.Float64()*float64(extra))
		}
	}
	if fn == nil {
		return jittered, nil
	}
	return fn(ctx, key, base, jittered)
}

// sleepInterruptible sleeps d or returns when ctx is done. A non-positive
// duration returns immediately.
func sleepInterruptible(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// AllowWithPolicy is Allow with an explicit storage-error policy argument, for
// call sites that cannot use the HTTP middleware. On a primary-store error it
// applies the policy: StorageFailOpen returns Allowed=true, StorageFailClosed
// returns the error, StorageMemoryFallback delegates to the in-process memory
// limiter (requires use_memory_fallback=true) using the component's configured fallback
// sizing. limit <= 0 still short-circuits (disabled_total only) before any
// policy logic.
func (c *RateLimiter) AllowWithPolicy(ctx context.Context, key string, limit int64, window time.Duration, policy StorageErrorPolicy) (Result, error) {
	return c.AllowWithPolicyOpts(ctx, key, limit, window, policy, MemoryFallbackConfig{})
}

// AllowWithPolicyOpts is AllowWithPolicy with per-call MemoryFallbackConfig
// overrides (wired from MiddlewareConfig.Memory).
func (c *RateLimiter) AllowWithPolicyOpts(ctx context.Context, key string, limit int64, window time.Duration, policy StorageErrorPolicy, memory MemoryFallbackConfig) (Result, error) {
	if limit <= 0 {
		return c.disabledCall(), nil
	}
	if window <= 0 {
		window = time.Second
	}
	if err := c.validateKey(key); err != nil {
		return Result{}, err
	}
	if policy == StorageMemoryFallback && !c.UseMemoryFallback() {
		return Result{}, ErrMemoryFallbackDisabled
	}
	res, err := c.allowStorage(ctx, key, limit, window)
	if err == nil {
		return res, nil
	}
	switch policy {
	case StorageFailOpen:
		c.fbOpen.Add(1)
		c.logger.Warn("cf_http_ratelimiter: store error; fail-open", "err", err)
		return Result{Allowed: true}, nil
	case StorageFailClosed:
		c.fbClosed.Add(1)
		return Result{}, err
	case StorageMemoryFallback:
		if !c.UseMemoryFallback() {
			return Result{}, ErrMemoryFallbackDisabled
		}
		c.fbMemory.Add(1)
		c.logger.Warn("cf_http_ratelimiter: store error; memory fallback", "err", err)
		fb := c.mergeMemoryConfig(memory)
		lim := limit
		win := window
		if fb.Limit > 0 {
			lim = fb.Limit
		}
		if fb.Window > 0 {
			win = fb.Window
		}
		return c.allowMemory(ctx, key, lim, win, fb)
	default:
		return Result{}, fmt.Errorf("cf_http_ratelimiter: unknown storage error policy %d", policy)
	}
}

// allowStorage dispatches to the active primary path without applying any
// OnStoreError policy.
func (c *RateLimiter) allowStorage(ctx context.Context, key string, limit int64, window time.Duration) (Result, error) {
	if c.useMemoryPath() {
		return c.allowMemory(ctx, key, limit, window, c.memoryFallbackConfig())
	}
	return c.allowValkey(ctx, key, limit, window)
}

// mergeMemoryConfig overlays call-site MemoryFallbackConfig onto component defaults.
func (c *RateLimiter) mergeMemoryConfig(override MemoryFallbackConfig) MemoryFallbackConfig {
	fb := c.memoryFallbackConfig()
	if override.MaxEntries > 0 {
		fb.MaxEntries = override.MaxEntries
	}
	if override.WhenMapFull == MapFullDeny {
		fb.WhenMapFull = MapFullDeny
	}
	if override.Limit > 0 {
		fb.Limit = override.Limit
	}
	if override.Window > 0 {
		fb.Window = override.Window
	}
	return fb
}

// memoryFallbackConfig returns the component-configured fallback sizing.
func (c *RateLimiter) memoryFallbackConfig() MemoryFallbackConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	fb := MemoryFallbackConfig{
		MaxEntries:  c.memoryMaxEntries,
		WhenMapFull: c.mapFullPolicy,
	}
	if c.memoryFallbackLimit != 0 {
		fb.Limit = c.memoryFallbackLimit
	}
	if c.memoryFallbackWindow != 0 {
		fb.Window = c.memoryFallbackWindow
	}
	return fb
}

// memoryMaxEntriesValue returns the configured memory map cap.
func (c *RateLimiter) memoryMaxEntriesValue() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.memoryMaxEntries <= 0 {
		return defaultMemoryMaxEntries
	}
	return c.memoryMaxEntries
}

// mapFullPolicyValue returns the configured map-full policy.
func (c *RateLimiter) mapFullPolicyValue() MapFullPolicy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.mapFullPolicy
}

// HashIPKeys reports the configured hash_ip_keys toggle. The component does
// not hash keys itself (the HMAC secret is app-owned); apps read this flag in
// their KeyFunc and use KeyHasher when true.
func (c *RateLimiter) HashIPKeys() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hashIPKeys
}

// OnConfigReload implements cf.ConfigReloader. It re-applies the module
// tunables from the bound configuration source. Invalid required policies keep
// last-good settings. No connection is rebuilt: the valkey peer owns client
// rotation.
func (c *RateLimiter) OnConfigReload(source string, cfg any) {
	if source != c.configSource || !c.initialized.Load() {
		return
	}
	typed, ok := cfg.(*Config)
	if !ok {
		c.logger.Error("cf_http_ratelimiter: config reload rejected", "source", source, "type", fmt.Sprintf("%T", cfg))
		return
	}
	c.mu.Lock()
	prev := snapshotTunables(c)
	c.applyConfigLocked(*typed)
	if err := c.validateRequiredPolicies(); err != nil {
		restoreTunables(c, prev)
		c.mu.Unlock()
		c.logger.Error("cf_http_ratelimiter: config reload rejected; keeping last-good", "err", err)
		return
	}
	// force_memory / use_memory_fallback flips at reload: recompute runtime path flags
	// without dropping the peer pointer.
	if c.vk != nil && c.vk.Client() != nil {
		c.valkeyLive = true
		c.memoryMode = c.forceMemory
		if c.forceMemory && c.useMemoryFallback {
			c.logger.Error("cf_http_ratelimiter: lame_memory_mode — force_memory and use_memory_fallback are on while valkey is healthy")
		}
	} else if c.vk != nil {
		if c.forceMemory {
			c.memoryMode = true
			c.valkeyLive = false
		}
	}
	c.mu.Unlock()
	c.reloads.Add(1)
	c.logger.Info("cf_http_ratelimiter: tunables reloaded",
		"key_prefix", c.keyPrefixValue(),
		"metrics_enabled", c.metricsEnabledValue(),
		"use_memory_fallback", c.UseMemoryFallback(),
		"force_memory", c.ForceMemory(),
		"max_key_length", c.maxLen(),
	)
}

type tunablesSnapshot struct {
	keyPrefix              string
	metricsEnabled         bool
	useMemoryFallback      bool
	forceMemory            bool
	memoryMaxEntries       int
	memoryFallbackLimit    int64
	memoryFallbackWindow   time.Duration
	mapFullPolicy          MapFullPolicy
	mapFullPolicySet       bool
	waitMissingTTLPolicy   MissingTTLPolicy
	waitMissingTTLPolicyOK bool
	hashIPKeys             bool
	maxKeyLength           int
	waitJitterMax          time.Duration
}

func snapshotTunables(c *RateLimiter) tunablesSnapshot {
	return tunablesSnapshot{
		keyPrefix:              c.keyPrefix,
		metricsEnabled:         c.metricsEnabled,
		useMemoryFallback:      c.useMemoryFallback,
		forceMemory:            c.forceMemory,
		memoryMaxEntries:       c.memoryMaxEntries,
		memoryFallbackLimit:    c.memoryFallbackLimit,
		memoryFallbackWindow:   c.memoryFallbackWindow,
		mapFullPolicy:          c.mapFullPolicy,
		mapFullPolicySet:       c.mapFullPolicySet,
		waitMissingTTLPolicy:   c.waitMissingTTLPolicy,
		waitMissingTTLPolicyOK: c.waitMissingTTLPolicyOK,
		hashIPKeys:             c.hashIPKeys,
		maxKeyLength:           c.maxKeyLength,
		waitJitterMax:          c.waitJitterMax,
	}
}

func restoreTunables(c *RateLimiter, s tunablesSnapshot) {
	c.keyPrefix = s.keyPrefix
	c.metricsEnabled = s.metricsEnabled
	c.useMemoryFallback = s.useMemoryFallback
	c.forceMemory = s.forceMemory
	c.memoryMaxEntries = s.memoryMaxEntries
	c.memoryFallbackLimit = s.memoryFallbackLimit
	c.memoryFallbackWindow = s.memoryFallbackWindow
	c.mapFullPolicy = s.mapFullPolicy
	c.mapFullPolicySet = s.mapFullPolicySet
	c.waitMissingTTLPolicy = s.waitMissingTTLPolicy
	c.waitMissingTTLPolicyOK = s.waitMissingTTLPolicyOK
	c.hashIPKeys = s.hashIPKeys
	c.maxKeyLength = s.maxKeyLength
	c.waitJitterMax = s.waitJitterMax
}

func (c *RateLimiter) keyPrefixValue() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keyPrefix
}

func (c *RateLimiter) metricsEnabledValue() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metricsEnabled
}

// RegisterConfigSources implements cf.ConfigSourceRegistrar. The framework
// calls it during argv absorption; it registers this component's configuration
// source (name, path, env prefix, format, Owner) with the configuration
// component. No-op when no source is bound.
func (c *RateLimiter) RegisterConfigSources(conf any) error {
	cfg, ok := conf.(*cf_configuration.Configuration)
	if !ok {
		return fmt.Errorf("cf_http_ratelimiter: RegisterConfigSources: expected configuration component, got %T", conf)
	}
	if c.configSource == "" {
		return nil
	}
	format := c.srcFormat
	if !c.srcFormatSet {
		if p := strings.ToLower(c.configPath); strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml") {
			format = cf_configuration.FormatYAML
		} else {
			format = cf_configuration.FormatJSON
		}
	}
	return cf_configuration.AddSource(cfg, cf_configuration.Source[Config]{
		Name:      c.configSource,
		Path:      c.configPath,
		Format:    format,
		Owner:     c.Name(),
		EnvPrefix: c.srcEnvPrefix,
	})
}

// Health implements cf.HealthProvider. It reports unhealthy before Init or
// after Shutdown. After Init in memory-only / force_memory sticky mode it
// reports healthy (the process-local map is ready). With a Valkey primary it
// delegates to the peer's health (a real PING).
func (c *RateLimiter) Health(ctx context.Context) error {
	if !c.initialized.Load() {
		return errors.New("cf_http_ratelimiter: component is not initialized")
	}
	if c.useMemoryPath() {
		return nil
	}
	vk := c.peer()
	if vk == nil || vk.Client() == nil {
		return errors.New("cf_http_ratelimiter: valkey client is not initialized")
	}
	return vk.Health(ctx)
}

var _ cf.CaerusComponent = (*RateLimiter)(nil)
var _ cf.Dependencies = (*RateLimiter)(nil)
var _ cf.HealthProvider = (*RateLimiter)(nil)
var _ cf_observability.MetricsProvider = (*RateLimiter)(nil)
var _ cf.ConfigReloader = (*RateLimiter)(nil)
var _ cf.ConfigSourceRegistrar = (*RateLimiter)(nil)
