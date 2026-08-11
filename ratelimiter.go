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

// Defaults for module knobs. Limits and windows are caller-supplied per call;
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
	// in-process map (the unlocked memory backend and the memory-fallback
	// policy share one map).
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
	// call. Still some limits, only on this one server. Typical for login
	// lockout where a coarse in-process ceiling is better than none.
	StorageMemoryFallback
)

// MapFullPolicy is the "fallback/memory map hit its max distinct keys" policy.
// Unlike OnStoreError, an unset map-full policy is permissive: it allows the
// call rather than denying it.
type MapFullPolicy int

const (
	// MapFullAllow is the default when unset (permissive). The call is
	// allowed without counting.
	MapFullAllow MapFullPolicy = iota
	// MapFullDeny rejects Allow for a new key when the cap is reached.
	MapFullDeny
)

// MemoryFallbackConfig sizes the in-process memory limiter used by the
// StorageMemoryFallback policy and (with MemoryMaxEntries as the cap) by the
// unlocked memory backend. Zero fields fall back to the component's configured
// values; when those are also zero, the call's own limit/window are used.
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
//
// Example app policies:
//
//	sleep(jittered)                        // default if nil
//	sleep(base) only                       // ignore jitter
//	return 0, errBudgetExceeded            // fail fast instead of waiting
//	sleep(min(jittered, 5*time.Second))    // cap wait for UX/SLA
type WaitDelayFunc func(ctx context.Context, key string, base, jittered time.Duration) (sleep time.Duration, err error)

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
	Memory MemoryFallbackConfig
	// OnDenied, when set, is called instead of the default 429/503 response.
	// status is http.StatusTooManyRequests for an over-limit denial, or
	// http.StatusServiceUnavailable for a FailClosed store error. Use it for
	// custom bodies, status codes, or logging.
	OnDenied func(w http.ResponseWriter, r *http.Request, res Result, status int)
}

// Config is the file/env-drivable module configuration. It holds module knobs
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
	// MemoryMaxEntries caps distinct keys in the in-process map (shared by the
	// unlocked memory backend and the memory-fallback policy). Default 10000.
	MemoryMaxEntries int `json:"memory_max_entries,omitempty" yaml:"memory_max_entries,omitempty" env:"MEMORY_MAX_ENTRIES"`
	// MemoryFallbackLimit is the optional coarser limit used when a call site
	// chooses StorageMemoryFallback. 0 → the call's own limit.
	MemoryFallbackLimit int64 `json:"memory_fallback_limit,omitempty" yaml:"memory_fallback_limit,omitempty" env:"MEMORY_FALLBACK_LIMIT"`
	// MemoryFallbackWindowSec is the optional coarser window (seconds) used
	// when a call site chooses StorageMemoryFallback. 0 → the call's own window.
	MemoryFallbackWindowSec float64 `json:"memory_fallback_window_sec,omitempty" yaml:"memory_fallback_window_sec,omitempty" env:"MEMORY_FALLBACK_WINDOW_SEC"`
	// MemoryMapFullPolicy: "" / "allow" → allow new keys when the map is full
	// (permissive default); "deny" → reject them. Any other value warns and
	// falls back to allow.
	MemoryMapFullPolicy string `json:"memory_map_full_policy,omitempty" yaml:"memory_map_full_policy,omitempty" env:"MEMORY_MAP_FULL_POLICY"`
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

	memoryBackend    bool // WithMemoryBackend unlock; no valkey peer required
	keyPrefix        string
	maxKeyLength     int
	memoryMaxEntries int
	metricsEnabled   bool
	hashIPKeys       bool
	waitJitterMax    time.Duration
	waitDelayFunc    WaitDelayFunc
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
// ConfigSourceRegistrar pass during argv absorption). The module owns the
// Source: the config type, the default EnvPrefix and its Owner (Name(), so
// named instances reload correctly). main only points the instance at where
// the config lives.
//
//	cf_http_ratelimiter.New(cf_http_ratelimiter.WithConfigSource("http-ratelimiter", "config/http-ratelimiter.json"))
//
// A path of "" registers an env-only (fileless) source when the EnvPrefix is
// non-empty. The path CLI override stays --<source-name> (ParseFlags).
// Declares a dependency on "configuration".
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

// WithMemoryBackend unlocks the in-process memory backend. It is disabled by
// default: without this option the component expects a valkey peer at Init and
// fails if it is missing. Unlock memory only for unit tests and local
// CLI/one-off binaries — not for multi-replica production. Config file/env
// alone cannot switch a process to memory-only.
func WithMemoryBackend() Option {
	return func(o *options) { o.memoryBackend = true }
}

// WithMemoryMaxEntries sets the hard cap on distinct keys in the in-process
// map (default 10000), shared by the unlocked memory backend and the
// memory-fallback policy.
func WithMemoryMaxEntries(n int) Option {
	return func(o *options) { o.memoryMaxEntries = n }
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
// default; an in-process map when WithMemoryBackend is unlocked) and reports
// allow/deny plus time-until-reset. It holds the valkey peer component (never
// a client snapshot) and builds every command through the peer's live Client()
// and prefix-aware Key(), so reconnects and key prefixes stay consistent.
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

	memoryBackend bool
	memory        *memoryLimiter

	keyPrefix            string
	maxKeyLength         int
	memoryMaxEntries     int
	memoryFallbackLimit  int64
	memoryFallbackWindow time.Duration
	mapFullPolicy        MapFullPolicy
	metricsEnabled       bool
	hashIPKeys           bool
	waitJitterMax        time.Duration
	waitDelayFunc        WaitDelayFunc

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
}

// New creates a rate-limiter component. The valkey peer (or memory backend)
// is resolved at Init, not here.
func New(opts ...Option) *RateLimiter {
	o := options{
		logger:           slog.Default(),
		keyPrefix:        defaultKeyPrefix,
		maxKeyLength:     defaultMaxKeyLength,
		memoryMaxEntries: defaultMemoryMaxEntries,
		metricsEnabled:   defaultMetricsEnabled,
		waitJitterMax:    defaultWaitJitterMax,
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
		memoryBackend:    o.memoryBackend,
		memory:           newMemoryLimiter(),
		keyPrefix:        strings.TrimSuffix(o.keyPrefix, ":"),
		maxKeyLength:     o.maxKeyLength,
		memoryMaxEntries: o.memoryMaxEntries,
		metricsEnabled:   o.metricsEnabled,
		hashIPKeys:       o.hashIPKeys,
		waitJitterMax:    o.waitJitterMax,
		waitDelayFunc:    o.waitDelayFunc,
	}
	if o.loaded != nil {
		c.applyConfig(*o.loaded)
	}
	return c
}

// applyConfig overlays non-zero fields of cfg onto the component's base
// settings. It runs last, so a loaded config always wins over option-set
// defaults. Callers must not hold the mutex.
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
	switch strings.ToLower(strings.TrimSpace(cfg.MemoryMapFullPolicy)) {
	case "", "allow":
		c.mapFullPolicy = MapFullAllow
	case "deny":
		c.mapFullPolicy = MapFullDeny
	default:
		c.logger.Warn("cf_http_ratelimiter: unknown memory_map_full_policy; defaulting to allow",
			"policy", cfg.MemoryMapFullPolicy)
		c.mapFullPolicy = MapFullAllow
	}
	// Fallback limit/window are read from the component state by
	// memoryFallbackConfig; only the configured (non-zero) values override.
	c.memoryFallbackLimit = cfg.MemoryFallbackLimit
	if cfg.MemoryFallbackWindowSec > 0 {
		c.memoryFallbackWindow = time.Duration(cfg.MemoryFallbackWindowSec * float64(time.Second))
	}
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

// GetDependencies implements cf.Dependencies. The valkey backend depends on
// the valkey peer it consumes (the actual peer name when WithValkeyName is
// set, the default ComponentName otherwise); the unlocked memory backend does
// not. Both depend on logs, and on configuration when WithConfigSource is set.
// Peer names are fixed at construction, so the graph is stable before Init.
func (c *RateLimiter) GetDependencies() []string {
	deps := []string{cf_logs.ComponentName}
	if !c.memoryBackend {
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

// Init implements cf.CaerusComponent. It subscribes to the framework logs
// component, applies the bound configuration source, and — unless the memory
// backend was unlocked with WithMemoryBackend — resolves the valkey peer
// component, failing fast when it is missing or not yet initialized. No
// connection is opened here; the peer owns its client.
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
	if !c.memoryBackend {
		var vk *cf_valkey.CFValkey
		var ok bool
		if c.valkeyName == "" {
			vk, ok = cf.Get[*cf_valkey.CFValkey](fw)
		} else {
			vk, ok = cf.GetByName[*cf_valkey.CFValkey](fw, c.valkeyName)
		}
		if !ok {
			return fmt.Errorf("cf_http_ratelimiter: valkey component %q is not registered (add it to the framework and to GetDependencies)", c.peerName())
		}
		if vk.Client() == nil {
			return fmt.Errorf("cf_http_ratelimiter: valkey component %q is not initialized", c.peerName())
		}
		c.vk = vk
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
	if c.memoryBackend {
		return c.allowMemory(ctx, key, limit, window, MemoryFallbackConfig{
			MaxEntries:  c.memoryMaxEntriesValue(),
			WhenMapFull: c.mapFullPolicyValue(),
		})
	}
	return c.allowValkey(ctx, key, limit, window)
}

// allowValkey runs the fixed-window Lua counter against the peer's live client.
func (c *RateLimiter) allowValkey(ctx context.Context, key string, limit int64, window time.Duration) (Result, error) {
	client, err := c.client()
	if err != nil {
		c.storageErrors.Add(1)
		return Result{}, err
	}
	resp := client.Do(ctx, client.B().Eval().Script(luaAllow).
		Numkeys(1).
		Key(c.Key(key)).
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
	res := Result{ResetIn: window}
	if len(vals) >= 1 {
		res.Count = vals[0]
	}
	if len(vals) >= 2 && vals[1] > 0 {
		res.ResetIn = time.Duration(vals[1]) * time.Millisecond
	}
	res.Allowed = res.Count <= limit
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
// missing key is a success (idempotent).
func (c *RateLimiter) Reset(ctx context.Context, key string) error {
	if err := c.validateKey(key); err != nil {
		return err
	}
	if c.memoryBackend {
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
		return fmt.Errorf("cf_http_ratelimiter: reset %q: %w", key, err)
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
	if c.memoryBackend {
		res := c.memory.Peek(ctx, key)
		c.peeks.Add(1)
		return res, nil
	}
	client, err := c.client()
	if err != nil {
		c.storageErrors.Add(1)
		return Result{}, err
	}
	resp := client.Do(ctx, client.B().Eval().Script(luaPeek).
		Numkeys(1).
		Key(c.Key(key)).
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
	res := Result{}
	if len(vals) >= 1 {
		res.Count = vals[0]
	}
	if len(vals) >= 2 && vals[1] > 0 {
		res.ResetIn = time.Duration(vals[1]) * time.Millisecond
	}
	c.peeks.Add(1)
	return res, nil
}

// Wait blocks until a single Allow would succeed, then performs that Allow
// once, or returns when ctx is done. It must not keep calling Allow while
// denied (each Allow increments the counter): it peeks, sleeps on ResetIn plus
// a small jitter, then tries Allow once. Sleep is interruptible by ctx.
// A limit <= 0 returns immediately (limiter off for this call).
func (c *RateLimiter) Wait(ctx context.Context, key string, limit int64, window time.Duration) error {
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
	for {
		peeked, err := c.Peek(ctx, key)
		if err != nil {
			c.waitsErr.Add(1)
			return err
		}
		if peeked.Count < limit {
			// Room in the window: try one Allow. This is the single grant
			// attempt per iteration; a lost race falls through to the sleep.
			grant, err := c.Allow(ctx, key, limit, window)
			if err != nil {
				c.waitsErr.Add(1)
				return err
			}
			if grant.Allowed {
				c.waitsOK.Add(1)
				return nil
			}
			peeked = grant // use the fresh ResetIn after the denied increment
		}
		sleep, err := c.waitDelay(ctx, key, peeked.ResetIn)
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

// waitDelay resolves the sleep duration for a Wait pause. When a WaitDelayFunc
// is installed it decides (returning 0 to skip sleeping or an error to abort);
// otherwise it sleeps jittered (base + up to 10% of base, capped by
// wait_jitter_max; no jitter when the cap is 0).
func (c *RateLimiter) waitDelay(ctx context.Context, key string, base time.Duration) (time.Duration, error) {
	c.mu.RLock()
	fn := c.waitDelayFunc
	jitterMax := c.waitJitterMax
	c.mu.RUnlock()

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
// limiter using the component's configured fallback sizing. limit <= 0 still
// short-circuits (disabled_total only) before any policy logic.
func (c *RateLimiter) AllowWithPolicy(ctx context.Context, key string, limit int64, window time.Duration, policy StorageErrorPolicy) (Result, error) {
	if limit <= 0 {
		return c.disabledCall(), nil
	}
	if window <= 0 {
		window = time.Second
	}
	if err := c.validateKey(key); err != nil {
		return Result{}, err
	}
	res, err := c.allowStorage(ctx, key, limit, window)
	if err == nil {
		return res, nil
	}
	// allowStorage already counted the storage error.
	switch policy {
	case StorageFailOpen:
		c.fbOpen.Add(1)
		c.logger.Warn("cf_http_ratelimiter: store error; fail-open", "err", err)
		return Result{Allowed: true}, nil
	case StorageFailClosed:
		c.fbClosed.Add(1)
		return Result{}, err
	case StorageMemoryFallback:
		c.fbMemory.Add(1)
		fb := c.memoryFallbackConfig()
		if fb.Limit <= 0 {
			fb.Limit = limit
		}
		if fb.Window <= 0 {
			fb.Window = window
		}
		return c.allowMemory(ctx, key, fb.Limit, fb.Window, fb)
	default:
		return Result{}, fmt.Errorf("cf_http_ratelimiter: unknown storage error policy %d", policy)
	}
}

// allowStorage dispatches to the active backend without applying any policy.
func (c *RateLimiter) allowStorage(ctx context.Context, key string, limit int64, window time.Duration) (Result, error) {
	if c.memoryBackend {
		return c.allowMemory(ctx, key, limit, window, MemoryFallbackConfig{
			MaxEntries:  c.memoryMaxEntriesValue(),
			WhenMapFull: c.mapFullPolicyValue(),
		})
	}
	return c.allowValkey(ctx, key, limit, window)
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
// tunables (key prefix, metrics, memory sizing, max key length, wait jitter)
// from the bound configuration source. No connection is rebuilt: the valkey
// peer owns client rotation, and this component is stateless over it.
func (c *RateLimiter) OnConfigReload(source string, cfg any) {
	if source != c.configSource || !c.initialized.Load() {
		return
	}
	typed, ok := cfg.(*Config)
	if !ok {
		c.logger.Error("cf_http_ratelimiter: config reload rejected", "source", source, "type", fmt.Sprintf("%T", cfg))
		return
	}
	c.applyConfig(*typed)
	c.reloads.Add(1)
	c.logger.Info("cf_http_ratelimiter: tunables reloaded",
		"key_prefix", c.keyPrefixValue(),
		"metrics_enabled", c.metricsEnabledValue(),
		"max_key_length", c.maxLen(),
	)
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
// after Shutdown. After Init with the valkey backend it delegates to the peer's
// health (a real PING); with the unlocked memory backend it reports healthy
// (the process-local map is ready).
func (c *RateLimiter) Health(ctx context.Context) error {
	if !c.initialized.Load() {
		return errors.New("cf_http_ratelimiter: component is not initialized")
	}
	if c.memoryBackend {
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
