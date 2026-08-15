// Package cf_http_ratelimiter is the Caerus Framework HTTP rate limiter:
// middleware, 429, KeyFunc, fail-open/fail-closed, Wait. The counter store
// (Lua or sticky-note map) lives on valkey-state.
package cf_http_ratelimiter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cf "github.com/caerus-framework/caerus-framework"
	cf_configuration "github.com/caerus-framework/caerus-framework-configuration"
	cf_logs "github.com/caerus-framework/caerus-framework-logs"
	cf_observability "github.com/caerus-framework/caerus-framework-observability"
	cf_valkey_state "github.com/caerus-framework/caerus-framework-valkey-state"
)

const (
	// ComponentName is the framework registry name and default config source name.
	ComponentName = "http-ratelimiter"

	// ComponentStage is the data stage (same wave family as other chassis).
	ComponentStage = cf.Stage("data")

	defaultMaxKeyLength   = 256
	defaultWaitJitterMax  = time.Second
	defaultMetricsEnabled = true
)

// ErrMissingTTL is the state's missing-TTL sentinel (errors.Is works).
var ErrMissingTTL = cf_valkey_state.ErrMissingTTL

// ErrMemoryFallbackDisabled is returned if a call site still uses
// StorageMemoryFallback. Memory is chosen on valkey-state, not here.
var ErrMemoryFallbackDisabled = errors.New("cf_http_ratelimiter: StorageMemoryFallback is removed; set rate_limit memory on valkey-state")

// Result is the HTTP-facing Allow/Peek outcome (same shape as state's RateLimitResult).
type Result struct {
	Allowed bool
	Count   int64
	ResetIn time.Duration
}

func fromState(r cf_valkey_state.RateLimitResult) Result {
	return Result{Allowed: r.Allowed, Count: r.Count, ResetIn: r.ResetIn}
}

// StorageErrorPolicy is what HTTP does when **state already failed**.
type StorageErrorPolicy int

const (
	StorageFailOpen StorageErrorPolicy = iota
	StorageFailClosed
	// StorageMemoryFallback is no longer a store choice. Using it is an error.
	StorageMemoryFallback
)

// MapFullPolicy is kept so old MiddlewareConfig.Memory still compiles; it is
// ignored. Map-full policy lives on valkey-state.
type MapFullPolicy int

const (
	MapFullAllow MapFullPolicy = iota
	MapFullDeny
)

// MissingTTLPolicy may override state's default proceed for Wait/Peek.
type MissingTTLPolicy int

const (
	MissingTTLProceed MissingTTLPolicy = iota + 1
	MissingTTLError
)

// MemoryFallbackConfig is ignored (store sizing is on valkey-state). Kept so
// existing MiddlewareConfig literals compile.
type MemoryFallbackConfig struct {
	MaxEntries  int
	WhenMapFull MapFullPolicy
	Limit       int64
	Window      time.Duration
}

// WaitDelayFunc is called when Wait must pause before retrying Allow.
type WaitDelayFunc func(ctx context.Context, key string, base, jittered time.Duration) (sleep time.Duration, err error)

// WaitOptions overrides Wait behaviour for a single call.
type WaitOptions struct {
	MissingTTLPolicy *MissingTTLPolicy
	DelayFunc        WaitDelayFunc
	delayFuncSet     bool
}

// MiddlewareConfig configures the stdlib Middleware.
type MiddlewareConfig struct {
	Limiter      *RateLimiter
	Limit        int64
	Window       time.Duration
	KeyFunc      func(*http.Request) string
	OnStoreError *StorageErrorPolicy
	Memory       MemoryFallbackConfig
	OnDenied     func(w http.ResponseWriter, r *http.Request, res Result, status int)
}

// Config is HTTP-limiter settings (not the counter store).
type Config struct {
	MetricsEnabled   *bool    `json:"metrics_enabled,omitempty" yaml:"metrics_enabled,omitempty" env:"METRICS_ENABLED"`
	HashIPKeys       *bool    `json:"hash_ip_keys,omitempty" yaml:"hash_ip_keys,omitempty" env:"HASH_IP_KEYS"`
	MaxKeyLength     int      `json:"max_key_length,omitempty" yaml:"max_key_length,omitempty" env:"MAX_KEY_LENGTH"`
	WaitJitterMaxSec *float64 `json:"wait_jitter_max_sec,omitempty" yaml:"wait_jitter_max_sec,omitempty" env:"WAIT_JITTER_MAX_SEC"`
}

// Option configures the rate limiter at construction time.
type Option func(*options)

type options struct {
	loaded         *Config
	configSource   string
	configPath     string
	srcEnvPrefix   string
	srcFormat      cf_configuration.Format
	srcFormatSet   bool
	name           string
	stateName      string
	logger         *slog.Logger
	loggerSet      bool
	maxKeyLength   int
	metricsEnabled bool
	hashIPKeys     bool
	waitJitterMax  time.Duration
	waitDelayFunc  WaitDelayFunc
}

type sourceOptions struct {
	envPrefix string
	format    cf_configuration.Format
	formatSet bool
}

// SourceOption configures the self-registered configuration source.
type SourceOption func(*sourceOptions)

func WithSourceEnvPrefix(prefix string) SourceOption {
	return func(o *sourceOptions) { o.envPrefix = prefix }
}

func WithSourceFormat(f cf_configuration.Format) SourceOption {
	return func(o *sourceOptions) { o.format = f; o.formatSet = true }
}

func defaultSourceEnvPrefix(name string) string {
	return strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_"
}

func WithConfig(cfg Config) Option {
	return func(o *options) { o.loaded = &cfg }
}

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

func WithName(name string) Option {
	return func(o *options) { o.name = name }
}

// WithStateName binds this limiter to a valkey-state component Name().
func WithStateName(name string) Option {
	return func(o *options) { o.stateName = name }
}

func WithLogger(logger *slog.Logger) Option {
	return func(o *options) { o.logger = logger; o.loggerSet = true }
}

func WithMaxKeyLength(n int) Option {
	return func(o *options) { o.maxKeyLength = n }
}

func WithMetricsEnabled(enabled bool) Option {
	return func(o *options) { o.metricsEnabled = enabled }
}

func WithWaitJitterMax(d time.Duration) Option {
	return func(o *options) { o.waitJitterMax = d }
}

func WithWaitDelayFunc(fn WaitDelayFunc) Option {
	return func(o *options) { o.waitDelayFunc = fn }
}

// RateLimiter is the HTTP rate-limiter component. It holds *CFState and never
// a Valkey client.
type RateLimiter struct {
	mu           sync.RWMutex
	configSource string
	configPath   string
	srcEnvPrefix string
	srcFormat    cf_configuration.Format
	srcFormatSet bool
	name         string
	stateName    string
	loggerSet    bool
	fw           *cf.CaerusFramework
	logsSub      *cf_logs.Subscription
	state        *cf_valkey_state.CFState
	initialized  atomic.Bool
	logger       *slog.Logger

	maxKeyLength   int
	metricsEnabled bool
	hashIPKeys     bool
	waitJitterMax  time.Duration
	waitDelayFunc  WaitDelayFunc

	disabledOnce sync.Once

	allows        atomic.Uint64
	denies        atomic.Uint64
	resets        atomic.Uint64
	peeks         atomic.Uint64
	waitsOK       atomic.Uint64
	waitsCanceled atomic.Uint64
	waitsErr      atomic.Uint64
	waitSleepNS   atomic.Int64
	waitSleepCnt  atomic.Uint64
	storageErrors atomic.Uint64
	fbOpen        atomic.Uint64
	fbClosed      atomic.Uint64
	reloads       atomic.Uint64
	disabled      atomic.Uint64
	rejectedEmpty atomic.Uint64
	rejectedLong  atomic.Uint64
}

func New(opts ...Option) *RateLimiter {
	o := options{
		logger:         slog.Default(),
		maxKeyLength:   defaultMaxKeyLength,
		metricsEnabled: defaultMetricsEnabled,
		waitJitterMax:  defaultWaitJitterMax,
	}
	for _, opt := range opts {
		opt(&o)
	}
	c := &RateLimiter{
		configSource:   o.configSource,
		configPath:     o.configPath,
		srcEnvPrefix:   o.srcEnvPrefix,
		srcFormat:      o.srcFormat,
		srcFormatSet:   o.srcFormatSet,
		name:           o.name,
		stateName:      o.stateName,
		logger:         o.logger,
		loggerSet:      o.loggerSet,
		maxKeyLength:   o.maxKeyLength,
		metricsEnabled: o.metricsEnabled,
		hashIPKeys:     o.hashIPKeys,
		waitJitterMax:  o.waitJitterMax,
		waitDelayFunc:  o.waitDelayFunc,
	}
	if o.loaded != nil {
		c.applyConfigLocked(*o.loaded)
	}
	return c
}

func (c *RateLimiter) applyConfigLocked(cfg Config) {
	if cfg.MetricsEnabled != nil {
		c.metricsEnabled = *cfg.MetricsEnabled
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
}

func (c *RateLimiter) Name() string {
	if c.name != "" {
		return c.name
	}
	return ComponentName
}

func (c *RateLimiter) GetInitOrderStage() cf.Stage { return ComponentStage }

func (c *RateLimiter) GetDependencies() []string {
	deps := []string{c.peerName(), cf_logs.ComponentName}
	if c.configSource != "" {
		deps = append(deps, cf_configuration.ComponentName)
	}
	return deps
}

func (c *RateLimiter) peerName() string {
	if c.stateName != "" {
		return c.stateName
	}
	return cf_valkey_state.ComponentName
}

func (c *RateLimiter) Init(ctx context.Context, fw *cf.CaerusFramework) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.initialized.Load() {
		return nil
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
	st, ok := cf.GetByName[*cf_valkey_state.CFState](fw, c.peerName())
	if !ok {
		return fmt.Errorf("cf_http_ratelimiter: valkey-state component %q is not registered", c.peerName())
	}
	c.state = st
	c.initialized.Store(true)
	return nil
}

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

func (c *RateLimiter) Shutdown(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.logsSub != nil {
		c.logsSub.Unsubscribe()
		c.logsSub = nil
	}
	c.state = nil
	c.initialized.Store(false)
	return nil
}

func (c *RateLimiter) peer() *cf_valkey_state.CFState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

func (c *RateLimiter) maxLen() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.maxKeyLength <= 0 {
		return defaultMaxKeyLength
	}
	return c.maxKeyLength
}

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

func (c *RateLimiter) disabledCall() Result {
	c.disabled.Add(1)
	c.disabledOnce.Do(func() {
		c.logger.Warn("cf_http_ratelimiter: Allow/Wait called with limit <= 0; rate limiting disabled for this call — check the caller's config")
	})
	return Result{Allowed: true}
}

func (c *RateLimiter) Allow(ctx context.Context, key string, limit int64, window time.Duration) (Result, error) {
	if limit <= 0 {
		return c.disabledCall(), nil
	}
	if window <= 0 {
		return Result{}, errors.New("cf_http_ratelimiter: window must be > 0")
	}
	if err := c.validateKey(key); err != nil {
		return Result{}, err
	}
	st := c.peer()
	if st == nil {
		c.storageErrors.Add(1)
		return Result{}, errors.New("cf_http_ratelimiter: not initialized")
	}
	res, err := st.Allow(ctx, key, limit, window)
	if err != nil {
		c.storageErrors.Add(1)
		return Result{}, err
	}
	if res.Allowed {
		c.allows.Add(1)
	} else {
		c.denies.Add(1)
	}
	return fromState(res), nil
}

func (c *RateLimiter) Reset(ctx context.Context, key string) error {
	if err := c.validateKey(key); err != nil {
		return err
	}
	st := c.peer()
	if st == nil {
		c.storageErrors.Add(1)
		return errors.New("cf_http_ratelimiter: not initialized")
	}
	if err := st.Reset(ctx, key); err != nil {
		c.storageErrors.Add(1)
		return err
	}
	c.resets.Add(1)
	return nil
}

func (c *RateLimiter) Peek(ctx context.Context, key string) (Result, error) {
	return c.peekOpts(ctx, key, cf_valkey_state.CounterOpts{})
}

func (c *RateLimiter) peekOpts(ctx context.Context, key string, opts cf_valkey_state.CounterOpts) (Result, error) {
	if err := c.validateKey(key); err != nil {
		return Result{}, err
	}
	st := c.peer()
	if st == nil {
		c.storageErrors.Add(1)
		return Result{}, errors.New("cf_http_ratelimiter: not initialized")
	}
	res, err := st.PeekOpts(ctx, key, opts)
	if err != nil {
		c.storageErrors.Add(1)
		return Result{}, err
	}
	c.peeks.Add(1)
	return fromState(res), nil
}

func (c *RateLimiter) Wait(ctx context.Context, key string, limit int64, window time.Duration) error {
	return c.WaitOpts(ctx, key, limit, window, WaitOptions{})
}

func (c *RateLimiter) WaitOpts(ctx context.Context, key string, limit int64, window time.Duration, opts WaitOptions) error {
	if limit <= 0 {
		c.disabled.Add(1)
		c.disabledOnce.Do(func() {
			c.logger.Warn("cf_http_ratelimiter: Wait called with limit <= 0; rate limiting disabled for this call — check the caller's config")
		})
		return nil
	}
	if window <= 0 {
		c.waitsErr.Add(1)
		return errors.New("cf_http_ratelimiter: window must be > 0")
	}
	if err := c.validateKey(key); err != nil {
		c.waitsErr.Add(1)
		return err
	}
	stOpts := cf_valkey_state.CounterOpts{}
	if opts.MissingTTLPolicy != nil && *opts.MissingTTLPolicy == MissingTTLError {
		stOpts.MissingTTL = cf_valkey_state.MissingTTLError
	}
	for {
		peeked, err := c.peekOpts(ctx, key, stOpts)
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
			c.logger.Error("cf_http_ratelimiter: Wait saw ResetIn<=0 after peek; refusing busy-loop")
			if opts.MissingTTLPolicy != nil && *opts.MissingTTLPolicy == MissingTTLError {
				c.waitsErr.Add(1)
				return ErrMissingTTL
			}
			continue
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

func (c *RateLimiter) AllowWithPolicy(ctx context.Context, key string, limit int64, window time.Duration, policy StorageErrorPolicy) (Result, error) {
	return c.AllowWithPolicyOpts(ctx, key, limit, window, policy, MemoryFallbackConfig{})
}

func (c *RateLimiter) AllowWithPolicyOpts(ctx context.Context, key string, limit int64, window time.Duration, policy StorageErrorPolicy, _ MemoryFallbackConfig) (Result, error) {
	if policy == StorageMemoryFallback {
		return Result{}, ErrMemoryFallbackDisabled
	}
	res, err := c.Allow(ctx, key, limit, window)
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
	default:
		return Result{}, fmt.Errorf("cf_http_ratelimiter: unknown storage error policy %d", policy)
	}
}

func (c *RateLimiter) HashIPKeys() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hashIPKeys
}

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
	c.applyConfigLocked(*typed)
	c.mu.Unlock()
	c.reloads.Add(1)
}

func (c *RateLimiter) metricsEnabledValue() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metricsEnabled
}

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

func (c *RateLimiter) Health(ctx context.Context) error {
	if !c.initialized.Load() {
		return errors.New("cf_http_ratelimiter: component is not initialized")
	}
	st := c.peer()
	if st == nil {
		return errors.New("cf_http_ratelimiter: valkey-state peer is missing")
	}
	return st.Health(ctx)
}

var _ cf.CaerusComponent = (*RateLimiter)(nil)
var _ cf.Dependencies = (*RateLimiter)(nil)
var _ cf.HealthProvider = (*RateLimiter)(nil)
var _ cf_observability.MetricsProvider = (*RateLimiter)(nil)
var _ cf.ConfigReloader = (*RateLimiter)(nil)
var _ cf.ConfigSourceRegistrar = (*RateLimiter)(nil)
