package cf_http_ratelimiter

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// KeyHasher hashes PII-ish key parts (emails, optionally IPs) before they
// become rate-limit keys. Emails/account ids are always hashed in the recipes;
// IPs are hashed when the app enables hash_ip_keys. The secret is app-owned (a
// pepper or a dedicated rate_limit_key_secret) and must never be logged or
// stored next to pre-hash identities.
type KeyHasher struct {
	secret []byte
}

// NewKeyHasher creates a KeyHasher with the given secret. An empty secret is
// an error: hashing with no secret is effectively a plain SHA-256 and defeats
// the purpose.
func NewKeyHasher(secret string) (*KeyHasher, error) {
	if secret == "" {
		return nil, errors.New("cf_http_ratelimiter: KeyHasher secret must not be empty")
	}
	return &KeyHasher{secret: []byte(secret)}, nil
}

// Hash returns the lowercase hex HMAC-SHA256 of part. The output is stable for
// the same secret+part and is 64 hex characters, so a key like
// "login:"+hash fits the default 256-byte MaxKeyLength.
func (h *KeyHasher) Hash(part string) string {
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(part))
	return hex.EncodeToString(mac.Sum(nil))
}

// HashKey is the package-level convenience form of KeyHasher.Hash.
func HashKey(secret, part string) (string, error) {
	if secret == "" {
		return "", errors.New("cf_http_ratelimiter: HashKey secret must not be empty")
	}
	h, err := NewKeyHasher(secret)
	if err != nil {
		return "", err
	}
	return h.Hash(part), nil
}
