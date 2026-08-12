package cf_http_ratelimiter

import (
	"strings"
	"testing"
)

func TestKeyHasherDeterministic(t *testing.T) {
	h, err := NewKeyHasher("pepper")
	if err != nil {
		t.Fatalf("NewKeyHasher: %v", err)
	}
	a := h.Hash("alice@example.com")
	b := h.Hash("alice@example.com")
	if a != b {
		t.Fatalf("Hash not deterministic: %q vs %q", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("Hash length = %d, want 64 (SHA-256 hex)", len(a))
	}
	if strings.ToLower(a) != a {
		t.Fatal("Hash should be lowercase hex")
	}
}

func TestKeyHasherDistinguishesParts(t *testing.T) {
	h, _ := NewKeyHasher("pepper")
	if h.Hash("alice@example.com") == h.Hash("bob@example.com") {
		t.Fatal("different parts must hash differently")
	}
	if h.Hash("ip:1.2.3.4") == h.Hash("ip:1.2.3.5") {
		t.Fatal("different IPs must hash differently")
	}
}

func TestKeyHasherSecretMatters(t *testing.T) {
	h1, _ := NewKeyHasher("secret-a")
	h2, _ := NewKeyHasher("secret-b")
	if h1.Hash("user") == h2.Hash("user") {
		t.Fatal("different secrets must hash differently")
	}
}

func TestKeyHasherEmptySecret(t *testing.T) {
	if _, err := NewKeyHasher(""); err == nil {
		t.Fatal("NewKeyHasher with empty secret should error")
	}
	if _, err := HashKey("", "user"); err == nil {
		t.Fatal("HashKey with empty secret should error")
	}
}

func TestHashKeyPackageLevel(t *testing.T) {
	h, _ := NewKeyHasher("pepper")
	got, err := HashKey("pepper", "user")
	if err != nil {
		t.Fatalf("HashKey: %v", err)
	}
	if got != h.Hash("user") {
		t.Fatalf("HashKey = %q, want %q", got, h.Hash("user"))
	}
}

func TestHashedKeyFitsDefaultMaxKeyLength(t *testing.T) {
	h, _ := NewKeyHasher("pepper")
	key := "login:" + h.Hash("alice@example.com")
	if len(key) > defaultMaxKeyLength {
		t.Fatalf("hashed login key is %d bytes, over the %d default", len(key), defaultMaxKeyLength)
	}
}
