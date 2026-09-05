package keyring

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func key(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeySize)
	rand.Read(k)
	return k
}

func mustNew(t *testing.T, masters ...[]byte) *Keyring {
	t.Helper()
	k, err := New(masters)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRoundtrip(t *testing.T) {
	k := mustNew(t, key(t))
	ct, err := k.Encrypt("sealbox", []byte("dek"), []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ct, "keeper:"+k.CurrentID()+":") {
		t.Fatalf("ciphertext %q", ct)
	}
	pt, err := k.Decrypt("sealbox", ct, []byte("ctx"))
	if err != nil || !bytes.Equal(pt, []byte("dek")) {
		t.Fatalf("got %q, %v", pt, err)
	}
	again, _ := k.Encrypt("sealbox", []byte("dek"), []byte("ctx"))
	if again == ct {
		t.Fatal("two encryptions of the same value must differ")
	}
}

func TestBinding(t *testing.T) {
	k := mustNew(t, key(t))
	ct, _ := k.Encrypt("sealbox", []byte("dek"), []byte("ctx"))
	if _, err := k.Decrypt("sealbox", ct, []byte("other")); !errors.Is(err, ErrCiphertext) {
		t.Fatalf("wrong context: %v", err)
	}
	if _, err := k.Decrypt("other-key", ct, []byte("ctx")); !errors.Is(err, ErrCiphertext) {
		t.Fatalf("wrong key name: %v", err)
	}
	if _, err := mustNew(t, key(t)).Decrypt("sealbox", ct, []byte("ctx")); !errors.Is(err, ErrRetiredVersion) {
		t.Fatalf("other master: %v", err)
	}
}

func TestMalformed(t *testing.T) {
	k := mustNew(t, key(t))
	ct, _ := k.Encrypt("sealbox", []byte("dek"), nil)
	tampered := ct[:len(ct)-2] + "AA"
	for name, c := range map[string]string{
		"tampered":     tampered,
		"no prefix":    strings.TrimPrefix(ct, "keeper:"),
		"short":        "keeper:" + k.CurrentID() + ":AAAA",
		"bad base64":   "keeper:" + k.CurrentID() + ":not base64!",
		"empty":        "",
		"vault format": "vault:v1:abc",
	} {
		if _, err := k.Decrypt("sealbox", c, nil); !errors.Is(err, ErrCiphertext) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestVersionsAndRewrap(t *testing.T) {
	old, fresh := key(t), key(t)
	ct, _ := mustNew(t, old).Encrypt("sealbox", []byte("dek"), []byte("ctx"))

	// The new version is current, the old one still opens.
	both := mustNew(t, fresh, old)
	if both.CurrentID() != KeyID(fresh) {
		t.Fatal("first master must be current")
	}
	if pt, err := both.Decrypt("sealbox", ct, []byte("ctx")); err != nil || string(pt) != "dek" {
		t.Fatalf("decrypt old during rotation: %q, %v", pt, err)
	}
	re, changed, err := both.Rewrap("sealbox", ct, []byte("ctx"))
	if err != nil || !changed || !strings.HasPrefix(re, "keeper:"+KeyID(fresh)+":") {
		t.Fatalf("rewrap: changed=%v err=%v %q", changed, err, re)
	}
	if _, changed, _ := both.Rewrap("sealbox", re, []byte("ctx")); changed {
		t.Fatal("rewrap of a current ciphertext must be a no-op")
	}
	if _, _, err := both.Rewrap("sealbox", ct, []byte("other")); !errors.Is(err, ErrCiphertext) {
		t.Fatalf("rewrap with wrong context: %v", err)
	}

	// The old version retired: rewrapped data opens, the rest is gone.
	only := mustNew(t, fresh)
	if pt, err := only.Decrypt("sealbox", re, []byte("ctx")); err != nil || string(pt) != "dek" {
		t.Fatalf("decrypt rewrapped with new only: %q, %v", pt, err)
	}
	if _, err := only.Decrypt("sealbox", ct, []byte("ctx")); !errors.Is(err, ErrRetiredVersion) {
		t.Fatalf("old ciphertext with new only: %v", err)
	}
}

func TestNew(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("no master: expected error")
	}
	if _, err := New([][]byte{make([]byte, 16)}); err == nil {
		t.Error("short master: expected error")
	}
	a := key(t)
	if KeyID(a) != KeyID(a) || len(KeyID(a)) != 16 || KeyID(a) == KeyID(key(t)) {
		t.Error("key id must be stable, 16 hex chars, and distinct per key")
	}
}
