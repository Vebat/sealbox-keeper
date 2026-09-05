package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8200": true,
		"localhost:8200": true,
		"[::1]:8200":     true,
		":8200":          false,
		"0.0.0.0:8200":   false,
		"garbage":        false,
	} {
		if got := isLoopback(addr); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestLoadMasterKeys(t *testing.T) {
	k1, k2 := make([]byte, 32), make([]byte, 32)
	rand.Read(k1)
	rand.Read(k2)
	b1, b2 := base64.StdEncoding.EncodeToString(k1), base64.StdEncoding.EncodeToString(k2)

	t.Setenv("KEEPER_MASTER_KEY_FILE", "")
	t.Setenv("KEEPER_MASTER_KEY", b1+"\n"+b2)
	keys, err := loadMasterKeys()
	if err != nil || len(keys) != 2 || !bytes.Equal(keys[0], k1) || !bytes.Equal(keys[1], k2) {
		t.Fatalf("got %d keys, %v", len(keys), err)
	}
	for name, value := range map[string]string{
		"empty":      "",
		"short":      "c2hvcnQ=",
		"not base64": "nope!",
	} {
		t.Setenv("KEEPER_MASTER_KEY", value)
		if _, err := loadMasterKeys(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
