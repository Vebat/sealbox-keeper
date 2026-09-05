// Package keyring holds the master key versions of a keeper and derives one
// wrapping key per key name from them, so a single secret serves any number
// of named keys. Every ciphertext names the master version that made it, so
// versions can be added, and retired once nothing refers to them.
//
// No custom cryptography: keys are derived with HKDF-SHA256, values are
// sealed with XChaCha20-Poly1305 from golang.org/x/crypto under a random
// 24-byte nonce, with the caller's context as associated data.
package keyring

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeySize is the length in bytes of a master key.
const KeySize = chacha20poly1305.KeySize

const prefix = "keeper:"

var (
	// ErrCiphertext covers every malformed, tampered or mismatched
	// ciphertext. The reason is deliberately not distinguished.
	ErrCiphertext = errors.New("keeper: invalid ciphertext")
	// ErrRetiredVersion means the ciphertext names a master key version this
	// keeper no longer holds. Load it again, or the data is gone.
	ErrRetiredVersion = errors.New("keeper: ciphertext names a master key version this keeper does not have")
)

// Keyring seals under the current master version and opens under any loaded one.
type Keyring struct {
	current string
	masters map[string][]byte
}

// New returns a Keyring for the given master key versions, current first.
func New(masters [][]byte) (*Keyring, error) {
	if len(masters) == 0 {
		return nil, errors.New("keyring: no master key")
	}
	k := &Keyring{masters: map[string][]byte{}}
	for i, m := range masters {
		if len(m) != KeySize {
			return nil, fmt.Errorf("keyring: master key %d must be %d bytes", i+1, KeySize)
		}
		id := KeyID(m)
		if i == 0 {
			k.current = id
		}
		k.masters[id] = m
	}
	return k, nil
}

// KeyID is a short fingerprint of a master key version. It travels inside
// every ciphertext and cannot be turned back into the key.
func KeyID(master []byte) string {
	m := hmac.New(sha256.New, master)
	m.Write([]byte("keeper/key-id/v1"))
	return hex.EncodeToString(m.Sum(nil))[:16]
}

// CurrentID is the fingerprint of the version that makes new ciphertexts.
func (k *Keyring) CurrentID() string { return k.current }

// Encrypt seals plaintext for the named key under the current master
// version, bound to context. The result is "keeper:<version>:<base64>".
func (k *Keyring) Encrypt(name string, plaintext, context []byte) (string, error) {
	aead, err := k.aead(k.current, name)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	rand.Read(nonce)
	sealed := aead.Seal(nonce, nonce, plaintext, context)
	return prefix + k.current + ":" + base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt is the inverse of Encrypt. name and context must match.
func (k *Keyring) Decrypt(name, ciphertext string, context []byte) ([]byte, error) {
	version, blob, err := parse(ciphertext)
	if err != nil {
		return nil, err
	}
	aead, err := k.aead(version, name)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(blob) < ns {
		return nil, ErrCiphertext
	}
	plaintext, err := aead.Open(nil, blob[:ns], blob[ns:], context)
	if err != nil {
		return nil, ErrCiphertext
	}
	return plaintext, nil
}

// Rewrap returns the ciphertext re-sealed under the current master version.
// The bool reports whether anything changed.
func (k *Keyring) Rewrap(name, ciphertext string, context []byte) (string, bool, error) {
	version, _, err := parse(ciphertext)
	if err != nil {
		return "", false, err
	}
	if version == k.current {
		return ciphertext, false, nil
	}
	plaintext, err := k.Decrypt(name, ciphertext, context)
	if err != nil {
		return "", false, err
	}
	out, err := k.Encrypt(name, plaintext, context)
	return out, err == nil, err
}

// aead derives the wrapping key for name from one master version. Two names
// never share a key, and a ciphertext made for one name does not open under
// another.
func (k *Keyring) aead(version, name string) (cipher.AEAD, error) {
	master, ok := k.masters[version]
	if !ok {
		return nil, ErrRetiredVersion
	}
	derived, err := hkdf.Key(sha256.New, master, nil, "keeper/key/v1/"+name, KeySize)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.NewX(derived)
}

func parse(ciphertext string) (version string, blob []byte, err error) {
	rest, ok := strings.CutPrefix(ciphertext, prefix)
	if !ok {
		return "", nil, ErrCiphertext
	}
	version, encoded, ok := strings.Cut(rest, ":")
	if !ok || len(version) != 16 {
		return "", nil, ErrCiphertext
	}
	blob, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", nil, ErrCiphertext
	}
	return version, blob, nil
}
