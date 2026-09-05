// Package api serves the subset of the Vault transit protocol that sealbox
// speaks: encrypt, decrypt and rewrap of a named key. Every call is
// authenticated by a client token, decrypt and rewrap are rate-limited per
// client, and every call, allowed or refused, goes to the audit log without
// any key material.
package api

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/Vebat/sealbox-keeper/internal/keyring"
)

const (
	maxBody                 = 256 << 10 // a wrapped key is tens of bytes; a batch of 500 fits with room
	minTokenLen             = 16
	defaultDecryptPerSecond = 200
)

var keyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Client is one holder of a token. Keys lists the key names it may use,
// or "*" for any. DecryptPerSecond caps decrypt and rewrap calls, the ones
// that hand out key material; 0 means the default. The burst is five
// seconds' worth, so a batch reveal of a thousand objects still fits.
type Client struct {
	Name             string   `json:"-"`
	Token            string   `json:"token"`
	Keys             []string `json:"keys"`
	DecryptPerSecond float64  `json:"decrypt_per_second"`
}

func (c Client) allows(key string) bool {
	return slices.Contains(c.Keys, "*") || slices.Contains(c.Keys, key)
}

// LoadClients reads a clients file of the form
//
//	{"sealbox-prod": {"token": "...", "keys": ["sealbox"], "decrypt_per_second": 200}}
//
// An empty path yields no clients.
func LoadClients(path string) ([]Client, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseClients(data)
}

// ParseClients decodes a clients document.
func ParseClients(data []byte) ([]Client, error) {
	var byName map[string]Client
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&byName); err != nil {
		return nil, fmt.Errorf("clients: %w", err)
	}
	clients := make([]Client, 0, len(byName))
	for name, c := range byName {
		c.Name = name
		clients = append(clients, c)
	}
	return clients, ValidateClients(clients)
}

// ValidateClients rejects nameless or duplicate names, short or shared
// tokens, empty or malformed key lists, and negative rates.
func ValidateClients(clients []Client) error {
	names := map[string]bool{}
	owner := map[string]string{}
	for _, c := range clients {
		if c.Name == "" {
			return errors.New("clients: client without a name")
		}
		if names[c.Name] {
			return fmt.Errorf("clients: two clients named %s", c.Name)
		}
		names[c.Name] = true
		if len(c.Token) < minTokenLen {
			return fmt.Errorf("clients: %s: token must be at least %d characters", c.Name, minTokenLen)
		}
		if other, dup := owner[c.Token]; dup {
			return fmt.Errorf("clients: %s and %s share a token", other, c.Name)
		}
		owner[c.Token] = c.Name
		if len(c.Keys) == 0 {
			return fmt.Errorf("clients: %s: no keys", c.Name)
		}
		for _, k := range c.Keys {
			if k != "*" && !keyRe.MatchString(k) {
				return fmt.Errorf("clients: %s: invalid key name %q", c.Name, k)
			}
		}
		if c.DecryptPerSecond < 0 {
			return fmt.Errorf("clients: %s: negative rate", c.Name)
		}
	}
	return nil
}

type server struct {
	ring     *keyring.Keyring
	clients  []Client
	limiters map[string]*rate.Limiter
	audit    *slog.Logger
}

// New returns the /v1/transit handler. clients must have passed
// ValidateClients. audit receives one record per call.
func New(ring *keyring.Keyring, clients []Client, audit *slog.Logger) http.Handler {
	s := &server{ring: ring, clients: clients, limiters: map[string]*rate.Limiter{}, audit: audit}
	for _, c := range clients {
		per := c.DecryptPerSecond
		if per == 0 {
			per = defaultDecryptPerSecond
		}
		s.limiters[c.Name] = rate.NewLimiter(rate.Limit(per), int(per*5))
	}
	mux := http.NewServeMux()
	for _, op := range []string{"encrypt", "decrypt", "rewrap"} {
		mux.HandleFunc("POST /v1/transit/"+op+"/{key}", s.handle(op))
	}
	return mux
}

func (s *server) handle(op string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.PathValue("key")
		c, ok := s.authenticate(r.Header.Get("X-Vault-Token"))
		if !ok {
			s.refuse(w, r, "", op, key, http.StatusForbidden, "permission denied")
			return
		}
		if !keyRe.MatchString(key) {
			s.refuse(w, r, c.Name, op, key, http.StatusBadRequest, "invalid key name")
			return
		}
		if !c.allows(key) {
			s.refuse(w, r, c.Name, op, key, http.StatusForbidden, "permission denied")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			s.refuse(w, r, c.Name, op, key, http.StatusBadRequest, "body too large or unreadable")
			return
		}
		var req struct {
			Plaintext  string `json:"plaintext"`
			Ciphertext string `json:"ciphertext"`
			Context    string `json:"context"`
			Batch      []struct {
				Ciphertext string `json:"ciphertext"`
				Context    string `json:"context"`
			} `json:"batch_input"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			s.refuse(w, r, c.Name, op, key, http.StatusBadRequest, "invalid request")
			return
		}
		units := 1
		if len(req.Batch) > 0 {
			if op != "decrypt" {
				s.refuse(w, r, c.Name, op, key, http.StatusBadRequest, "batch_input is only supported for decrypt")
				return
			}
			units = len(req.Batch)
		}
		if op != "encrypt" && !s.limiters[c.Name].AllowN(time.Now(), units) {
			s.refuse(w, r, c.Name, op, key, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		if len(req.Batch) > 0 {
			// One result per input, in order; a bad item fails alone.
			results := make([]map[string]string, 0, len(req.Batch))
			for _, item := range req.Batch {
				context, err := base64.StdEncoding.DecodeString(item.Context)
				if err != nil {
					results = append(results, map[string]string{"error": "context must be base64"})
					continue
				}
				plaintext, err := s.ring.Decrypt(key, item.Ciphertext, context)
				if err != nil {
					results = append(results, map[string]string{"error": err.Error()})
					continue
				}
				results = append(results, map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintext)})
			}
			s.audit.Info("transit", "client", c.Name, "op", op, "key", key, "status", http.StatusOK, "batch", len(results))
			writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"batch_results": results}})
			return
		}
		context, err := base64.StdEncoding.DecodeString(req.Context)
		if err != nil {
			s.refuse(w, r, c.Name, op, key, http.StatusBadRequest, "context must be base64")
			return
		}

		var data map[string]string
		switch op {
		case "encrypt":
			plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
			if err != nil || len(plaintext) == 0 {
				s.refuse(w, r, c.Name, op, key, http.StatusBadRequest, "plaintext must be base64")
				return
			}
			ct, err := s.ring.Encrypt(key, plaintext, context)
			if err != nil {
				s.refuse(w, r, c.Name, op, key, http.StatusInternalServerError, "internal error")
				return
			}
			data = map[string]string{"ciphertext": ct, "key_id": s.ring.CurrentID()}
		case "decrypt":
			plaintext, err := s.ring.Decrypt(key, req.Ciphertext, context)
			if err != nil {
				s.refuse(w, r, c.Name, op, key, http.StatusBadRequest, err.Error())
				return
			}
			data = map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintext)}
		case "rewrap":
			ct, _, err := s.ring.Rewrap(key, req.Ciphertext, context)
			if err != nil {
				s.refuse(w, r, c.Name, op, key, http.StatusBadRequest, err.Error())
				return
			}
			data = map[string]string{"ciphertext": ct, "key_id": s.ring.CurrentID()}
		}
		s.audit.Info("transit", "client", c.Name, "op", op, "key", key, "status", http.StatusOK)
		writeJSON(w, http.StatusOK, map[string]any{"data": data})
	}
}

// authenticate finds the client presenting the token. Both sides are hashed
// first, so the constant-time comparison does not depend on length, and
// every client is compared, so timing does not say which was close.
func (s *server) authenticate(token string) (Client, bool) {
	got := sha256.Sum256([]byte(token))
	var found Client
	matched := false
	for _, c := range s.clients {
		want := sha256.Sum256([]byte(c.Token))
		if subtle.ConstantTimeCompare(got[:], want[:]) == 1 {
			found, matched = c, true
		}
	}
	return found, matched
}

// refuse answers in the transit error format and logs the refusal. For an
// unauthenticated caller the remote address stands in for the client name.
func (s *server) refuse(w http.ResponseWriter, r *http.Request, client, op, key string, status int, msg string) {
	if client == "" {
		client = "unauthenticated " + strings.TrimSpace(r.RemoteAddr)
	}
	s.audit.Warn("transit", "client", client, "op", op, "key", key, "status", status, "reason", msg)
	writeJSON(w, status, map[string][]string{"errors": {msg}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
