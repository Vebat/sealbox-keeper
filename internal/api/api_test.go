package api

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Vebat/sealbox-keeper/internal/keyring"
)

const (
	sealboxToken = "sealbox-token-0123456789"
	otherToken   = "other-token-0123456789ab"
)

var testClients = []Client{
	{Name: "sealbox", Token: sealboxToken, Keys: []string{"sealbox"}, DecryptPerSecond: 2},
	{Name: "other", Token: otherToken, Keys: []string{"other"}},
}

func newServer(t *testing.T) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	master := make([]byte, keyring.KeySize)
	rand.Read(master)
	ring, err := keyring.New([][]byte{master})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateClients(testClients); err != nil {
		t.Fatal(err)
	}
	var audit bytes.Buffer
	srv := httptest.NewServer(New(ring, testClients, slog.New(slog.NewJSONHandler(&audit, nil))))
	t.Cleanup(srv.Close)
	return srv, &audit
}

// call posts the way sealbox's transit client does and returns the status
// and the data or errors object.
func call(t *testing.T, srv *httptest.Server, token, op, key string, body map[string]string) (int, map[string]string, []string) {
	t.Helper()
	payload, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", srv.URL+"/v1/transit/"+op+"/"+key, bytes.NewReader(payload))
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var res struct {
		Data   map[string]string `json:"data"`
		Errors []string          `json:"errors"`
	}
	json.Unmarshal(raw, &res)
	return resp.StatusCode, res.Data, res.Errors
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestEncryptDecryptRewrap(t *testing.T) {
	srv, audit := newServer(t)
	status, data, _ := call(t, srv, sealboxToken, "encrypt", "sealbox", map[string]string{"plaintext": b64("dek"), "context": b64("objects/customers/tok_1")})
	if status != http.StatusOK || !strings.HasPrefix(data["ciphertext"], "keeper:") || data["key_id"] == "" {
		t.Fatalf("encrypt: %d %v", status, data)
	}
	ct := data["ciphertext"]

	status, data, _ = call(t, srv, sealboxToken, "decrypt", "sealbox", map[string]string{"ciphertext": ct, "context": b64("objects/customers/tok_1")})
	if status != http.StatusOK || data["plaintext"] != b64("dek") {
		t.Fatalf("decrypt: %d %v", status, data)
	}

	status, data, _ = call(t, srv, sealboxToken, "rewrap", "sealbox", map[string]string{"ciphertext": ct, "context": b64("objects/customers/tok_1")})
	if status != http.StatusOK || data["ciphertext"] != ct {
		t.Fatalf("rewrap under the same version must return the same ciphertext: %d %v", status, data)
	}

	for name, body := range map[string]map[string]string{
		"wrong context": {"ciphertext": ct, "context": b64("objects/customers/tok_2")},
		"tampered":      {"ciphertext": ct[:len(ct)-2] + "AA", "context": b64("objects/customers/tok_1")},
		"garbage":       {"ciphertext": "vault:v1:abc", "context": b64("x")},
		"bad context":   {"ciphertext": ct, "context": "not base64!"},
	} {
		if status, _, errs := call(t, srv, sealboxToken, "decrypt", "sealbox", body); status != http.StatusBadRequest || len(errs) == 0 {
			t.Errorf("%s: %d %v", name, status, errs)
		}
	}
	if status, _, _ := call(t, srv, sealboxToken, "encrypt", "sealbox", map[string]string{"plaintext": ""}); status != http.StatusBadRequest {
		t.Errorf("empty plaintext: %d", status)
	}

	// The audit log names client, op, key and status, never material.
	log := audit.String()
	for _, want := range []string{`"client":"sealbox"`, `"op":"encrypt"`, `"op":"decrypt"`, `"key":"sealbox"`, `"status":200`, `"status":400`} {
		if !strings.Contains(log, want) {
			t.Errorf("audit log lacks %s:\n%s", want, log)
		}
	}
	for _, leak := range []string{b64("dek"), "dek", ct} {
		if strings.Contains(log, leak) {
			t.Errorf("audit log leaks %q", leak)
		}
	}
}

func TestAuth(t *testing.T) {
	srv, audit := newServer(t)
	body := map[string]string{"plaintext": b64("dek")}
	for name, tc := range map[string]struct {
		token, key string
		want       int
	}{
		"no token":         {"", "sealbox", http.StatusForbidden},
		"wrong token":      {"nope-0123456789abcdef", "sealbox", http.StatusForbidden},
		"prefixed token":   {sealboxToken + "x", "sealbox", http.StatusForbidden},
		"key not allowed":  {otherToken, "sealbox", http.StatusForbidden},
		"invalid key name": {sealboxToken, "Sealbox!", http.StatusBadRequest},
		"allowed":          {sealboxToken, "sealbox", http.StatusOK},
	} {
		if status, _, _ := call(t, srv, tc.token, "encrypt", tc.key, body); status != tc.want {
			t.Errorf("%s: expected %d, got %d", name, tc.want, status)
		}
	}
	if !strings.Contains(audit.String(), `"client":"unauthenticated `) {
		t.Errorf("refusals without a token must be logged with the remote address:\n%s", audit.String())
	}
}

func TestRateLimit(t *testing.T) {
	srv, _ := newServer(t)
	_, data, _ := call(t, srv, sealboxToken, "encrypt", "sealbox", map[string]string{"plaintext": b64("dek")})
	body := map[string]string{"ciphertext": data["ciphertext"]}
	// sealbox's limit is 2/s with a burst of 10: the eleventh decrypt in a row is refused.
	limited := 0
	for range 12 {
		if status, _, _ := call(t, srv, sealboxToken, "decrypt", "sealbox", body); status == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("expected the burst to run out")
	}
	// Encrypt hands out no material and is never limited; other clients are unaffected.
	if status, _, _ := call(t, srv, sealboxToken, "encrypt", "sealbox", map[string]string{"plaintext": b64("dek")}); status != http.StatusOK {
		t.Errorf("encrypt limited: %d", status)
	}
	if status, _, _ := call(t, srv, otherToken, "encrypt", "other", map[string]string{"plaintext": b64("dek")}); status != http.StatusOK {
		t.Errorf("other client affected: %d", status)
	}
}

func TestParseClients(t *testing.T) {
	clients, err := ParseClients([]byte(`{"sealbox-prod": {"token": "0123456789abcdef", "keys": ["sealbox"], "decrypt_per_second": 50}}`))
	if err != nil || len(clients) != 1 || clients[0].Name != "sealbox-prod" || clients[0].DecryptPerSecond != 50 {
		t.Fatalf("got %+v, %v", clients, err)
	}
	for name, doc := range map[string]string{
		"short token":   `{"a": {"token": "short", "keys": ["k"]}}`,
		"no keys":       `{"a": {"token": "0123456789abcdef", "keys": []}}`,
		"bad key name":  `{"a": {"token": "0123456789abcdef", "keys": ["Bad Key"]}}`,
		"shared token":  `{"a": {"token": "0123456789abcdef", "keys": ["k"]}, "b": {"token": "0123456789abcdef", "keys": ["k"]}}`,
		"negative rate": `{"a": {"token": "0123456789abcdef", "keys": ["k"], "decrypt_per_second": -1}}`,
		"unknown field": `{"a": {"token": "0123456789abcdef", "keys": ["k"], "admin": true}}`,
		"not json":      `nope`,
	} {
		if _, err := ParseClients([]byte(doc)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
