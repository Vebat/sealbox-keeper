// Command keeper runs a small key service speaking the Vault transit
// protocol. sealbox points at it with SEALBOX_KMS=transit; the master key
// never leaves this process.
//
// Configuration is taken from the environment:
//
//	KEEPER_MASTER_KEY        master key versions, base64, one per line or comma-separated,
//	KEEPER_MASTER_KEY_FILE   current first; exactly one of the two
//	KEEPER_CLIENTS_FILE      JSON file of named clients with tokens, key names and rate limits, see clients.example.json
//	KEEPER_TOKEN             one extra token allowed every key, for development
//	KEEPER_ADDR              listen address, default :8200
//	KEEPER_TLS_CERT          PEM certificate; together with KEEPER_TLS_KEY enables TLS
//	KEEPER_TLS_KEY           PEM private key
//	KEEPER_TLS_CLIENT_CA     PEM CA bundle; when set, clients must present a certificate it signed
//	KEEPER_INSECURE_HTTP     "1" allows plaintext HTTP on a non-loopback address
//
// Without a certificate the server only listens on loopback addresses.
// Every call is written to stdout as one JSON line; ship those lines
// somewhere this host cannot rewrite.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Vebat/sealbox-keeper/internal/api"
	"github.com/Vebat/sealbox-keeper/internal/keyring"
)

func main() {
	if err := harden(); err != nil {
		log.Printf("warning: %v", err)
	}

	masters, err := loadMasterKeys()
	if err != nil {
		log.Fatal(err)
	}
	ring, err := keyring.New(masters)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("master key %s, %d previous version(s) loaded", ring.CurrentID(), len(masters)-1)

	clients, err := api.LoadClients(os.Getenv("KEEPER_CLIENTS_FILE"))
	if err != nil {
		log.Fatal(err)
	}
	if t := os.Getenv("KEEPER_TOKEN"); t != "" {
		clients = append(clients, api.Client{Name: "default", Token: t, Keys: []string{"*"}})
	}
	if len(clients) == 0 {
		log.Fatal("no clients: set KEEPER_CLIENTS_FILE or KEEPER_TOKEN")
	}
	if err := api.ValidateClients(clients); err != nil {
		log.Fatal(err)
	}
	log.Printf("clients: %d", len(clients))

	addr := os.Getenv("KEEPER_ADDR")
	if addr == "" {
		addr = ":8200"
	}
	cert, key, clientCA := os.Getenv("KEEPER_TLS_CERT"), os.Getenv("KEEPER_TLS_KEY"), os.Getenv("KEEPER_TLS_CLIENT_CA")
	if (cert == "") != (key == "") {
		log.Fatal("set both KEEPER_TLS_CERT and KEEPER_TLS_KEY, or neither")
	}
	useTLS := cert != ""
	if !useTLS && clientCA != "" {
		log.Fatal("KEEPER_TLS_CLIENT_CA needs KEEPER_TLS_CERT and KEEPER_TLS_KEY")
	}
	if !useTLS && !isLoopback(addr) && os.Getenv("KEEPER_INSECURE_HTTP") != "1" {
		log.Fatalf("refusing plaintext HTTP on %s: set KEEPER_TLS_CERT and KEEPER_TLS_KEY, or KEEPER_INSECURE_HTTP=1 if TLS is terminated in front of keeper", addr)
	}

	audit := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.Handle("/v1/transit/", api.New(ring, clients, audit))

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	if !useTLS {
		log.Printf("keeper listening on %s (plaintext HTTP)", addr)
		log.Fatal(srv.ListenAndServe())
	}
	srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	if clientCA != "" {
		pool, err := loadCA(clientCA)
		if err != nil {
			log.Fatal(err)
		}
		srv.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		srv.TLSConfig.ClientCAs = pool
		log.Printf("keeper listening on %s (TLS, client certificates required)", addr)
	} else {
		log.Printf("keeper listening on %s (TLS)", addr)
	}
	log.Fatal(srv.ListenAndServeTLS(cert, key))
}

func loadCA(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("KEEPER_TLS_CLIENT_CA: no certificates found")
	}
	return pool, nil
}

// loadMasterKeys reads the master key versions from exactly one source.
func loadMasterKeys() ([][]byte, error) {
	var raw string
	sources := 0
	if v := os.Getenv("KEEPER_MASTER_KEY"); v != "" {
		raw = v
		sources++
	}
	if path := os.Getenv("KEEPER_MASTER_KEY_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		raw = string(b)
		sources++
	}
	if sources != 1 {
		return nil, errors.New("set exactly one of KEEPER_MASTER_KEY, KEEPER_MASTER_KEY_FILE")
	}
	var keys [][]byte
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' }) {
		key, err := base64.StdEncoding.DecodeString(field)
		if err != nil || len(key) != keyring.KeySize {
			return nil, errors.New("each master key must be 32 random bytes, base64-encoded: openssl rand -base64 32")
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("no master key found")
	}
	return keys, nil
}

// isLoopback reports whether addr binds only to the local machine.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
