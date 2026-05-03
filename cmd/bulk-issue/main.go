// Command bulk-issue runs the ACME order → finalize → download flow N times
// against the local mtc-bridge ACME endpoint. Each successful run appends one
// entry to the Merkle tree (leaf index becomes the cert serial in MTC mode).
//
// Useful for populating the visualizer with realistic data, stress-testing the
// issuance log, and generating consistency-proof opportunities.
//
// Example:
//
//	bulk-issue -count 100 -concurrency 8 -insecure
//
// Reuses a single ACME account across all orders for efficiency. Domains are
// generated as <prefix>-<unix_nano>-<i>.example.com to avoid collisions
// across runs.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	acmeURL := flag.String("acme-url", "https://localhost:8443", "ACME server base URL")
	count := flag.Int("count", 10, "Number of certificates to issue")
	concurrency := flag.Int("concurrency", 4, "Number of parallel orders")
	domainPrefix := flag.String("domain-prefix", "bulk", "Domain prefix; full DNS = <prefix>-<runID>-<i>.example.com")
	insecure := flag.Bool("insecure", true, "Skip TLS verification (self-signed ACME cert)")
	verbose := flag.Bool("verbose", false, "Print one line per issued cert")
	flag.Parse()

	if *count <= 0 {
		fmt.Fprintln(os.Stderr, "count must be positive")
		os.Exit(1)
	}
	if *concurrency <= 0 {
		*concurrency = 1
	}

	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure},
		},
	}

	cli := &acmeClient{baseURL: *acmeURL, http: client}

	// One account, reused across all orders.
	acctKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate account key: %v\n", err)
		os.Exit(1)
	}
	kid, err := cli.createAccount(acctKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create account: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Account: %s\n", kid)

	runID := time.Now().UnixNano() % 1_000_000
	start := time.Now()

	var ok, fail int64
	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup

	for i := 0; i < *count; i++ {
		i := i
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			domain := fmt.Sprintf("%s-%d-%d.example.com", *domainPrefix, runID, i)
			serial, err := cli.issueOne(acctKey, kid, domain)
			if err != nil {
				atomic.AddInt64(&fail, 1)
				fmt.Fprintf(os.Stderr, "[%d/%d] %s: %v\n", i+1, *count, domain, err)
				return
			}
			atomic.AddInt64(&ok, 1)
			if *verbose {
				fmt.Printf("[%d/%d] %s serial=%s\n", i+1, *count, domain, serial)
			}
		}()
	}
	wg.Wait()

	elapsed := time.Since(start)
	rate := float64(ok) / elapsed.Seconds()
	fmt.Printf("\nDone: %d issued, %d failed in %s (%.1f cert/s)\n", ok, fail, elapsed.Round(time.Millisecond), rate)
	if fail > 0 {
		os.Exit(1)
	}
}

// --- ACME client ---

type acmeClient struct {
	baseURL string
	http    *http.Client
}

func (c *acmeClient) nonce() (string, error) {
	resp, err := c.http.Head(c.baseURL + "/acme/new-nonce")
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		return "", fmt.Errorf("no Replay-Nonce header")
	}
	return n, nil
}

// post sends a JWS-signed POST. Use kid="" to embed the JWK (account creation),
// otherwise the account URL is referenced via kid.
func (c *acmeClient) post(url string, key *ecdsa.PrivateKey, payload interface{}, kid string) ([]byte, int, http.Header, error) {
	nonce, err := c.nonce()
	if err != nil {
		return nil, 0, nil, fmt.Errorf("nonce: %w", err)
	}

	hdr := map[string]interface{}{"alg": "ES256", "nonce": nonce, "url": url}
	if kid != "" {
		hdr["kid"] = kid
	} else {
		hdr["jwk"] = json.RawMessage(jwkFromPub(&key.PublicKey))
	}
	hdrJSON, _ := json.Marshal(hdr)
	protected := base64.RawURLEncoding.EncodeToString(hdrJSON)

	var payloadStr string
	if payload != nil {
		pj, _ := json.Marshal(payload)
		payloadStr = base64.RawURLEncoding.EncodeToString(pj)
	}

	sigInput := protected + "." + payloadStr
	hash := sha256.Sum256([]byte(sigInput))
	rInt, sInt, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return nil, 0, nil, fmt.Errorf("sign: %w", err)
	}
	rB, sB := rInt.Bytes(), sInt.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rB):32], rB)
	copy(sig[64-len(sB):64], sB)

	body := fmt.Sprintf(`{"protected":"%s","payload":"%s","signature":"%s"}`,
		protected, payloadStr, base64.RawURLEncoding.EncodeToString(sig))
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	return respBody, resp.StatusCode, resp.Header, err
}

func jwkFromPub(pub *ecdsa.PublicKey) string {
	x := base64.RawURLEncoding.EncodeToString(pub.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(pub.Y.Bytes())
	return fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}`, x, y)
}

func (c *acmeClient) createAccount(key *ecdsa.PrivateKey) (string, error) {
	payload := map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:bulk-issue@example.com"},
	}
	_, status, hdr, err := c.post(c.baseURL+"/acme/new-account", key, payload, "")
	if err != nil {
		return "", err
	}
	if status != 200 && status != 201 {
		return "", fmt.Errorf("status %d", status)
	}
	loc := hdr.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("no Location header")
	}
	return loc, nil
}

// issueOne runs the full order → finalize → download flow for one domain.
// Returns the cert's hex-encoded serial (== leaf index in MTC mode).
func (c *acmeClient) issueOne(key *ecdsa.PrivateKey, kid, domain string) (string, error) {
	// Order
	body, status, hdr, err := c.post(c.baseURL+"/acme/new-order", key, map[string]interface{}{
		"identifiers": []map[string]string{{"type": "dns", "value": domain}},
	}, kid)
	if err != nil {
		return "", fmt.Errorf("new-order: %w", err)
	}
	if status != 201 {
		return "", fmt.Errorf("new-order status %d: %s", status, body)
	}
	var order map[string]interface{}
	json.Unmarshal(body, &order)
	orderURL := hdr.Get("Location")
	authzs := order["authorizations"].([]interface{})

	// Authz + http-01 challenge (auto-approved by the bridge)
	body, status, _, err = c.post(authzs[0].(string), key, nil, kid)
	if err != nil {
		return "", fmt.Errorf("get authz: %w", err)
	}
	var authz map[string]interface{}
	json.Unmarshal(body, &authz)
	var challengeURL string
	for _, ch := range authz["challenges"].([]interface{}) {
		m := ch.(map[string]interface{})
		if m["type"] == "http-01" {
			challengeURL = m["url"].(string)
			break
		}
	}
	if challengeURL == "" {
		return "", fmt.Errorf("no http-01 challenge")
	}
	if _, status, _, err = c.post(challengeURL, key, map[string]interface{}{}, kid); err != nil {
		return "", fmt.Errorf("post challenge: %w", err)
	}
	if status != 200 {
		return "", fmt.Errorf("challenge status %d", status)
	}

	// Wait for ready
	if err := c.pollOrder(key, kid, orderURL, "ready", 10*time.Second); err != nil {
		return "", fmt.Errorf("wait ready: %w", err)
	}

	// Re-fetch order to get the finalize URL after polling
	body, _, _, _ = c.post(orderURL, key, nil, kid)
	json.Unmarshal(body, &order)
	finalizeURL := order["finalize"].(string)

	// CSR
	csrKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("csr key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain, Organization: []string{"Bulk Issue"}, Country: []string{"US"}},
		DNSNames: []string{domain},
	}, csrKey)
	if err != nil {
		return "", fmt.Errorf("create csr: %w", err)
	}
	body, status, _, err = c.post(finalizeURL, key, map[string]interface{}{
		"csr": base64.RawURLEncoding.EncodeToString(csrDER),
	}, kid)
	if err != nil {
		return "", fmt.Errorf("finalize: %w", err)
	}
	if status != 200 {
		return "", fmt.Errorf("finalize status %d: %s", status, body)
	}

	// Wait for valid + extract certificate URL
	if err := c.pollOrder(key, kid, orderURL, "valid", 30*time.Second); err != nil {
		return "", fmt.Errorf("wait valid: %w", err)
	}
	body, _, _, _ = c.post(orderURL, key, nil, kid)
	json.Unmarshal(body, &order)
	certURL, _ := order["certificate"].(string)
	if certURL == "" {
		return "", fmt.Errorf("no certificate URL")
	}

	// Download (POST-as-GET) — verifies the chain reached us, gives us the serial
	body, status, _, err = c.post(certURL, key, nil, kid)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	if status != 200 {
		return "", fmt.Errorf("download status %d", status)
	}
	serial, err := extractSerial(body)
	if err != nil {
		return "", fmt.Errorf("parse cert: %w", err)
	}
	return serial, nil
}

func (c *acmeClient) pollOrder(key *ecdsa.PrivateKey, kid, orderURL, want string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		body, _, _, err := c.post(orderURL, key, nil, kid)
		if err != nil {
			continue
		}
		var o map[string]interface{}
		json.Unmarshal(body, &o)
		st, _ := o["status"].(string)
		if st == want {
			return nil
		}
		if st == "invalid" {
			detail := ""
			if e, ok := o["error"].(map[string]interface{}); ok {
				detail, _ = e["detail"].(string)
			}
			return fmt.Errorf("order invalid: %s", detail)
		}
	}
	return fmt.Errorf("timeout waiting for %s", want)
}

func extractSerial(certPEM []byte) (string, error) {
	// The bridge returns PEM that may have an MTC assertion bundle appended;
	// only the first BEGIN CERTIFICATE block matters for the serial.
	const begin = "-----BEGIN CERTIFICATE-----"
	const end = "-----END CERTIFICATE-----"
	s := string(certPEM)
	bi := indexOf(s, begin)
	if bi < 0 {
		return "", fmt.Errorf("no certificate block")
	}
	rest := s[bi+len(begin):]
	ei := indexOf(rest, end)
	if ei < 0 {
		return "", fmt.Errorf("no end-cert marker")
	}
	der, err := base64.StdEncoding.DecodeString(stripWhitespace(rest[:ei]))
	if err != nil {
		return "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%X", cert.SerialNumber.Bytes()), nil
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func stripWhitespace(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\n' && c != '\r' && c != ' ' && c != '\t' {
			out = append(out, c)
		}
	}
	return string(out)
}
