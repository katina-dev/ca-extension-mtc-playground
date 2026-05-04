// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Command cert-size-report measures issued MTC certificate sizes across a
// matrix of subject-key algorithms. For each (algorithm, count) cell it
// generates a keypair, builds a CSR, drives an ACME order against the
// bridge, downloads the issued cert, and writes a CSV row with the
// observed cert / SPKI / MTC-proof sizes.
//
// Usage:
//
//	cert-size-report -acme-url https://localhost:8443 \
//	                 -algorithms ed25519,ecdsa256,rsa2048,mldsa44,mldsa65,mldsa87 \
//	                 -count-per-algo 5 -output sizes.csv
//
// Output CSV columns:
//
//	timestamp,subject_algo,leaf_index,cert_bytes,spki_bytes,proof_bytes,proof_hashes,subtree_end
//
// Leaf index increases monotonically across the run, so plotting cert_bytes
// vs leaf_index also reveals proof-length growth as the tree gets bigger.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/briantrzupek/ca-extension-merkle/internal/mtccert"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// ML-DSA OIDs per RFC 9881 §3.
var (
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

	oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	oidSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
)

func main() {
	acmeURL := flag.String("acme-url", "https://localhost:8443", "ACME server base URL")
	algoCSV := flag.String("algorithms", "ed25519,ecdsa256,rsa2048,mldsa44,mldsa65,mldsa87",
		"comma-separated subject-key algorithms to issue with")
	count := flag.Int("count-per-algo", 3, "certs to issue per algorithm")
	domainPrefix := flag.String("domain-prefix", "size", "DNS name prefix; full = <prefix>-<algo>-<i>.example.com")
	insecure := flag.Bool("insecure", true, "skip TLS verification (self-signed bridge cert)")
	output := flag.String("output", "cert-sizes.csv", "CSV output path")
	verbose := flag.Bool("verbose", false, "log each issued cert")
	flag.Parse()

	algorithms := strings.Split(*algoCSV, ",")
	for i, a := range algorithms {
		algorithms[i] = strings.TrimSpace(a)
	}

	out, err := os.Create(*output)
	if err != nil {
		die("open output: %v", err)
	}
	defer out.Close()

	w := newCSV(out)
	w.header("timestamp", "subject_algo", "leaf_index", "cert_bytes",
		"spki_bytes", "proof_bytes", "proof_hashes", "subtree_end")

	httpClient := newHTTPClient(*insecure)
	c, err := newACMEClient(*acmeURL, httpClient)
	if err != nil {
		die("acme client init: %v", err)
	}
	if err := c.createAccount(); err != nil {
		die("create account: %v", err)
	}

	runID := time.Now().Format("150405")
	totalIssued := 0
	for _, algo := range algorithms {
		if !knownAlgorithm(algo) {
			fmt.Fprintf(os.Stderr, "[skip] unknown algorithm %q\n", algo)
			continue
		}
		for i := 0; i < *count; i++ {
			domain := fmt.Sprintf("%s-%s-%s-%d.example.com", *domainPrefix, algo, runID, i)
			certPEM, err := c.issueOneCert(algo, domain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[fail] %s/%d: %v\n", algo, i, err)
				continue
			}
			m, err := measureCert(certPEM)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[fail] measure %s/%d: %v\n", algo, i, err)
				continue
			}
			w.row(time.Now().UTC().Format(time.RFC3339),
				algo,
				fmt.Sprintf("%d", m.LeafIndex),
				fmt.Sprintf("%d", m.CertBytes),
				fmt.Sprintf("%d", m.SPKIBytes),
				fmt.Sprintf("%d", m.ProofBytes),
				fmt.Sprintf("%d", m.ProofHashes),
				fmt.Sprintf("%d", m.SubtreeEnd))
			totalIssued++
			if *verbose {
				fmt.Printf("%-10s leaf=%-6d cert=%-5d spki=%-5d proof=%-5d hashes=%d\n",
					algo, m.LeafIndex, m.CertBytes, m.SPKIBytes, m.ProofBytes, m.ProofHashes)
			}
		}
	}

	fmt.Printf("\nWrote %d rows to %s\n", totalIssued, *output)
}

// CertMeasurement is the per-cert size record we write to CSV.
type CertMeasurement struct {
	LeafIndex   int64
	CertBytes   int
	SPKIBytes   int
	ProofBytes  int // total bytes consumed by the inclusion proof in the cert
	ProofHashes int
	SubtreeEnd  uint64
}

// measureCert parses a PEM-encoded MTC cert and extracts size fields.
func measureCert(certPEM []byte) (*CertMeasurement, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	parsed, err := mtccert.ParseMTCCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse mtc cert: %w", err)
	}
	m := &CertMeasurement{
		LeafIndex:   parsed.SerialNumber,
		CertBytes:   len(block.Bytes),
		SPKIBytes:   len(parsed.SubjectPubKeyInfo),
		ProofHashes: len(parsed.Proof.InclusionProof),
		SubtreeEnd:  parsed.Proof.End,
	}
	// Proof bytes: 32 per hash + a small per-cert envelope (subtree start/end +
	// signatures length prefix in signatureless mode). We report just the
	// inclusion-proof contribution since that's the algorithm-independent
	// growth term verifiers care about.
	m.ProofBytes = m.ProofHashes * 32
	return m, nil
}

// knownAlgorithm reports whether algo is one of the supported subject-key
// algorithms.
func knownAlgorithm(algo string) bool {
	switch algo {
	case "ed25519", "ecdsa256", "rsa2048", "mldsa44", "mldsa65", "mldsa87":
		return true
	}
	return false
}

// genKeyAndCSR returns a CSR DER for the given algorithm. The keypair is
// generated fresh each call. CSR signature is real for classical algorithms
// (built via stdlib) and real for ML-DSA (built manually with CIRCL).
func genKeyAndCSR(algo, domain string) ([]byte, error) {
	switch algo {
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return x509.CreateCertificateRequest(rand.Reader, csrTemplate(domain), priv)
	case "ecdsa256":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return x509.CreateCertificateRequest(rand.Reader, csrTemplate(domain), priv)
	case "rsa2048":
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		return x509.CreateCertificateRequest(rand.Reader, csrTemplate(domain), priv)
	case "mldsa44":
		pub, priv, err := mldsa44.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		pubBytes, _ := pub.MarshalBinary()
		return buildMLDSACSR(domain, oidMLDSA44, pubBytes, func(msg []byte) []byte {
			sig := make([]byte, mldsa44.SignatureSize)
			_ = mldsa44.SignTo(priv, msg, nil, false, sig)
			return sig
		})
	case "mldsa65":
		pub, priv, err := mldsa65.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		pubBytes, _ := pub.MarshalBinary()
		return buildMLDSACSR(domain, oidMLDSA65, pubBytes, func(msg []byte) []byte {
			sig := make([]byte, mldsa65.SignatureSize)
			_ = mldsa65.SignTo(priv, msg, nil, false, sig)
			return sig
		})
	case "mldsa87":
		pub, priv, err := mldsa87.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		pubBytes, _ := pub.MarshalBinary()
		return buildMLDSACSR(domain, oidMLDSA87, pubBytes, func(msg []byte) []byte {
			sig := make([]byte, mldsa87.SignatureSize)
			_ = mldsa87.SignTo(priv, msg, nil, false, sig)
			return sig
		})
	}
	return nil, fmt.Errorf("unsupported algorithm %q", algo)
}

func csrTemplate(domain string) *x509.CertificateRequest {
	return &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain, Organization: []string{"Cert-Size Report"}, Country: []string{"US"}},
		DNSNames: []string{domain},
	}
}

// buildMLDSACSR constructs a PKCS#10 CSR DER with an ML-DSA SPKI and a real
// ML-DSA signature over the CertificationRequestInfo. The bridge's permissive
// CSR parser doesn't verify CSR signatures, but signing properly here keeps
// the artifact valid for downstream tools that do.
func buildMLDSACSR(domain string, algOID asn1.ObjectIdentifier, pubKey []byte, sign func([]byte) []byte) ([]byte, error) {
	type spkiStruct struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	spkiDER, err := asn1.Marshal(spkiStruct{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: algOID},
		PublicKey: asn1.BitString{Bytes: pubKey, BitLength: len(pubKey) * 8},
	})
	if err != nil {
		return nil, err
	}

	subjectDER, err := asn1.Marshal(pkix.Name{
		CommonName:   domain,
		Organization: []string{"Cert-Size Report"},
		Country:      []string{"US"},
	}.ToRDNSequence())
	if err != nil {
		return nil, err
	}

	// SAN extension: SEQUENCE { [2] IA5String "domain" }.
	sanValue, err := asn1.Marshal([]asn1.RawValue{{
		Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(domain),
	}})
	if err != nil {
		return nil, err
	}
	extsDER, err := asn1.Marshal([]pkix.Extension{{Id: oidSubjectAltName, Value: sanValue}})
	if err != nil {
		return nil, err
	}

	type csrAttribute struct {
		Type   asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}
	type tbs struct {
		Version    int
		Subject    asn1.RawValue
		SPKI       asn1.RawValue
		Attributes []csrAttribute `asn1:"tag:0"`
	}
	tbsValue := tbs{
		Version: 0,
		Subject: asn1.RawValue{FullBytes: subjectDER},
		SPKI:    asn1.RawValue{FullBytes: spkiDER},
		Attributes: []csrAttribute{{
			Type:   oidExtensionRequest,
			Values: []asn1.RawValue{{FullBytes: extsDER}},
		}},
	}
	tbsDER, err := asn1.Marshal(tbsValue)
	if err != nil {
		return nil, err
	}

	sig := sign(tbsDER)
	type csrOuter struct {
		TBS                asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          asn1.BitString
	}
	return asn1.Marshal(csrOuter{
		TBS:                asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: algOID},
		Signature:          asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
}

// =====================================================================
// ACME client (subset of bulk-issue's, kept self-contained on purpose)
// =====================================================================

type acmeClient struct {
	baseURL    string
	http       *http.Client
	directory  map[string]string
	accountKey *ecdsa.PrivateKey
	kid        string
}

func newACMEClient(baseURL string, h *http.Client) (*acmeClient, error) {
	c := &acmeClient{baseURL: baseURL, http: h, directory: map[string]string{}}
	resp, err := h.Get(baseURL + "/acme/directory")
	if err != nil {
		return nil, fmt.Errorf("get directory: %w", err)
	}
	defer resp.Body.Close()
	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode directory: %w", err)
	}
	for k, v := range raw {
		if s, ok := v.(string); ok {
			c.directory[k] = s
		}
	}
	return c, nil
}

func (c *acmeClient) createAccount() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	c.accountKey = priv

	// JWK for the account key (RFC 7638 thumbprint format).
	jwk := jwkForECDSA(&priv.PublicKey)

	// Initial JWS uses jwk header (no kid yet).
	body, status, hdr, err := c.postWithJWK(c.directory["newAccount"], jwk, map[string]interface{}{
		"termsOfServiceAgreed": true,
	})
	if err != nil {
		return fmt.Errorf("new-account: %w", err)
	}
	if status != 201 && status != 200 {
		return fmt.Errorf("new-account status %d: %s", status, body)
	}
	c.kid = hdr.Get("Location")
	return nil
}

func (c *acmeClient) issueOneCert(algo, domain string) ([]byte, error) {
	// 1. new-order
	body, status, hdr, err := c.post(c.directory["newOrder"], map[string]interface{}{
		"identifiers": []map[string]string{{"type": "dns", "value": domain}},
	})
	if err != nil {
		return nil, fmt.Errorf("new-order: %w", err)
	}
	if status != 201 {
		return nil, fmt.Errorf("new-order status %d: %s", status, body)
	}
	var order map[string]interface{}
	json.Unmarshal(body, &order)
	orderURL := hdr.Get("Location")

	// 2. authz + http-01 challenge (auto-approved by bridge)
	authzURL := order["authorizations"].([]interface{})[0].(string)
	body, _, _, _ = c.post(authzURL, nil)
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
	if _, _, _, err := c.post(challengeURL, map[string]interface{}{}); err != nil {
		return nil, fmt.Errorf("post challenge: %w", err)
	}

	// 3. wait for ready
	if err := c.poll(orderURL, "ready", 10*time.Second); err != nil {
		return nil, fmt.Errorf("wait ready: %w", err)
	}

	// 4. CSR + finalize
	csrDER, err := genKeyAndCSR(algo, domain)
	if err != nil {
		return nil, fmt.Errorf("genCSR(%s): %w", algo, err)
	}
	body, _, _, _ = c.post(orderURL, nil)
	json.Unmarshal(body, &order)
	finalizeURL := order["finalize"].(string)
	if _, status, _, err := c.post(finalizeURL, map[string]interface{}{
		"csr": base64.RawURLEncoding.EncodeToString(csrDER),
	}); err != nil {
		return nil, fmt.Errorf("finalize: %w", err)
	} else if status != 200 {
		return nil, fmt.Errorf("finalize status %d", status)
	}

	// 5. wait for valid + download cert
	if err := c.poll(orderURL, "valid", 30*time.Second); err != nil {
		return nil, fmt.Errorf("wait valid: %w", err)
	}
	body, _, _, _ = c.post(orderURL, nil)
	json.Unmarshal(body, &order)
	certURL, _ := order["certificate"].(string)
	if certURL == "" {
		return nil, fmt.Errorf("no certificate URL")
	}
	body, status, _, err = c.post(certURL, nil)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	if status != 200 {
		return nil, fmt.Errorf("download status %d", status)
	}
	return body, nil
}

func (c *acmeClient) poll(orderURL, want string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		body, _, _, _ := c.post(orderURL, nil)
		var o map[string]interface{}
		json.Unmarshal(body, &o)
		if st, _ := o["status"].(string); st == want {
			return nil
		}
	}
	return fmt.Errorf("poll timeout waiting for %q", want)
}

func (c *acmeClient) nonce() (string, error) {
	resp, err := c.http.Head(c.directory["newNonce"])
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return resp.Header.Get("Replay-Nonce"), nil
}

func (c *acmeClient) post(url string, payload interface{}) ([]byte, int, http.Header, error) {
	return c.signedRequest(url, payload, "")
}

func (c *acmeClient) postWithJWK(url string, jwk map[string]interface{}, payload interface{}) ([]byte, int, http.Header, error) {
	return c.signedRequestWithJWK(url, payload, jwk)
}

func (c *acmeClient) signedRequest(url string, payload interface{}, _ string) ([]byte, int, http.Header, error) {
	nonce, err := c.nonce()
	if err != nil {
		return nil, 0, nil, fmt.Errorf("nonce: %w", err)
	}
	header := map[string]interface{}{
		"alg":   "ES256",
		"nonce": nonce,
		"url":   url,
		"kid":   c.kid,
	}
	return c.doSigned(url, payload, header)
}

func (c *acmeClient) signedRequestWithJWK(url string, payload interface{}, jwk map[string]interface{}) ([]byte, int, http.Header, error) {
	nonce, err := c.nonce()
	if err != nil {
		return nil, 0, nil, fmt.Errorf("nonce: %w", err)
	}
	header := map[string]interface{}{
		"alg":   "ES256",
		"nonce": nonce,
		"url":   url,
		"jwk":   jwk,
	}
	return c.doSigned(url, payload, header)
}

func (c *acmeClient) doSigned(url string, payload interface{}, header map[string]interface{}) ([]byte, int, http.Header, error) {
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	var payloadB64 string
	if payload != nil {
		pb, _ := json.Marshal(payload)
		payloadB64 = base64.RawURLEncoding.EncodeToString(pb)
	}

	signing := headerB64 + "." + payloadB64
	hash := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, c.accountKey, hash[:])
	if err != nil {
		return nil, 0, nil, err
	}
	sig := make([]byte, 64)
	rb, sb := r.Bytes(), s.Bytes()
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):], sb)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	body, _ := json.Marshal(map[string]string{
		"protected": headerB64,
		"payload":   payloadB64,
		"signature": sigB64,
	})

	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return respBody, resp.StatusCode, resp.Header, nil
}

// =====================================================================
// helpers
// =====================================================================

func jwkForECDSA(pub *ecdsa.PublicKey) map[string]interface{} {
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	xPad := make([]byte, 32)
	yPad := make([]byte, 32)
	copy(xPad[32-len(x):], x)
	copy(yPad[32-len(y):], y)
	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xPad),
		"y":   base64.RawURLEncoding.EncodeToString(yPad),
	}
}

// =====================================================================
// CSV writer
// =====================================================================

type csvWriter struct {
	w io.Writer
}

func newCSV(w io.Writer) *csvWriter { return &csvWriter{w: w} }

func (c *csvWriter) header(cols ...string) {
	fmt.Fprintln(c.w, strings.Join(cols, ","))
}

func (c *csvWriter) row(cols ...string) {
	fmt.Fprintln(c.w, strings.Join(cols, ","))
}

// =====================================================================
// HTTP
// =====================================================================

func newHTTPClient(insecure bool) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

