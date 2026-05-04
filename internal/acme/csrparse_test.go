// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package acme

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

// TestParseCSRPermissive_StdlibPath confirms that a normal Ed25519 CSR
// produced by stdlib still parses unchanged — i.e. the permissive wrapper
// is backward-compatible.
func TestParseCSRPermissive_StdlibPath(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	_ = pub

	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "stdlib.example.com"},
		DNSNames: []string{"stdlib.example.com", "alt.stdlib.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}

	parsed, err := ParseCSRPermissive(csrDER)
	if err != nil {
		t.Fatalf("ParseCSRPermissive: %v", err)
	}
	if parsed.Subject.CommonName != "stdlib.example.com" {
		t.Errorf("CN: got %q, want stdlib.example.com", parsed.Subject.CommonName)
	}
	if len(parsed.DNSNames) != 2 {
		t.Errorf("DNSNames: got %v, want 2 entries", parsed.DNSNames)
	}
	if len(parsed.RawSubjectPublicKeyInfo) == 0 {
		t.Error("RawSubjectPublicKeyInfo is empty")
	}
	if parsed.PublicKey == nil {
		t.Error("PublicKey should be populated when stdlib parse succeeds")
	}
}

// TestParseCSRPermissive_UnknownSPKIAlgorithm builds a CSR with an SPKI whose
// algorithm OID is not in stdlib's recognized list (ML-DSA-65 OID per
// RFC 9881). Modern stdlib accepts the CSR but leaves PublicKey nil; the
// permissive parser must produce the same useful field set whether stdlib
// accepts or rejects.
func TestParseCSRPermissive_UnknownSPKIAlgorithm(t *testing.T) {
	// ML-DSA-65 OID per RFC 9881 §3 (id-ml-dsa-65 = 2.16.840.1.101.3.4.3.18).
	mldsa65OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}

	csrDER, err := buildCSRWithUnknownSPKI(t, mldsa65OID, "test.example.com",
		[]string{"test.example.com", "www.test.example.com"})
	if err != nil {
		t.Fatalf("build synthetic CSR: %v", err)
	}

	// Permissive parser must succeed regardless of whether stdlib accepted.
	parsed, err := ParseCSRPermissive(csrDER)
	if err != nil {
		t.Fatalf("ParseCSRPermissive: %v", err)
	}

	if parsed.Subject.CommonName != "test.example.com" {
		t.Errorf("CN: got %q, want test.example.com", parsed.Subject.CommonName)
	}
	// PublicKey is nil whether stdlib accepted (modern Go) or fell back to the
	// manual parser. Either way, MTC mode never reads it.
	if parsed.PublicKey != nil {
		t.Errorf("PublicKey should be nil for unknown SPKI algorithm, got %T", parsed.PublicKey)
	}
	if len(parsed.RawSubjectPublicKeyInfo) == 0 {
		t.Fatal("RawSubjectPublicKeyInfo is empty")
	}

	// The raw SPKI should contain the ML-DSA-65 OID encoded in DER.
	mldsaOIDDER, _ := asn1.Marshal(mldsa65OID)
	if !bytes.Contains(parsed.RawSubjectPublicKeyInfo, mldsaOIDDER) {
		t.Error("RawSubjectPublicKeyInfo does not contain the expected algorithm OID")
	}

	// DNS names should round-trip.
	if len(parsed.DNSNames) != 2 {
		t.Fatalf("DNSNames count: got %d (%v), want 2", len(parsed.DNSNames), parsed.DNSNames)
	}
	wantNames := map[string]bool{
		"test.example.com":     false,
		"www.test.example.com": false,
	}
	for _, n := range parsed.DNSNames {
		if _, ok := wantNames[n]; !ok {
			t.Errorf("unexpected DNS name %q", n)
		}
		wantNames[n] = true
	}
	for n, seen := range wantNames {
		if !seen {
			t.Errorf("missing DNS name %q in parsed.DNSNames=%v", n, parsed.DNSNames)
		}
	}
}

// TestParseCSRManual_DirectCall exercises the manual ASN.1 fallback path
// directly, since stdlib happens to accept unknown OIDs in current Go
// versions. This guards against regressions in the manual path that
// would otherwise go undetected.
func TestParseCSRManual_DirectCall(t *testing.T) {
	mldsa65OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	csrDER, err := buildCSRWithUnknownSPKI(t, mldsa65OID, "manual.example.com",
		[]string{"manual.example.com"})
	if err != nil {
		t.Fatalf("build synthetic CSR: %v", err)
	}

	parsed, err := parseCSRManual(csrDER)
	if err != nil {
		t.Fatalf("parseCSRManual: %v", err)
	}
	if parsed.Subject.CommonName != "manual.example.com" {
		t.Errorf("CN: got %q, want manual.example.com", parsed.Subject.CommonName)
	}
	if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "manual.example.com" {
		t.Errorf("DNSNames: got %v, want [manual.example.com]", parsed.DNSNames)
	}
	if len(parsed.RawSubjectPublicKeyInfo) == 0 {
		t.Error("RawSubjectPublicKeyInfo empty after manual parse")
	}
	if parsed.PublicKey != nil {
		t.Error("manual parser must leave PublicKey nil")
	}
}

// buildCSRWithUnknownSPKI constructs a syntactically-valid CSR DER whose
// SPKI carries an arbitrary algorithm OID and 1952 bytes of dummy public
// key material (the size of an ML-DSA-65 public key per FIPS 204). The
// CSR self-signature is dummy bytes — stdlib doesn't verify CSR signatures
// in ParseCertificateRequest, and neither does ParseCSRPermissive.
func buildCSRWithUnknownSPKI(t *testing.T, algOID asn1.ObjectIdentifier, cn string, dnsNames []string) ([]byte, error) {
	t.Helper()

	// SubjectPublicKeyInfo with the unknown algorithm.
	type spkiStruct struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	dummyKey := bytes.Repeat([]byte{0x42}, 1952)
	spki := spkiStruct{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: algOID},
		PublicKey: asn1.BitString{Bytes: dummyKey, BitLength: len(dummyKey) * 8},
	}
	spkiDER, err := asn1.Marshal(spki)
	if err != nil {
		return nil, err
	}

	// Subject DN.
	subjectDER, err := asn1.Marshal(pkix.Name{CommonName: cn}.ToRDNSequence())
	if err != nil {
		return nil, err
	}

	// SubjectAltName extension.
	var sanRaw []asn1.RawValue
	for _, name := range dnsNames {
		sanRaw = append(sanRaw, asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   2,
			Bytes: []byte(name),
		})
	}
	sanValue, err := asn1.Marshal(sanRaw)
	if err != nil {
		return nil, err
	}
	sanExt := pkix.Extension{Id: oidSubjectAltName, Value: sanValue}
	extsDER, err := asn1.Marshal([]pkix.Extension{sanExt})
	if err != nil {
		return nil, err
	}

	// extensionRequest attribute (PKCS#9): SET containing the Extensions SEQUENCE.
	type attribute struct {
		Type   asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}
	extReqAttr := attribute{
		Type:   oidExtensionRequest,
		Values: []asn1.RawValue{{FullBytes: extsDER}},
	}

	// CertificationRequestInfo (TBS) — manually so we can drop in the
	// pre-built SPKI raw.
	type tbs struct {
		Version    int
		Subject    asn1.RawValue
		SPKI       asn1.RawValue
		Attributes []attribute `asn1:"tag:0"`
	}
	tbsValue := tbs{
		Version:    0,
		Subject:    asn1.RawValue{FullBytes: subjectDER},
		SPKI:       asn1.RawValue{FullBytes: spkiDER},
		Attributes: []attribute{extReqAttr},
	}
	tbsDER, err := asn1.Marshal(tbsValue)
	if err != nil {
		return nil, err
	}

	// CertificationRequest: TBS, signatureAlgorithm, signature.
	type csrOuter struct {
		TBS                asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          asn1.BitString
	}
	dummySig := bytes.Repeat([]byte{0x99}, 64)
	outer := csrOuter{
		TBS:                asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: algOID},
		Signature:          asn1.BitString{Bytes: dummySig, BitLength: len(dummySig) * 8},
	}
	return asn1.Marshal(outer)
}
