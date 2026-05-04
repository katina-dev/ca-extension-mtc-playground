// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package acme

// CSR parsing that tolerates unknown SubjectPublicKeyInfo algorithm OIDs.
//
// As of Go 1.21, stdlib's x509.ParseCertificateRequest does not error on an
// unknown SPKI algorithm — it sets PublicKey to nil and PublicKeyAlgorithm
// to UnknownPublicKeyAlgorithm but otherwise populates the request. That
// happens to be enough for MTC mode, which only needs Subject, DNSNames,
// and RawSubjectPublicKeyInfo (the SPKI is copied into the leaf cert as
// opaque bytes — the bridge never interprets the public key).
//
// ParseCSRPermissive is defensive: it wraps the stdlib call so that if a
// future Go version tightens parsing (or any other parse failure occurs),
// we fall back to a manual ASN.1 walk that extracts the same minimal field
// set. PublicKey is left nil on the fallback path. MTC mode tolerates this;
// the legacy ECDSA-signing path will fail at x509.CreateCertificate time
// with a clearer downstream error if someone sends a non-stdlib SPKI to a
// non-MTC bridge.

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// oidExtensionRequest is the PKCS#9 attribute carrying X.509 extensions
// inside a CSR (RFC 2985 §5.4.2).
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// oidSubjectAltName is the X.509 SAN extension OID (RFC 5280 §4.2.1.6).
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// ParseCSRPermissive parses a PKCS#10 CSR, falling back to a manual ASN.1
// walk when stdlib rejects the SPKI's algorithm OID (e.g. ML-DSA, SLH-DSA).
//
// On the manual fallback path the returned CSR has:
//   - Subject populated from the CertificationRequestInfo Subject field
//   - DNSNames populated from any SubjectAltName extension in the
//     extensionRequest attribute
//   - RawSubjectPublicKeyInfo populated with the SPKI bytes verbatim
//   - PublicKey left nil (caller must handle this — MTC mode does, legacy
//     ECDSA-signing mode does not)
//   - Raw and RawTBSCertificateRequest populated for downstream code that
//     needs the original DER
//
// CSR self-signature is NOT verified on the fallback path. Stdlib's
// ParseCertificateRequest also doesn't verify it (verification is opt-in
// via csr.CheckSignature), so this matches existing behavior — domain
// control is established via ACME challenges, not CSR signature.
func ParseCSRPermissive(csrDER []byte) (*x509.CertificateRequest, error) {
	if csr, err := x509.ParseCertificateRequest(csrDER); err == nil {
		return csr, nil
	}
	return parseCSRManual(csrDER)
}

// certificationRequest mirrors PKCS#10 CertificationRequest with raw fields
// so we can survive unknown OIDs in the SPKI.
type certificationRequest struct {
	Raw                asn1.RawContent
	TBS                certificationRequestInfo
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
}

type certificationRequestInfo struct {
	Raw        asn1.RawContent
	Version    int
	Subject    asn1.RawValue
	SPKI       asn1.RawValue
	Attributes []csrAttribute `asn1:"tag:0"`
}

// csrAttribute models PKCS#10 Attribute manually because pkix.AttributeTypeAndValueSET
// assumes the values are SEQUENCE OF AttributeTypeAndValue (OID/value pairs),
// which is wrong for extensionRequest — there the SET wraps an Extensions
// SEQUENCE directly.
type csrAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

func parseCSRManual(csrDER []byte) (*x509.CertificateRequest, error) {
	var req certificationRequest
	rest, err := asn1.Unmarshal(csrDER, &req)
	if err != nil {
		return nil, fmt.Errorf("acme: manual CSR parse: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("acme: manual CSR parse: trailing data")
	}

	// Subject: stdlib RDNSequence handling works regardless of SPKI algorithm.
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(req.TBS.Subject.FullBytes, &rdn); err != nil {
		return nil, fmt.Errorf("acme: manual CSR parse: subject: %w", err)
	}
	var name pkix.Name
	name.FillFromRDNSequence(&rdn)

	dnsNames, err := dnsNamesFromAttributes(req.TBS.Attributes)
	if err != nil {
		return nil, fmt.Errorf("acme: manual CSR parse: attributes: %w", err)
	}

	return &x509.CertificateRequest{
		Raw:                      append([]byte(nil), csrDER...),
		RawTBSCertificateRequest: append([]byte(nil), req.TBS.Raw...),
		RawSubjectPublicKeyInfo:  append([]byte(nil), req.TBS.SPKI.FullBytes...),
		RawSubject:               append([]byte(nil), req.TBS.Subject.FullBytes...),
		Version:                  req.TBS.Version,
		Subject:                  name,
		DNSNames:                 dnsNames,
		// PublicKey is intentionally nil — MTC mode treats SPKI as opaque bytes.
		// Legacy ECDSA-signing mode will fail downstream if someone sends a
		// non-stdlib SPKI to a non-MTC bridge.
	}, nil
}

// dnsNamesFromAttributes walks the CSR's Attributes for an extensionRequest
// attribute, then within that for a SubjectAltName extension, and returns
// the dNSName entries. Returns nil (no error) if no SAN extension is present.
func dnsNamesFromAttributes(attrs []csrAttribute) ([]string, error) {
	for _, attr := range attrs {
		if !attr.Type.Equal(oidExtensionRequest) {
			continue
		}
		// extensionRequest values are each an Extensions SEQUENCE.
		for _, value := range attr.Values {
			dns, err := dnsNamesFromExtensionsRaw(value.FullBytes)
			if err != nil {
				return nil, err
			}
			if len(dns) > 0 {
				return dns, nil
			}
		}
	}
	return nil, nil
}

// dnsNamesFromExtensionsRaw decodes a SEQUENCE OF Extension and returns
// the DNS names from the SubjectAltName extension if present.
func dnsNamesFromExtensionsRaw(b []byte) ([]string, error) {
	var exts []pkix.Extension
	if _, err := asn1.Unmarshal(b, &exts); err != nil {
		return nil, fmt.Errorf("decode extensions: %w", err)
	}
	for _, ext := range exts {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		return dnsNamesFromSAN(ext.Value)
	}
	return nil, nil
}

// dnsNamesFromSAN extracts dNSName entries (tag [2] IMPLICIT IA5String) from
// a SubjectAltName extension value (RFC 5280 §4.2.1.6).
func dnsNamesFromSAN(value []byte) ([]string, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(value, &seq); err != nil {
		return nil, fmt.Errorf("SAN outer: %w", err)
	}
	var names []string
	rest := seq.Bytes
	for len(rest) > 0 {
		var name asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &name)
		if err != nil {
			return nil, fmt.Errorf("SAN entry: %w", err)
		}
		// dNSName is [2] IMPLICIT IA5String.
		if name.Class == asn1.ClassContextSpecific && name.Tag == 2 {
			names = append(names, string(name.Bytes))
		}
	}
	return names, nil
}
