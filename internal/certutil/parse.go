// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

// Package certutil extracts X.509 metadata from DER-encoded certificates.
//
// It is a leaf package with no internal dependencies - it relies only on
// the Go standard library crypto/x509 parser.
package certutil

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"crypto/x509/pkix"
)

// CertMeta holds human-readable metadata extracted from an X.509 certificate.
type CertMeta struct {
	CommonName         string   `json:"common_name,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Country            []string `json:"country,omitempty"`
	Province           []string `json:"province,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	SerialNumber       string   `json:"serial_number"`
	SANs               []string `json:"sans,omitempty"`
	IssuerCN           string   `json:"issuer_cn,omitempty"`
	IssuerOrganization []string `json:"issuer_organization,omitempty"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	KeyAlgorithm       string `json:"key_algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	KeyUsage           string `json:"key_usage,omitempty"`
	IsCA               bool     `json:"is_ca"`
	ExtKeyUsage        []string `json:"ext_key_usage,omitempty"`
	CRLEndpoints       []string `json:"crl_endpoints,omitempty"`
	OCSPServers        []string `json:"ocsp_servers,omitempty"`
	IssuingCertURL     []string `json:"issuing_cert_url,omitempty"`
}

// ParseDER parses a DER-encoded X.509 certificate and extracts metadata.
func ParseDER(der []byte) (*CertMeta, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("certutil.ParseDER: %w", err)
	}
	return fromCert(cert), nil
}

// ParseMTCLogEntry extracts metadata from an MTC-spec log entry whose
// entry_data is a TLS-presentation-language MerkleTreeCertEntry:
//   - 2 bytes BE uint16 = MerkleTreeCertEntryType (1 = tbs_cert_entry)
//   - 3 bytes BE uint24 = data length
//   - N bytes = contents octets of TBSCertificateLogEntry DER (no SEQUENCE envelope)
//
// The TBSCertificateLogEntry omits serialNumber and replaces the full public
// key with SHA-256(SPKI), so the returned CertMeta has no serial and an empty
// SignatureAlgorithm (the cert's signature is the MTC inclusion proof).
func ParseMTCLogEntry(entryData []byte) (*CertMeta, error) {
	if len(entryData) < 5 {
		return nil, fmt.Errorf("certutil.ParseMTCLogEntry: entry too short (%d bytes)", len(entryData))
	}
	entryType := uint16(entryData[0])<<8 | uint16(entryData[1])
	if entryType != 1 {
		return nil, fmt.Errorf("certutil.ParseMTCLogEntry: expected MerkleTreeCertEntry type 1 (tbs_cert_entry), got %d", entryType)
	}
	dataLen := int(entryData[2])<<16 | int(entryData[3])<<8 | int(entryData[4])
	if 5+dataLen > len(entryData) {
		return nil, fmt.Errorf("certutil.ParseMTCLogEntry: data length %d exceeds entry size", dataLen)
	}
	contents := entryData[5 : 5+dataLen]

	// Re-wrap contents octets as a SEQUENCE so encoding/asn1 can parse it.
	wrapped, err := asn1.Marshal(asn1.RawValue{
		Tag: asn1.TagSequence, Class: asn1.ClassUniversal, IsCompound: true, Bytes: contents,
	})
	if err != nil {
		return nil, fmt.Errorf("certutil.ParseMTCLogEntry: wrap contents: %w", err)
	}

	type tbsValidity struct {
		NotBefore time.Time
		NotAfter  time.Time
	}
	type tbsLogEntry struct {
		Version                   int              `asn1:"optional,explicit,tag:0,default:0"`
		Issuer                    asn1.RawValue    `asn1:""`
		Validity                  tbsValidity      `asn1:""`
		Subject                   asn1.RawValue    `asn1:""`
		SubjectPublicKeyAlgorithm asn1.RawValue    `asn1:""`
		SubjectPublicKeyInfoHash  []byte           `asn1:""`
		Extensions                []pkix.Extension `asn1:"optional,explicit,tag:3"`
	}

	var tbs tbsLogEntry
	if _, err := asn1.Unmarshal(wrapped, &tbs); err != nil {
		return nil, fmt.Errorf("certutil.ParseMTCLogEntry: unmarshal: %w", err)
	}

	subject, _ := unmarshalDN(tbs.Subject.FullBytes)
	issuer, _ := unmarshalDN(tbs.Issuer.FullBytes)

	meta := &CertMeta{
		CommonName:         subject.CommonName,
		Organization:       subject.Organization,
		OrganizationalUnit: subject.OrganizationalUnit,
		Country:            subject.Country,
		Province:           subject.Province,
		Locality:           subject.Locality,
		IssuerCN:           issuer.CommonName,
		IssuerOrganization: issuer.Organization,
		NotBefore:          tbs.Validity.NotBefore,
		NotAfter:           tbs.Validity.NotAfter,
		KeyAlgorithm:       keyAlgorithmFromAlgID(tbs.SubjectPublicKeyAlgorithm.FullBytes),
		SignatureAlgorithm: "id-alg-mtcProof",
	}
	for _, ext := range tbs.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) { // subjectAltName
			meta.SANs = append(meta.SANs, parseSANDNSNames(ext.Value)...)
		}
	}
	return meta, nil
}

func unmarshalDN(der []byte) (pkix.Name, error) {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(der, &rdns); err != nil {
		return pkix.Name{}, err
	}
	var n pkix.Name
	n.FillFromRDNSequence(&rdns)
	return n, nil
}

func keyAlgorithmFromAlgID(algIDDER []byte) string {
	type algID struct {
		OID        asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	var a algID
	if _, err := asn1.Unmarshal(algIDDER, &a); err != nil {
		return ""
	}
	switch {
	case a.OID.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}):
		return "ECDSA"
	case a.OID.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}):
		return "RSA"
	case a.OID.Equal(asn1.ObjectIdentifier{1, 3, 101, 112}):
		return "Ed25519"
	}
	return a.OID.String()
}

func parseSANDNSNames(extValue []byte) []string {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(extValue, &seq); err != nil {
		return nil
	}
	var names []string
	rest := seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			break
		}
		// dNSName is [2] IMPLICIT IA5String
		if v.Class == asn1.ClassContextSpecific && v.Tag == 2 {
			names = append(names, string(v.Bytes))
		}
	}
	return names
}

// ParseLogEntry extracts the DER certificate from an MTC log entry and parses it.
// Log entry format: [uint16 LE type][uint32 LE length][DER blob]
func ParseLogEntry(entryData []byte) (*CertMeta, []byte, error) {
	if len(entryData) < 6 {
		return nil, nil, fmt.Errorf("certutil.ParseLogEntry: entry too short (%d bytes)", len(entryData))
	}
	entryType := uint16(entryData[0]) | uint16(entryData[1])<<8
	if entryType == 0 {
		return nil, nil, fmt.Errorf("certutil.ParseLogEntry: null entry (type 0)")
	}
	if entryType != 1 {
		return nil, nil, fmt.Errorf("certutil.ParseLogEntry: unsupported entry type %d", entryType)
	}
	derLen := uint32(entryData[2]) | uint32(entryData[3])<<8 | uint32(entryData[4])<<16 | uint32(entryData[5])<<24
	if int(derLen)+6 > len(entryData) {
		return nil, nil, fmt.Errorf("certutil.ParseLogEntry: DER length %d exceeds entry size %d", derLen, len(entryData)-6)
	}
	der := entryData[6 : 6+derLen]
	meta, err := ParseDER(der)
	if err != nil {
		return nil, der, err
	}
	return meta, der, nil
}

func fromCert(cert *x509.Certificate) *CertMeta {
	m := &CertMeta{
		CommonName:         cert.Subject.CommonName,
		Organization:       cert.Subject.Organization,
		OrganizationalUnit: cert.Subject.OrganizationalUnit,
		Country:            cert.Subject.Country,
		Province:           cert.Subject.Province,
		Locality:           cert.Subject.Locality,
		SerialNumber:       formatSerial(cert.SerialNumber.Bytes()),
		IssuerCN:           cert.Issuer.CommonName,
		IssuerOrganization: cert.Issuer.Organization,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		KeyAlgorithm:       cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCA:               cert.IsCA,
		CRLEndpoints:       cert.CRLDistributionPoints,
		OCSPServers:        cert.OCSPServer,
		IssuingCertURL:     cert.IssuingCertificateURL,
	}
	for _, dns := range cert.DNSNames {
		m.SANs = append(m.SANs, dns)
	}
	for _, ip := range cert.IPAddresses {
		m.SANs = append(m.SANs, ip.String())
	}
	for _, email := range cert.EmailAddresses {
		m.SANs = append(m.SANs, email)
	}
	for _, uri := range cert.URIs {
		m.SANs = append(m.SANs, uri.String())
	}
	m.KeyUsage = formatKeyUsage(cert.KeyUsage)
	m.ExtKeyUsage = formatExtKeyUsage(cert.ExtKeyUsage)
	return m
}

func formatSerial(b []byte) string {
	if len(b) == 0 {
		return "0"
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func formatKeyUsage(ku x509.KeyUsage) string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}
	return strings.Join(usages, ", ")
}

func formatExtKeyUsage(ekus []x509.ExtKeyUsage) []string {
	var usages []string
	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageAny:
			usages = append(usages, "Any")
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		default:
			usages = append(usages, fmt.Sprintf("Unknown(%d)", eku))
		}
	}
	return usages
}
