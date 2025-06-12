package cmd

import "time"

// TLSScanResult holds all info about one host's scan.
type TLSScanResult struct {
	Host             string            `json:"host"`
	Port             int               `json:"port"`
	TLSVersions      map[string]string `json:"tls_versions"`
	Certificates     []CertificateInfo `json:"certificates,omitempty"`
	CipherSuites     map[string]bool   `json:"cipher_suites,omitempty"`
	NegotiatedTLS    string            `json:"negotiated_tls,omitempty"`
	NegotiatedCipher string            `json:"negotiated_cipher,omitempty"`
	NegotiatedProto  string            `json:"negotiated_proto,omitempty"`
	OCSPStapled      bool              `json:"ocsp_stapled"`
	OCSPResponse     []byte            `json:"-"`
	Warnings         []string          `json:"warnings,omitempty"`
	Grade            string            `json:"grade,omitempty"`
	Error            error             `json:"-"`
}

// CertificateInfo captures details from x509 certs.
type CertificateInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	Valid              bool      `json:"valid"`
	ValidationErr      string    `json:"validation_err,omitempty"`
	ExpiringSoon       bool      `json:"expiring_soon"`
	SignatureAlgorithm string    `json:"signature_algorithm,omitempty"`
	WeakSignature      bool      `json:"weak_signature,omitempty"`
}

// LogEntry represents the summary information written to log files.
type LogEntry struct {
	Host        string `json:"host"`
	HighestTLS  string `json:"highest_tls"`
	WeakCiphers bool   `json:"weak_ciphers"`
}
