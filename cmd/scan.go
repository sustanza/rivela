package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

var deprecatedTLSVersions = map[string]struct{}{
	"TLS 1.0": {},
	"TLS 1.1": {},
}

var weakCipherNames = map[string]struct{}{
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":       {},
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": {},
	"TLS_RSA_WITH_RC4_128_SHA":            {},
	"TLS_RSA_WITH_RC4_128_MD5":            {},
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":      {},
}

// scanHost tries TLS versions, cert extraction, and (optionally) cipher enumeration
func scanHost(host string, port int) *TLSScanResult {
	r := &TLSScanResult{
		Host:        host,
		Port:        port,
		TLSVersions: make(map[string]string, 4),
	}

	versions := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}
	var successCount int

	// 1) check each TLS version
	for _, v := range versions {
		stat := checkTLSVersion(host, port, v)
		r.TLSVersions[tlsVersionString(v)] = stat

		if stat == "supported" {
			successCount++
		}
	}

	// 2) normal handshake to see negotiated TLS, cipher, and cert
	detailsErr := fillDetails(r, host, port)

	// 3) if user asked for full cipher enumeration
	if flagFullCipher {
		r.CipherSuites = enumerateCiphers(host, port)
	}

	// 4) If no version succeeded AND the handshake also failed => error
	if successCount == 0 && detailsErr != nil {
		r.Error = detailsErr
	} else if successCount == 0 {
		r.Error = errors.New("no TLS versions succeeded")
	}

	// 5) If the handshake was successful (detailsErr == nil),
	//    but the entire chain is invalid => error
	if detailsErr == nil && !flagInsecure && isAllCertsUntrusted(r.Certificates) {
		r.Error = errors.New("self-signed or untrusted certificate without --insecure")
	}

	// 6) Collect warnings for deprecated versions and weak ciphers
	var deprecated []string
	for v, status := range r.TLSVersions {
		if status == "supported" {
			if _, ok := deprecatedTLSVersions[v]; ok {
				deprecated = append(deprecated, v)
			}
		}
	}
	if len(deprecated) > 0 {
		r.Warnings = append(r.Warnings, "supports deprecated TLS versions: "+strings.Join(deprecated, ", "))
	}

	var weakCiphers []string
	if _, ok := weakCipherNames[r.NegotiatedCipher]; ok && r.NegotiatedCipher != "" {
		weakCiphers = append(weakCiphers, r.NegotiatedCipher)
	}
	if flagFullCipher {
		for c, ok := range r.CipherSuites {
			if ok {
				if _, weak := weakCipherNames[c]; weak && !contains(weakCiphers, c) {
					weakCiphers = append(weakCiphers, c)
				}
			}
		}
	}
	if len(weakCiphers) > 0 {
		r.Warnings = append(r.Warnings, "supports weak ciphers: "+strings.Join(weakCiphers, ", "))
	}

	r.Grade = computeGrade(r)
	return r
}

// checkTLSVersion tries a forced TLS version
func checkTLSVersion(host string, port int, version uint16) string {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	cfg := &tls.Config{
		InsecureSkipVerify: flagInsecure,
		MinVersion:         version,
		MaxVersion:         version,
		ServerName:         serverNameOrDefault(host),
		NextProtos:         []string{"h2", "http/1.1"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), flagTimeout)
	defer cancel()

	dialer := &tls.Dialer{Config: cfg, NetDialer: &net.Dialer{}}
	nc, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
			return "connection failed (timeout)"
		}
		return fmt.Sprintf("connection failed (%v)", err)
	}
	conn, ok := nc.(*tls.Conn)
	if !ok {
		_ = nc.Close()
		return "connection failed (not tls)"
	}
	defer func() {
		_ = conn.Close()
	}()

	if ctx.Err() == context.DeadlineExceeded {
		return "connection failed (timeout)"
	}

	if conn.ConnectionState().Version == version {
		return "supported"
	}
	return "not supported"
}

// fillDetails attempts a normal handshake to discover negotiated version/cipher + certs
func fillDetails(r *TLSScanResult, host string, port int) error {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	cfg := &tls.Config{
		// Always skip verification during the handshake so we can
		// capture certificate details even when they are invalid.
		InsecureSkipVerify: true,
		ServerName:         serverNameOrDefault(host),
		NextProtos:         []string{"h2", "http/1.1"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), flagTimeout)
	defer cancel()

	dialer := &net.Dialer{}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer func() {
		_ = raw.Close()
	}()

	client := tls.Client(raw, cfg)

	// Set a deadline for the TLS handshake itself to ensure we don't hang
	// indefinitely if the server doesn't respond.
	deadline := time.Now().Add(flagTimeout)
	_ = client.SetDeadline(deadline)

	if err := client.Handshake(); err != nil {
		_ = client.Close()
		return err
	}

	// Clear the deadlines once the handshake is complete so further reads
	// or writes aren't restricted by the handshake timeout.
	_ = client.SetDeadline(time.Time{})

	st := client.ConnectionState()
	r.NegotiatedTLS = tlsVersionString(st.Version)
	r.NegotiatedCipher = tls.CipherSuiteName(st.CipherSuite)
	r.NegotiatedProto = st.NegotiatedProtocol
	r.OCSPResponse = st.OCSPResponse
	r.OCSPStapled = len(st.OCSPResponse) > 0
	var warn []string
	r.Certificates, warn = parseCertificateChain(st.PeerCertificates, host)
	if len(warn) > 0 {
		r.Warnings = append(r.Warnings, warn...)
	}

	// Manually verify the peer certificates when not running in insecure
	// mode. We skip verification during the handshake, so this ensures the
	// connection is still validated when required.
	if !flagInsecure && len(st.PeerCertificates) > 0 {
		opts := x509.VerifyOptions{DNSName: host, Intermediates: x509.NewCertPool()}
		for _, ic := range st.PeerCertificates[1:] {
			opts.Intermediates.AddCert(ic)
		}
		if _, err := st.PeerCertificates[0].Verify(opts); err != nil {
			return err
		}
	}

	return nil
}

func enumerateCiphers(host string, port int) map[string]bool {
	out := make(map[string]bool)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	all := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)

	for _, c := range all {
		cfg := &tls.Config{
			InsecureSkipVerify: flagInsecure,
			CipherSuites:       []uint16{c.ID},
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS12,
			ServerName:         serverNameOrDefault(host),
			NextProtos:         []string{"h2", "http/1.1"},
		}
		if conn, err := tls.Dial("tcp", addr, cfg); err == nil {
			out[c.Name] = true
			_ = conn.Close()
		} else {
			out[c.Name] = false
		}
	}
	return out
}

func parseCertificateChain(chain []*x509.Certificate, hostname string) ([]CertificateInfo, []string) {
	out := make([]CertificateInfo, 0, len(chain))
	var warnings []string

	if len(chain) > 0 {
		opts := x509.VerifyOptions{DNSName: hostname, Intermediates: x509.NewCertPool()}
		for _, ic := range chain[1:] {
			opts.Intermediates.AddCert(ic)
		}
		if _, err := chain[0].Verify(opts); err != nil {
			var uaErr x509.UnknownAuthorityError
			if errors.As(err, &uaErr) {
				warnings = append(warnings, "incomplete certificate chain")
			}
		}
	}

	for _, cert := range chain {
		info := CertificateInfo{
			Subject:            cert.Subject.String(),
			Issuer:             cert.Issuer.String(),
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			DNSNames:           cert.DNSNames,
			IPAddresses:        ipStrings(cert.IPAddresses),
			Valid:              true,
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		}
		if isWeakSignature(cert.SignatureAlgorithm) {
			info.WeakSignature = true
			warnings = append(warnings, "certificate signed with weak algorithm")
		}

		warnDur := time.Duration(flagExpiryWarningDays) * 24 * time.Hour
		if time.Until(cert.NotAfter) <= warnDur {
			info.ExpiringSoon = true
		}
		if !flagInsecure {
			opts := x509.VerifyOptions{DNSName: hostname}
			if _, err := cert.Verify(opts); err != nil {
				info.Valid = false
				info.ValidationErr = err.Error()
			}
		}
		out = append(out, info)
	}
	return out, warnings
}

func isAllCertsUntrusted(certs []CertificateInfo) bool {
	if len(certs) == 0 {
		return false
	}
	for _, c := range certs {
		if c.Valid {
			return false
		}
	}
	return true
}

func versionSorter(v string) float64 {
	switch v {
	case "TLS 1.0":
		return 1.0
	case "TLS 1.1":
		return 1.1
	case "TLS 1.2":
		return 1.2
	case "TLS 1.3":
		return 1.3
	default:
		return 10.0
	}
}

func tlsVersionString(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%x)", ver)
	}
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func isWeakSignature(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1, x509.MD5WithRSA:
		return true
	default:
		return false
	}
}

func contains(slice []string, v string) bool {
	for _, s := range slice {
		if s == v {
			return true
		}
	}
	return false
}

// serverNameOrDefault returns the value to use for tls.Config.ServerName.
// If the --sni flag is provided, that value is used. Otherwise, if the host
// is an IP address we omit SNI by returning an empty string. For all other
// cases the host itself is returned.
func serverNameOrDefault(host string) string {
	if flagSNI != "" {
		return flagSNI
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

// computeGrade assigns a letter grade based on supported TLS versions.
// A: Only modern (TLS 1.2+). B: Modern plus deprecated. C: Only deprecated.
// F: Scan error or no TLS 1.2+ support.
func computeGrade(r *TLSScanResult) string {
	if r.Error != nil {
		return "F"
	}
	var hasModern bool
	var hasDeprecated bool
	for v, status := range r.TLSVersions {
		if status != "supported" {
			continue
		}
		switch v {
		case "TLS 1.0", "TLS 1.1":
			hasDeprecated = true
		case "TLS 1.2", "TLS 1.3":
			hasModern = true
		}
	}

	if !hasModern {
		return "C"
	}
	if hasDeprecated {
		return "B"
	}
	return "A"
}
