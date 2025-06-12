package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func generateCert(expireIn time.Duration) tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(expireIn),
		DNSNames:     []string{"example.com"},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func TestParseCertificateChainExpiringSoon(t *testing.T) {
	resetGlobalFlags()
	flagExpiryWarningDays = 10
	cert := generateCert(2 * 24 * time.Hour)
	xCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	result, warn := parseCertificateChain([]*x509.Certificate{xCert}, "example.com")
	if len(result) != 1 || !result[0].ExpiringSoon {
		t.Fatalf("expected ExpiringSoon=true, got %+v", result)
	}
	if len(warn) != 1 || warn[0] != "incomplete certificate chain" {
		t.Fatalf("expected chain warning, got %v", warn)
	}
}

func getShortExpiryTLSConfig(days int) *tls.Config {
	cert := generateCert(time.Duration(days) * 24 * time.Hour)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
}

func TestRivelaExpiryWarningText(t *testing.T) {
	resetGlobalFlags()
	flagExpiryWarningDays = 3
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("expire")); err != nil {
			t.Fatalf("write error: %v", err)
		}
	}))
	ts.TLS = getShortExpiryTLSConfig(2)
	ts.StartTLS()
	defer ts.Close()

	cmd := buildTestableRivelaCmd([]string{
		"--host", ts.Listener.Addr().String(),
		"--insecure",
		"--format", "text",
		"--expiry-warning-days", "3",
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("command error: %v", err)
	}
	if !strings.Contains(out.String(), "expires within 3 days") {
		t.Fatalf("expected expiry warning, got:\n%s", out.String())
	}
}
