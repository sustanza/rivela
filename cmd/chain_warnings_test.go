package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func genWeakSHA1Cert() *x509.Certificate {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "sha1.test"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		DNSNames:           []string{"sha1.test"},
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm: x509.SHA1WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert
}

func genLeafOnlyChain() *x509.Certificate {
	rootKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	rootTmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(2),
		Subject:            pkix.Name{CommonName: "root"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		IsCA:               true,
		KeyUsage:           x509.KeyUsageCertSign,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	leafTmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(3),
		Subject:            pkix.Name{CommonName: "leaf"},
		DNSNames:           []string{"leaf"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafDER)
	return leafCert
}

func TestParseCertificateChainWeakAndIncomplete(t *testing.T) {
	resetGlobalFlags()
	flagInsecure = true

	weakCert := genWeakSHA1Cert()
	res, warnings := parseCertificateChain([]*x509.Certificate{weakCert}, "sha1.test")
	if len(res) != 1 {
		t.Fatalf("expected one cert")
	}
	if !res[0].WeakSignature {
		t.Fatalf("expected WeakSignature true")
	}
	foundWeak := false
	for _, w := range warnings {
		if w == "certificate signed with weak algorithm" {
			foundWeak = true
		}
	}
	if !foundWeak {
		t.Fatalf("expected weak signature warning, got %v", warnings)
	}

	leafOnly := genLeafOnlyChain()
	_, warnings = parseCertificateChain([]*x509.Certificate{leafOnly}, "leaf")
	foundChain := false
	for _, w := range warnings {
		if w == "incomplete certificate chain" {
			foundChain = true
		}
	}
	if !foundChain {
		t.Fatalf("expected chain warning, got %v", warnings)
	}
}
