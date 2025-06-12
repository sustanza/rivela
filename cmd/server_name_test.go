package cmd

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestServerNameOrDefault_CustomSNI(t *testing.T) {
	resetGlobalFlags()
	flagSNI = "custom.example.com"
	got := serverNameOrDefault("192.0.2.1")
	if got != "custom.example.com" {
		t.Errorf("expected custom SNI %q, got %q", "custom.example.com", got)
	}
}

func TestServerNameOrDefault_IPAddress(t *testing.T) {
	resetGlobalFlags()
	tests := []string{"192.0.2.1", "2001:db8::1"}
	for _, ip := range tests {
		if got := serverNameOrDefault(ip); got != "" {
			t.Errorf("expected empty server name for IP %s, got %q", ip, got)
		}
	}
}

func TestServerNameOrDefault_DefaultHostname(t *testing.T) {
	resetGlobalFlags()
	host := "example.com"
	if got := serverNameOrDefault(host); got != host {
		t.Errorf("expected host %q, got %q", host, got)
	}
}

func TestVersionSorter(t *testing.T) {
	cases := map[string]float64{
		"TLS 1.0": 1.0,
		"TLS 1.1": 1.1,
		"TLS 1.2": 1.2,
		"TLS 1.3": 1.3,
		"foo":     10.0,
	}
	for in, want := range cases {
		if got := versionSorter(in); got != want {
			t.Errorf("%s => %v, want %v", in, got, want)
		}
	}
}

func TestTLSVersionString(t *testing.T) {
	if tlsVersionString(tls.VersionTLS12) != "TLS 1.2" {
		t.Errorf("unexpected TLS string")
	}
	if !strings.HasPrefix(tlsVersionString(0x9999), "Unknown") {
		t.Errorf("expected Unknown for unknown version")
	}
}
