package cmd

import "testing"

func TestParseHostPort_WithScheme(t *testing.T) {
	host, port, err := parseHostPort("https://example.com:8443", 443)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "example.com" || port != 8443 {
		t.Errorf("expected example.com:8443 got %s:%d", host, port)
	}

	host, port, err = parseHostPort("http://example.com", 8080)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "example.com" || port != 8080 {
		t.Errorf("expected example.com:8080 got %s:%d", host, port)
	}
}

func TestParseHostPort_Invalid(t *testing.T) {
	tests := []string{
		"example.com:",
		"http://:443",
	}
	for _, in := range tests {
		if _, _, err := parseHostPort(in, 443); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func TestParseHostPort_DefaultPort(t *testing.T) {
	host, port, err := parseHostPort("example.com", 8443)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "example.com" || port != 8443 {
		t.Errorf("expected example.com:8443 got %s:%d", host, port)
	}
}
