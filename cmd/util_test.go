package cmd

import "testing"

func TestIsAllCertsUntrusted(t *testing.T) {
	cases := []struct {
		certs []CertificateInfo
		want  bool
	}{
		{nil, false},
		{[]CertificateInfo{{Valid: true}}, false},
		{[]CertificateInfo{{Valid: false}, {Valid: false}}, true},
	}
	for _, c := range cases {
		got := isAllCertsUntrusted(c.certs)
		if got != c.want {
			t.Errorf("isAllCertsUntrusted(%v) = %v, want %v", c.certs, got, c.want)
		}
	}
}

func TestContains(t *testing.T) {
	s := []string{"a", "b"}
	if !contains(s, "a") {
		t.Error("expected true")
	}
	if contains(s, "c") {
		t.Error("expected false")
	}
}
