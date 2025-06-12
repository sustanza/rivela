package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestColorDisabled(t *testing.T) {
	resetGlobalFlags()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("color"))
	}))
	defer ts.Close()

	cmd := buildTestableRivelaCmd([]string{
		"--host", ts.Listener.Addr().String(),
		"--insecure",
		"--format", "text",
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("expected no ANSI codes, got: %q", out.String())
	}
}

func TestColorEnabled(t *testing.T) {
	resetGlobalFlags()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("color"))
	}))
	defer ts.Close()

	cmd := buildTestableRivelaCmd([]string{
		"--host", ts.Listener.Addr().String(),
		"--insecure",
		"--format", "text",
		"--color",
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	outStr := out.String()
	if !strings.Contains(outStr, "\x1b[32m") && !strings.Contains(outStr, "\x1b[33m") && !strings.Contains(outStr, "\x1b[31m") {
		t.Fatalf("expected ANSI colors, got: %q", outStr)
	}
}
