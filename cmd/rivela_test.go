package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestRivela_OneServer(t *testing.T) {
	resetGlobalFlags()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("Hello from test TLS server")); err != nil {
			t.Fatalf("handler write failed: %v", err)
		}
	}))
	defer ts.Close()

	// Combine ephemeral host:port as a single string so no confusion
	fullAddr := ts.Listener.Addr().String()

	cmd := buildTestableRivelaCmd([]string{
		"--host", fullAddr,
		"--insecure",
		"--format", "text",
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	outStr := out.String()
	if !strings.Contains(outStr, "TLS 1.2 => supported") &&
		!strings.Contains(outStr, "TLS 1.3 => supported") {
		t.Errorf("Expected TLS 1.2 or 1.3 support:\n%s", outStr)
	}
	if !strings.Contains(outStr, "Certificate [0]:") {
		t.Errorf("Expected certificate details in output:\n%s", outStr)
	}
}

func TestRivela_TwoServers_Concurrency(t *testing.T) {
	resetGlobalFlags()

	ts1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("Server1")); err != nil {
			t.Fatalf("handler write failed: %v", err)
		}
	}))
	defer ts1.Close()

	ts2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("Server2")); err != nil {
			t.Fatalf("handler write failed: %v", err)
		}
	}))
	defer ts2.Close()

	cmd := buildTestableRivelaCmd([]string{
		"--host", ts1.Listener.Addr().String(), // combined ephemeral
		"--host", ts2.Listener.Addr().String(), // combined ephemeral
		"--insecure",
		"--format", "text",
		"--concurrency", "2",
	})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Error in concurrency test: %v\nOutput:\n%s", err, out.String())
	}

	output := out.String()
	addr1 := ts1.Listener.Addr().String()
	addr2 := ts2.Listener.Addr().String()

	if !strings.Contains(output, fmt.Sprintf("Results for %s", addr1)) {
		t.Errorf("Did not find results for first server:\n\n%s", output)
	}
	if !strings.Contains(output, fmt.Sprintf("Results for %s", addr2)) {
		t.Errorf("Did not find results for second server:\n\n%s", output)
	}
}

func TestRivela_FullCipher(t *testing.T) {
	resetGlobalFlags()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("Cipher Test")); err != nil {
			t.Fatalf("handler write failed: %v", err)
		}
	}))
	defer ts.Close()

	cmd := buildTestableRivelaCmd([]string{
		"--host", ts.Listener.Addr().String(),
		"--format", "text",
		"--insecure",
		"--full-cipher",
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	outStr := out.String()
	if !strings.Contains(outStr, "--- Full Cipher Enumeration ---") {
		t.Errorf("Expected Full Cipher Enumeration block:\n%s", outStr)
	}
}

func TestRivela_Progress(t *testing.T) {
	resetGlobalFlags()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("progress")); err != nil {
			t.Fatalf("handler write failed: %v", err)
		}
	}))
	defer ts.Close()

	cmd := buildTestableRivelaCmd([]string{
		"--host", ts.Listener.Addr().String(),
		"--insecure",
		"--format", "text",
		"--progress",
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(out.String(), "100%") {
		t.Errorf("expected progress output, got: %s", out.String())
	}
}

func TestRivela_FileInput(t *testing.T) {
	resetGlobalFlags()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("Test from file input")); err != nil {
			t.Fatalf("handler write failed: %v", err)
		}
	}))
	defer ts.Close()

	tmpFile, err := os.CreateTemp("", "rivela_hosts_*.txt")
	if err != nil {
		t.Fatalf("CreateTemp error = %v", err)
	}
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			t.Logf("failed to remove temp file: %v", err)
		}
	}()

	addr := ts.Listener.Addr().String()
	if _, err := fmt.Fprintf(tmpFile, "%s\n", addr); err != nil {
		t.Fatalf("write temp file failed: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("temp file close failed: %v", err)
	}

	cmd := buildTestableRivelaCmd([]string{
		"--file", tmpFile.Name(),
		"--insecure",
		"--format", "text",
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	outStr := out.String()
	if !strings.Contains(outStr, fmt.Sprintf("Results for %s", addr)) {
		t.Errorf("Expected results for %s in file input:\n%s", addr, outStr)
	}
}

func TestRivela_CompareMode(t *testing.T) {
	resetGlobalFlags()

	ts1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("compare1"))
	}))
	defer ts1.Close()

	ts2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("compare2"))
	}))
	defer ts2.Close()

	cmd := buildTestableRivelaCmd([]string{
		"--host", ts1.Listener.Addr().String(),
		"--host", ts2.Listener.Addr().String(),
		"--insecure",
		"--format", "text",
		"--compare",
	})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("compare mode execute: %v\n%s", err, out.String())
	}

	outStr := out.String()
	if !strings.Contains(outStr, "Host") || !strings.Contains(outStr, "CipherCount") {
		t.Fatalf("expected table header, got:\n%s", outStr)
	}

	if !strings.Contains(outStr, ts1.Listener.Addr().String()) || !strings.Contains(outStr, ts2.Listener.Addr().String()) {
		t.Fatalf("missing host entries in compare output:\n%s", outStr)
	}
}

func TestRivela_ConcurrencyStress(t *testing.T) {
	resetGlobalFlags()

	const count = 5
	var servers []*httptest.Server
	for i := 0; i < count; i++ {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := fmt.Fprintf(w, "Server %d", i); err != nil {
				t.Fatalf("handler write failed: %v", err)
			}
		}))
		servers = append(servers, ts)
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	args := []string{"--format", "text", "--concurrency", "3", "--insecure"}

	for _, srv := range servers {
		args = append(args, "--host", srv.Listener.Addr().String())
	}

	cmd := buildTestableRivelaCmd(args)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Concurrency stress test error: %v\nOutput:\n%s", err, out.String())
	}

	output := out.String()
	for _, s := range servers {
		addr := s.Listener.Addr().String()
		if !strings.Contains(output, fmt.Sprintf("Results for %s", addr)) {
			t.Errorf("Missing output for %s\n", addr)
		}
	}
}

func TestInsecureScan(t *testing.T) {
	resetGlobalFlags()

	ss := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("Self-signed test server")); err != nil {
			t.Fatalf("handler write failed: %v", err)
		}
	}))
	ss.TLS = getSelfSignedTLSConfig()
	ss.StartTLS()
	defer ss.Close()

	addr := ss.Listener.Addr().String()

	// 1) Without --insecure => expect an error
	cmdNoInsecure := buildTestableRivelaCmd([]string{
		"--host", addr,
		"--format", "text",
	})
	var outNoInsecure bytes.Buffer
	cmdNoInsecure.SetOut(&outNoInsecure)
	cmdNoInsecure.SetErr(&outNoInsecure)

	err := cmdNoInsecure.Execute()
	outputNoInsecure := outNoInsecure.String()
	if err == nil {
		t.Errorf("Expected error scanning self-signed cert w/out --insecure, got no error.\nOutput:\n%s", outputNoInsecure)
	}
	if !strings.Contains(outputNoInsecure, "Certificate [0]:") {
		t.Errorf("Expected certificate details even on failure. Output:\n%s", outputNoInsecure)
	}

	// 2) With --insecure => expect success
	cmdInsecure := buildTestableRivelaCmd([]string{
		"--host", addr,
		"--format", "text",
		"--insecure",
	})
	var outInsecure bytes.Buffer
	cmdInsecure.SetOut(&outInsecure)
	cmdInsecure.SetErr(&outInsecure)

	err = cmdInsecure.Execute()
	if err != nil {
		t.Fatalf("Expected success scanning self-signed with --insecure, got %v\nOutput:\n%s", err, outInsecure.String())
	}
}

// Provide a short, valid RSA cert+key with no stray spaces
func getSelfSignedTLSConfig() *tls.Config {
	cert, err := tls.X509KeyPair([]byte(selfSignedCertPEM), []byte(selfSignedKeyPEM))
	if err != nil {
		panic(fmt.Sprintf("failed to parse self-signed cert: %v", err))
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
}

func getWeakTLSConfig() *tls.Config {
	cert, err := tls.X509KeyPair([]byte(selfSignedCertPEM), []byte(selfSignedKeyPEM))
	if err != nil {
		panic(fmt.Sprintf("failed to parse self-signed cert: %v", err))
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}
}

func getOldTLSConfig() *tls.Config {
	cert, err := tls.X509KeyPair([]byte(selfSignedCertPEM), []byte(selfSignedKeyPEM))
	if err != nil {
		panic(fmt.Sprintf("failed to parse self-signed cert: %v", err))
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS11,
	}
}

func buildTestableRivelaCmd(args []string) *cobra.Command {
	resetGlobalFlags()
	cmd := &cobra.Command{
		Use:  "rivela",
		RunE: runRivela,
	}
	cmd.Flags().StringSliceVar(&flagHosts, "host", nil, "")
	cmd.Flags().IntVar(&flagPort, "port", 443, "") // Fixed: Added missing default value argument
	cmd.Flags().BoolVar(&flagInsecure, "insecure", false, "")
	cmd.Flags().BoolVar(&flagFullCipher, "full-cipher", false, "")
	cmd.Flags().StringVar(&flagSNI, "sni", "", "")
	cmd.Flags().StringVar(&flagOutputFormat, "format", "text", "")
	cmd.Flags().DurationVar(&flagTimeout, "timeout", 5*time.Second, "")
	cmd.Flags().IntVar(&flagConcurrency, "concurrency", 10, "")
	cmd.Flags().StringVar(&flagFile, "file", "", "")
	cmd.Flags().BoolVar(&flagProgress, "progress", false, "")
	cmd.Flags().IntVar(&flagExpiryWarningDays, "expiry-warning-days", 30, "")
	cmd.Flags().BoolVar(&flagCompare, "compare", false, "")
	cmd.Flags().BoolVar(&flagColor, "color", false, "")
	cmd.SetArgs(args)
	return cmd
}

func TestWarningsAppearJSON(t *testing.T) {
	resetGlobalFlags()

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("weak"))
	}))
	ts.TLS = getWeakTLSConfig()
	ts.StartTLS()
	defer ts.Close()

	cmd := buildTestableRivelaCmd([]string{
		"--host", ts.Listener.Addr().String(),
		"--insecure",
		"--full-cipher",
		"--format", "json",
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v\nOutput:\n%s", err, out.String())
	}

	var wrapper struct {
		Data []TLSScanResult `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &wrapper); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if len(wrapper.Data) != 1 {
		t.Fatalf("expected one result")
	}
	w := wrapper.Data[0].Warnings
	var hasDeprecated, hasWeak bool
	for _, warn := range w {
		if strings.Contains(warn, "deprecated TLS") {
			hasDeprecated = true
		}
		if strings.Contains(warn, "weak ciphers") {
			hasWeak = true
		}
	}
	if !hasDeprecated || !hasWeak {
		t.Fatalf("expected both warnings, got %v", w)
	}
}

func TestWarningsAppearText(t *testing.T) {
	resetGlobalFlags()

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("weak"))
	}))
	ts.TLS = getWeakTLSConfig()
	ts.StartTLS()
	defer ts.Close()

	cmd := buildTestableRivelaCmd([]string{
		"--host", ts.Listener.Addr().String(),
		"--insecure",
		"--full-cipher",
		"--format", "text",
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v\nOutput:\n%s", err, out.String())
	}

	outStr := out.String()
	if !strings.Contains(outStr, "deprecated TLS versions") {
		t.Fatalf("expected deprecated TLS warning, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "weak ciphers") {
		t.Fatalf("expected weak cipher warning, got:\n%s", outStr)
	}
}

func TestRivela_JSONOutput(t *testing.T) {
	resetGlobalFlags()

	// Create a quick TLS server
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("JSON Test")); err != nil {
			t.Fatalf("handler write failed: %v", err)
		}
	}))
	defer ts.Close()

	// Compose the command to run in JSON mode
	addr := ts.Listener.Addr().String()
	cmd := buildTestableRivelaCmd([]string{
		"--host", addr,
		"--format", "json",
		"--insecure", // to avoid self-signed verification failures
	})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	// Run the command
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v\nOutput:\n%s", err, out.String())
	}

	// Now parse the JSON output
	jsonStr := out.String()

	var wrapper struct {
		Cmd     string          `json:"cmd"`
		Version string          `json:"version"`
		Data    []TLSScanResult `json:"data"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &wrapper); err != nil {
		t.Fatalf("Failed to unmarshal JSON output: %v\nOutput:\n%s", err, jsonStr)
	}

	// 1. Check top-level fields
	if wrapper.Cmd != "rivela" {
		t.Errorf("Expected cmd=rivela, got %q", wrapper.Cmd)
	}
	if wrapper.Version != Version {
		t.Errorf("Expected version=%s, got %q", Version, wrapper.Version)
	}

	// 2. Check that we have data
	if len(wrapper.Data) == 0 {
		t.Fatalf("Expected at least one scan result in data, got 0\nFull JSON:\n%s", jsonStr)
	}

	// 3. Validate the first result object
	res := wrapper.Data[0]
	if res.Host == "" {
		t.Errorf("Expected 'Host' to be set, but was empty. Full object: %+v", res)
	}
	if res.Port == 0 {
		t.Errorf("Expected 'Port' to be set, but was 0. Full object: %+v", res)
	}
	if len(res.TLSVersions) == 0 {
		t.Errorf("Expected at least one TLS version result, got none. Full object: %+v", res)
	}

	// (Optional) Check that at least TLS 1.2 or 1.3 is "supported"
	var foundSupport bool
	for _, stat := range res.TLSVersions {
		if strings.Contains(stat, "supported") {
			foundSupport = true
			break
		}
	}
	if !foundSupport {
		t.Errorf("Expected at least one 'supported' TLS version in %v", res.TLSVersions)
	}
}

func TestRivela_JSONOutput_MultipleHosts(t *testing.T) {
	resetGlobalFlags()

	ts1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("Server1 JSON")); err != nil {
			t.Fatalf("handler write failed: %v", err)
		}
	}))
	defer ts1.Close()

	ts2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("Server2 JSON")); err != nil {
			t.Fatalf("handler write failed: %v", err)
		}
	}))
	defer ts2.Close()

	cmd := buildTestableRivelaCmd([]string{
		"--host", ts1.Listener.Addr().String(),
		"--host", ts2.Listener.Addr().String(),
		"--format", "json",
		"--insecure",
	})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Error scanning multiple servers in JSON: %v\nOutput:\n%s", err, out.String())
	}

	jsonStr := out.String()
	var wrapper struct {
		Cmd  string          `json:"cmd"`
		Data []TLSScanResult `json:"data"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &wrapper); err != nil {
		t.Fatalf("Failed to unmarshal JSON (multiple hosts): %v\nOutput:\n%s", err, jsonStr)
	}

	if len(wrapper.Data) != 2 {
		t.Fatalf("Expected 2 results in 'data', got %d", len(wrapper.Data))
	}
}

func TestRivela_JSONOutput_FullCipher(t *testing.T) {
	resetGlobalFlags()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("Cipher JSON Test")); err != nil {
			t.Fatalf("handler write failed: %v", err)
		}
	}))
	defer ts.Close()

	cmd := buildTestableRivelaCmd([]string{
		"--host", ts.Listener.Addr().String(),
		"--format", "json",
		"--insecure",
		"--full-cipher",
	})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v\nOutput:\n%s", err, out.String())
	}

	var wrapper struct {
		Data []TLSScanResult `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &wrapper); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if len(wrapper.Data) == 0 {
		t.Fatalf("Expected at least 1 result")
	}

	// Check that we have a CipherSuites map in the JSON
	if wrapper.Data[0].CipherSuites == nil {
		t.Fatalf("Expected 'CipherSuites' in JSON output when --full-cipher is used.")
	}
}

func TestRivela_CSVOutput(t *testing.T) {
	resetGlobalFlags()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("csv")); err != nil {
			t.Fatalf("handler write failed: %v", err)
		}
	}))
	defer ts.Close()

	cmd := buildTestableRivelaCmd([]string{
		"--host", ts.Listener.Addr().String(),
		"--format", "csv",
		"--insecure",
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v\nOutput:\n%s", err, out.String())
	}

	r := csv.NewReader(strings.NewReader(out.String()))
	recs, err := r.ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 records got %d", len(recs))
	}
	if recs[1][0] != ts.Listener.Addr().String() {
		t.Fatalf("unexpected host %s", recs[1][0])
	}
}

func TestCheckTLSVersionTimeout(t *testing.T) {
	resetGlobalFlags()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			t.Logf("listener close error: %v", err)
		}
	}()

	flagTimeout = 100 * time.Millisecond
	timeout := flagTimeout

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		time.Sleep(2 * timeout)
		if err := conn.Close(); err != nil {
			t.Logf("conn close error: %v", err)
		}
	}()

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	status := checkTLSVersion(host, port, tls.VersionTLS12)
	if status != "connection failed (timeout)" {
		t.Fatalf("expected timeout, got %q", status)
	}
}

func TestCheckTLSVersionConnectionRefused(t *testing.T) {
	resetGlobalFlags()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil { // close immediately so no one is listening
		t.Logf("listener close error: %v", err)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	status := checkTLSVersion(host, port, tls.VersionTLS12)
	if !strings.HasPrefix(status, "connection failed") {
		t.Fatalf("expected connection failed, got %q", status)
	}
}

func TestCheckTLSVersionSuccess(t *testing.T) {
	resetGlobalFlags()

	flagInsecure = true

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("ok")); err != nil {
			t.Fatalf("handler write failed: %v", err)
		}
	}))
	defer ts.Close()

	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	status := checkTLSVersion(host, port, tls.VersionTLS12)
	if status != "supported" {
		t.Fatalf("expected supported, got %q", status)
	}
}

func TestFillDetailsTimeout(t *testing.T) {
	resetGlobalFlags()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			t.Logf("listener close error: %v", err)
		}
	}()

	flagTimeout = 100 * time.Millisecond
	timeout := flagTimeout

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		time.Sleep(2 * timeout)
		if err := conn.Close(); err != nil {
			t.Logf("conn close error: %v", err)
		}
	}()

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	r := &TLSScanResult{}
	err = fillDetails(r, host, port)
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestFillDetailsOCSPStapling(t *testing.T) {
	resetGlobalFlags()
	flagInsecure = true

	// Server without stapling
	noStaple := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("no"))
	}))
	noStaple.TLS = getSelfSignedTLSConfig()
	noStaple.StartTLS()
	defer noStaple.Close()

	host, portStr, _ := net.SplitHostPort(noStaple.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	r := &TLSScanResult{}
	if err := fillDetails(r, host, port); err != nil {
		t.Fatalf("fillDetails no staple: %v", err)
	}
	if r.OCSPStapled {
		t.Fatalf("expected OCSPStapled=false")
	}

	// Server with stapling
	withStaple := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("yes"))
	}))
	withStaple.TLS = getSelfSignedTLSConfig()
	if len(withStaple.TLS.Certificates) > 0 {
		withStaple.TLS.Certificates[0].OCSPStaple = []byte("dummy")
	}
	withStaple.StartTLS()
	defer withStaple.Close()

	host2, portStr2, _ := net.SplitHostPort(withStaple.Listener.Addr().String())
	port2, _ := strconv.Atoi(portStr2)
	r2 := &TLSScanResult{}
	if err := fillDetails(r2, host2, port2); err != nil {
		t.Fatalf("fillDetails with staple: %v", err)
	}
	if !r2.OCSPStapled || len(r2.OCSPResponse) == 0 {
		t.Fatalf("expected OCSPStapled=true and response")
	}
}

func TestInitConfigWithFile(t *testing.T) {
	resetGlobalFlags()

	tmp, err := os.CreateTemp("", "rivela_config_*.yaml")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close temp: %v", err)
	}
	cfgFile = tmp.Name()
	defer func() {
		if err := os.Remove(cfgFile); err != nil {
			t.Logf("remove temp: %v", err)
		}
	}()

	initConfig()
	if viper.ConfigFileUsed() != cfgFile {
		t.Fatalf("expected config file used")
	}
}

func TestInitConfigDefault(t *testing.T) {
	resetGlobalFlags()
	t.Setenv("HOME", t.TempDir())
	cfgFile = ""
	initConfig()
}

func TestGetCommand(t *testing.T) {
	if GetCommand() == nil {
		t.Fatal("expected command")
	}
}

func TestExecute_NoError(t *testing.T) {
	called := false
	orig := rootCmd
	rootCmd = &cobra.Command{RunE: func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}}
	defer func() { rootCmd = orig }()

	Execute()
	if !called {
		t.Fatal("expected Execute to run command")
	}
}

func TestGradeComputation(t *testing.T) {
	cases := []struct {
		name   string
		cfg    *tls.Config
		expect string
	}{
		{"strong", getSelfSignedTLSConfig(), "A"},
		{"weak", getWeakTLSConfig(), "B"},
		{"old", getOldTLSConfig(), "C"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetGlobalFlags()
			flagInsecure = true

			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("grade"))
			}))
			ts.TLS = tc.cfg
			ts.StartTLS()
			defer ts.Close()

			cmd := buildTestableRivelaCmd([]string{
				"--host", ts.Listener.Addr().String(),
				"--format", "json",
				"--insecure",
			})
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)

			if err := cmd.Execute(); err != nil {
				t.Fatalf("execute: %v\n%s", err, out.String())
			}

			var wrapper struct {
				Data []TLSScanResult `json:"data"`
			}
			if err := json.Unmarshal(out.Bytes(), &wrapper); err != nil {
				t.Fatalf("unmarshal: %v\n%s", err, out.String())
			}
			if len(wrapper.Data) != 1 {
				t.Fatalf("expected 1 result")
			}
			if wrapper.Data[0].Grade != tc.expect {
				t.Fatalf("expected grade %s got %s", tc.expect, wrapper.Data[0].Grade)
			}
		})
	}
}

func resetGlobalFlags() {
	flagHosts = nil
	flagPort = 443
	flagInsecure = false
	flagFullCipher = false
	flagSNI = ""
	flagOutputFormat = "text"
	flagTimeout = 5 * time.Second
	flagConcurrency = 10
	flagFile = ""
	flagProgress = false
	flagExpiryWarningDays = 30
}

// Simple, short 1024-bit RSA cert/key that should parse cleanly
var selfSignedCertPEM = `-----BEGIN CERTIFICATE-----
MIIDMTCCAhmgAwIBAgIULb2q+5DvP/yILJ8DmRJu2MhLrdEwDQYJKoZIhvcNAQEL
BQAwKDEUMBIGA1UEAwwLZXhhbXBsZS5jb20xEDAOBgNVBAoMB0FjbWUgQ28wHhcN
MjUwMjI3MjE1MDI0WhcNMjYwMjI3MjE1MDI0WjAoMRQwEgYDVQQDDAtleGFtcGxl
LmNvbTEQMA4GA1UECgwHQWNtZSBDbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAN+68g7DEGl4chPH+UEdJfOzk4rv12Co20mDdycRF7dfypiFiDEbDHjY
HlDKtO9a8krCOX5UP6OMSr3DDKs97mUWmIJaPPJaFHzhCZF2TJg4oVYM86lqZTr8
h9FKwSg4KjdA7xY39Ez2ey+3vThro1NDS5fySXFw/eror83vn6F21pMFpI9j7Fp5
i2Fjd0nmwN6omfk1aygeiIecGnyXA4jGKv5pryN7dyrPtNHzzF4p8lPLrXjtZTzd
OIgjVyQSX8Z+Zn746mU9ml43XiHaOuL44TFBXILx6ER9QYmd6FvXvtCMBd1Gy67c
TgUt+6hQWV/Cc1mdJHUwEY6bgz4ISEsCAwEAAaNTMFEwHQYDVR0OBBYEFGij14PZ
mOo/1UHGcqWQ+3llN5A8MB8GA1UdIwQYMBaAFGij14PZmOo/1UHGcqWQ+3llN5A8
MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABceKf11LsPLtlpU
Y6M/kmMbiYQPoLjSsfW6I3pkNuiap6sATbjAl9umxU1dYi9dlep+V/Lzvq3kFngZ
+4pDaj7eLCpBCFg9vxBJVI9VvTqbQjQeR2QEz6uEzFGoE7K6EtGN2bw2HWu6h7Tk
x5fKnjVVZW2Je0gjmjoBLCmaZs0rEFHV14RcKOdXpHvY/VgmggDeTtA3+OkLsvq9
gzJwVpiwQoiUHdZkUJYlTS5JEZmi1jrqJvuzPIZDsNNUfBggG4Cg1uNh2/f3cxjB
ae1v/vacl041v5w66nhB0b5pMJtgFnzn9ajT7UPt7W7uykrwEOcg1unJRdEsPiBM
/uVFoTE=
-----END CERTIFICATE-----`

var selfSignedKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDfuvIOwxBpeHIT
x/lBHSXzs5OK79dgqNtJg3cnERe3X8qYhYgxGwx42B5QyrTvWvJKwjl+VD+jjEq9
wwyrPe5lFpiCWjzyWhR84QmRdkyYOKFWDPOpamU6/IfRSsEoOCo3QO8WN/RM9nsv
t704a6NTQ0uX8klxcP3q6K/N75+hdtaTBaSPY+xaeYthY3dJ5sDeqJn5NWsoHoiH
nBp8lwOIxir+aa8je3cqz7TR88xeKfJTy6147WU83TiII1ckEl/GfmZ++OplPZpe
N14h2jri+OExQVyC8ehEfUGJnehb177QjAXdRsuu3E4FLfuoUFlfwnNZnSR1MBGO
m4M+CEhLAgMBAAECggEAUDucG+QjSheaHXLs9cdsuVEwe7ZYUD8t6NafD+EG1smg
/4J/nVCcb+fdM08GhQHh+yJc+OtgqReiJBxDOlPq3tC0H6cZzTW1vDT9t+8rN7mz
Tgc2CI7xv64ZTNqYm4JMzWTZeOfXEhSgh7PGRWoAd9cd0F9grDB/ttL8XQdugTnP
ng3aNHqlpSmBJ4bRLgnOHPyprLp6SWZ/heSD08rJKr0mGWsqfPtjC4O9YSjyRc9/
N3biSXRfKLUfkIID2LYd8+hybXwszufz5Cv7NESiSNhJzgDeBRpgrzTOCimbwegT
M10nx4ZmPopzPWU8GWxAGKBPqN9r6G7wewd9rcFozQKBgQD5LkvpWYs91D+Rcv7z
b5HjwhcprTyxKV09+34Qn8UyZyt6R+06y1qIzirR9waNFf8BC/ITyYiK7etB2RMw
tGIMyaPXTaUTX3K4DnqKg9VdYTK/0hA2ZXQvq3m+3CKzCFZCORNSHlEFDpN8gcWf
9/lbcA556rx5/Pgf4RaQdjFeJQKBgQDl2lkZ+f/Zg3Pku/HMgzgfUBHyNPREEyBU
J9oSmFDRZz9IVGWMc/4vEdIYsTdKFwHUIJ6lydVrbYA6H4FMETgIEbEuQYjLvhs9
aiXTabyp/cR3tpMqF11+HBf663woJWqLxsSjKQM1c7tvyxXzifNzdNexa8tNf6S2
LZfZltEprwKBgQC8VNaBJvGLqKjnCNBTM6dDSkXxdQLjL81OdI9ihy8nGj0NLeHK
RzpFHfXVPexQpChZJSsw82hlAM+HtEbB0AQvgBN6PjAfBUwSerb5jAyuiDEwM9eX
FXUMNoFM1NrRD+MKKFNHBKzdspecSgURE/3+syHt2ZHcbWsnxRsl0n8blQKBgQC1
RyK0qQXOn6z8ffnyyJ6vm2+77WWkds0tcgy8U6KRtHMlcWJxhl2288AWN1YaudB4
Y42bxXXrdv4FWSmZO49MVd++UnM39OP46MmSVjc0fm6/159zN+BFgJStEaHm67N/
L7GP2N2t/2uZfLsASxFVQpaGWDSMF5ppD8ZOFnM6AwKBgQCW39oB3GYkeMj6gcV9
xAzMz+E1R3IjMKdEDHOKKR6uRDe5YE/NCW2GGar9z6M+E/ywaadFz4X/wTtDSftT
rp/XtqVluPpovHg3rRsCu7IN9HruM64Ixo1IfQoaVj5GHW8eK70XtbN8ccEXSIDU
NXKp24zFc6CFCap06BqTXoAZgw==
-----END PRIVATE KEY-----
`
