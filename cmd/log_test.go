package cmd

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteLogFile_JSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "out.json")
	results := []*TLSScanResult{
		{Host: "example.com", Port: 443, TLSVersions: map[string]string{"TLS 1.2": "supported"}, NegotiatedCipher: "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
		{Host: "foo.com", Port: 443, TLSVersions: map[string]string{"TLS 1.3": "supported"}},
	}

	if err := writeLogFile(path, "json", results); err != nil {
		t.Fatalf("write json: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var entries []LogEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries")
	}
	if !entries[0].WeakCiphers {
		t.Errorf("expected weak cipher true")
	}
	if entries[1].HighestTLS != "TLS 1.3" {
		t.Errorf("expected TLS 1.3 got %s", entries[1].HighestTLS)
	}
}

func TestWriteLogFile_CSV(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "out.csv")
	results := []*TLSScanResult{
		{Host: "bar.com", Port: 443, TLSVersions: map[string]string{"TLS 1.0": "supported"}},
	}
	if err := writeLogFile(path, "csv", results); err != nil {
		t.Fatalf("write csv: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}()
	r := csv.NewReader(f)
	recs, err := r.ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 records got %d", len(recs))
	}
	if recs[1][0] != "bar.com:443" {
		t.Errorf("unexpected host %s", recs[1][0])
	}
}
