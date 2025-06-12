package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// writeLogFile writes summary log entries to the given path in the specified format.
func writeLogFile(path, format string, results []*TLSScanResult) (err error) {
	if path == "" {
		return nil
	}

	entries := make([]LogEntry, 0, len(results))
	for _, r := range results {
		if r == nil {
			continue
		}
		entries = append(entries, LogEntry{
			Host:        fmt.Sprintf("%s:%d", r.Host, r.Port),
			HighestTLS:  highestSupportedTLS(r),
			WeakCiphers: hasWeakCipher(r),
		})
	}

	if format == "json" {
		data, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(path, data, 0o644)
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	w := csv.NewWriter(f)
	if err := w.Write([]string{"host", "highest_tls", "weak_ciphers"}); err != nil {
		return err
	}
	for _, e := range entries {
		if err := w.Write([]string{e.Host, e.HighestTLS, strconv.FormatBool(e.WeakCiphers)}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

// highestSupportedTLS returns the highest supported TLS version string.
func highestSupportedTLS(r *TLSScanResult) string {
	versions := []string{"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"}
	for _, v := range versions {
		if r.TLSVersions[v] == "supported" {
			return v
		}
	}
	return ""
}

// hasWeakCipher reports whether any weak cipher was seen.
func hasWeakCipher(r *TLSScanResult) bool {
	if _, ok := weakCipherNames[r.NegotiatedCipher]; ok && r.NegotiatedCipher != "" {
		return true
	}
	for c, ok := range r.CipherSuites {
		if ok {
			if _, weak := weakCipherNames[c]; weak {
				return true
			}
		}
	}
	return false
}
