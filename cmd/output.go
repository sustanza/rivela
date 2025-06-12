package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

func printJSON(cmd *cobra.Command, results []*TLSScanResult, overallErr error) error {
	output := struct {
		Cmd     string           `json:"cmd"`
		Version string           `json:"version"`
		Data    []*TLSScanResult `json:"data"`
	}{
		Cmd:     "rivela",
		Version: Version,
		Data:    results,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}
	cmd.Println(string(data))
	return overallErr
}

func printText(cmd *cobra.Command, results []*TLSScanResult) {
	for _, r := range results {
		cmd.Printf("\n==== Results for %s:%d ====\n", r.Host, r.Port)

		var versions []string
		for v := range r.TLSVersions {
			versions = append(versions, v)
		}
		sort.Slice(versions, func(i, j int) bool {
			return versionSorter(versions[i]) < versionSorter(versions[j])
		})
		for _, v := range versions {
			stat := r.TLSVersions[v]
			switch {
			case strings.Contains(stat, "supported"):
				stat = colorize(stat, ansiGreen)
			case strings.Contains(stat, "not supported"), strings.HasPrefix(stat, "connection failed"):
				stat = colorize(stat, ansiRed)
			}
			cmd.Printf("%s => %s\n", v, stat)
		}

		if r.NegotiatedTLS != "" || r.NegotiatedCipher != "" {
			cmd.Println("\n--- Detailed TLS Handshake Info ---")
			cmd.Printf("Negotiated TLS: %s\n", r.NegotiatedTLS)
			if r.NegotiatedProto != "" {
				cmd.Printf("Application Protocol: %s\n", r.NegotiatedProto)
			}
			cmd.Printf("Cipher Suite: %s\n", r.NegotiatedCipher)
			if r.OCSPStapled {
				cmd.Println("OCSP Stapling: yes")
			} else {
				cmd.Println("OCSP Stapling: no")
			}
		}

		if len(r.Certificates) > 0 {
			cmd.Println()
			for i, c := range r.Certificates {
				cmd.Printf("Certificate [%d]:\n", i)
				cmd.Printf("  Subject: %s\n", c.Subject)
				cmd.Printf("  Issuer: %s\n", c.Issuer)
				cmd.Printf("  NotBefore: %v\n", c.NotBefore)
				cmd.Printf("  NotAfter: %v\n", c.NotAfter)
				cmd.Printf("  DNS Names: %v\n", c.DNSNames)
				cmd.Printf("  IP Addrs: %v\n", c.IPAddresses)
				cmd.Printf("  Valid: %v\n", c.Valid)
				cmd.Printf("  Signature Algorithm: %s\n", c.SignatureAlgorithm)
				if c.WeakSignature {
					cmd.Printf("  Warning: weak signature algorithm\n")
				}
				if c.ExpiringSoon {
					cmd.Printf("  Warning: expires within %d days\n", flagExpiryWarningDays)
				}
				if c.ValidationErr != "" {
					cmd.Printf("  ValidationErr: %s\n", c.ValidationErr)
				}
			}
		}

		if flagFullCipher && r.CipherSuites != nil {
			cmd.Println("\n--- Full Cipher Enumeration ---")
			var cNames []string
			for c := range r.CipherSuites {
				cNames = append(cNames, c)
			}
			sort.Strings(cNames)
			for _, cName := range cNames {
				cmd.Printf("  %s => %v\n", cName, r.CipherSuites[cName])
			}
		}

		cmd.Println("\n--- Summary ---")
		supportedCount := 0
		for _, status := range r.TLSVersions {
			if strings.Contains(status, "supported") {
				supportedCount++
			}
		}
		cmd.Printf("Supported TLS versions: %d out of %d tested\n", supportedCount, len(r.TLSVersions))

		switch r.NegotiatedTLS {
		case "TLS 1.3":
			cmd.Println("Server negotiated TLS 1.3 – currently the most secure modern standard.")
		case "TLS 1.2":
			cmd.Println("Server supports TLS 1.2 – acceptable modern standard.")
		default:
			cmd.Println("Server does not support TLS 1.2+ – consider upgrading for better security.")
		}

		if len(r.Warnings) > 0 {
			cmd.Println("\n--- Warnings ---")
			for _, w := range r.Warnings {
				cmd.Println(colorize("WARNING: "+w, ansiYellow))
			}
		}

		if r.Grade != "" {
			grade := r.Grade
			switch grade {
			case "A":
				grade = colorize(grade, ansiGreen)
			case "B", "C":
				grade = colorize(grade, ansiYellow)
			case "F":
				grade = colorize(grade, ansiRed)
			}
			cmd.Printf("\nOverall Grade: %s\n", grade)
		}
	}
}

func printCompare(cmd *cobra.Command, results []*TLSScanResult) {
	versionSet := make(map[string]struct{})
	for _, r := range results {
		for v := range r.TLSVersions {
			versionSet[v] = struct{}{}
		}
	}

	versions := make([]string, 0, len(versionSet))
	for v := range versionSet {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool {
		return versionSorter(versions[i]) < versionSorter(versions[j])
	})

	header := append([]string{"Host"}, versions...)
	header = append(header, "CipherCount")
	cmd.Println(strings.Join(header, "\t"))

	for _, r := range results {
		row := []string{fmt.Sprintf("%s:%d", r.Host, r.Port)}
		for _, v := range versions {
			val, ok := r.TLSVersions[v]
			if !ok {
				row = append(row, "n/a")
			} else {
				row = append(row, val)
			}
		}
		count := 0
		for _, ok := range r.CipherSuites {
			if ok {
				count++
			}
		}
		row = append(row, strconv.Itoa(count))
		cmd.Println(strings.Join(row, "\t"))
	}
}

func printCSV(cmd *cobra.Command, results []*TLSScanResult, overallErr error) error {
	versionSet := make(map[string]struct{})
	for _, r := range results {
		for v := range r.TLSVersions {
			versionSet[v] = struct{}{}
		}
	}

	versions := make([]string, 0, len(versionSet))
	for v := range versionSet {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool {
		return versionSorter(versions[i]) < versionSorter(versions[j])
	})

	header := append([]string{"host"}, versions...)
	header = append(header, "cipher_count")

	w := csv.NewWriter(cmd.OutOrStdout())
	if err := w.Write(header); err != nil {
		return err
	}
	for _, r := range results {
		row := []string{fmt.Sprintf("%s:%d", r.Host, r.Port)}
		for _, v := range versions {
			val, ok := r.TLSVersions[v]
			if !ok {
				row = append(row, "n/a")
			} else {
				row = append(row, val)
			}
		}
		count := 0
		for _, ok := range r.CipherSuites {
			if ok {
				count++
			}
		}
		row = append(row, strconv.Itoa(count))
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return overallErr
}
