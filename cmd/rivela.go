package cmd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	progressbar "github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

// Global flags
var (
	flagHosts             []string
	flagPort              int
	flagInsecure          bool
	flagFullCipher        bool
	flagSNI               string
	flagOutputFormat      string
	flagTimeout           time.Duration
	flagConcurrency       int
	flagFile              string
	flagProgress          bool
	flagExpiryWarningDays int
	flagCompare           bool
	flagLogFile           string
	flagLogFormat         string
	flagColor             bool
)

// RivelaCmd represents the rivela command
var RivelaCmd = &cobra.Command{
	Use:   "rivela",
	Short: "Scan TLS configurations of a host",
	Long:  `Rivela scans the TLS configurations of a specified host and provides details about the certificates, supported protocols, and ciphers.`,
	RunE:  runRivela,
}

func init() {
	RivelaCmd.Flags().StringSliceVar(&flagHosts, "host", nil, "Host(s) to scan. You can specify host:port directly.")
	RivelaCmd.Flags().IntVar(&flagPort, "port", 443, "Port to scan if not specified in --host")
	RivelaCmd.Flags().BoolVar(&flagInsecure, "insecure", false, "Allow insecure/invalid certificates without error")
	RivelaCmd.Flags().BoolVar(&flagFullCipher, "full-cipher", false, "Enumerate all cipher suites individually")
	RivelaCmd.Flags().StringVar(&flagSNI, "sni", "", "Optional Server Name Indication override")
	RivelaCmd.Flags().StringVar(&flagOutputFormat, "format", "text", "Output format (text|json|csv)")
	RivelaCmd.Flags().DurationVar(&flagTimeout, "timeout", 5*time.Second, "Connection timeout per TLS handshake")
	RivelaCmd.Flags().IntVar(&flagConcurrency, "concurrency", 10, "Number of concurrent scans")
	RivelaCmd.Flags().StringVar(&flagFile, "file", "", "File containing list of hosts (one per line)")
	RivelaCmd.Flags().BoolVar(&flagProgress, "progress", false, "Display progress bar during scan")
	RivelaCmd.Flags().IntVar(&flagExpiryWarningDays, "expiry-warning-days", 30, "Warn if certificate expires within N days")
	RivelaCmd.Flags().BoolVar(&flagCompare, "compare", false, "Compare mode: display side-by-side table")
	RivelaCmd.Flags().StringVar(&flagLogFile, "log-file", "", "Optional file to write summary log")
	RivelaCmd.Flags().StringVar(&flagLogFormat, "log-format", "csv", "Log format (csv|json)")
	RivelaCmd.Flags().BoolVar(&flagColor, "color", false, "Enable ANSI color output")
}

// runRivela is the main entry point, orchestrating concurrency & printing results.
func runRivela(cmd *cobra.Command, args []string) error {
	hosts, err := gatherHosts()
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return errors.New("no hosts provided (use --host or --file)")
	}

	// Build a list of (host, port) from each line
	targets := make([]struct {
		host string
		port int
	}, 0, len(hosts))
	for _, rawHost := range hosts {
		h, p, parseErr := parseHostPort(rawHost, flagPort)
		if parseErr != nil {
			return fmt.Errorf("invalid host/port %q: %v", rawHost, parseErr)
		}
		targets = append(targets, struct {
			host string
			port int
		}{host: h, port: p})
	}

	sem := make(chan struct{}, flagConcurrency)
	var wg sync.WaitGroup
	results := make([]*TLSScanResult, len(targets))

	var bar *progressbar.ProgressBar
	if flagProgress {
		bar = progressbar.NewOptions(len(targets),
			progressbar.OptionSetWriter(cmd.ErrOrStderr()),
			progressbar.OptionShowCount(),
		)
	}

	for i, t := range targets {
		i, t := i, t // rebind for closure
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res := scanHost(t.host, t.port)
			results[i] = res
			if bar != nil {
				_ = bar.Add(1)
			}
		}()
	}
	wg.Wait()

	if bar != nil {
		_ = bar.Finish()
	}

	// if any host failed, return an overall error
	var overallErr error
	for _, r := range results {
		if r != nil && r.Error != nil {
			overallErr = errors.New("one or more hosts failed scanning")
			break
		}
	}

	if err := writeLogFile(flagLogFile, flagLogFormat, results); err != nil {
		return fmt.Errorf("write log file: %w", err)
	}

	// Print results
	if flagOutputFormat == "json" {
		return printJSON(cmd, results, overallErr)
	}
	if flagOutputFormat == "csv" {
		return printCSV(cmd, results, overallErr)
	}
	if flagCompare {
		printCompare(cmd, results)
	} else {
		printText(cmd, results)
	}
	return overallErr
}

// gatherHosts merges any hosts from flags and from a file
func gatherHosts() ([]string, error) {
	var all []string
	for _, h := range flagHosts {
		parts := strings.Split(h, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				all = append(all, p)
			}
		}
	}
	if flagFile != "" {
		data, err := os.ReadFile(flagFile)
		if err != nil {
			return nil, err
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				all = append(all, line)
			}
		}
	}
	return all, nil
}

// parseHostPort splits host[:port]. If no port is present, use defaultPort.
func parseHostPort(h string, defaultPort int) (string, int, error) {
	if strings.HasPrefix(h, "http://") {
		h = strings.TrimPrefix(h, "http://")
	} else if strings.HasPrefix(h, "https://") {
		h = strings.TrimPrefix(h, "https://")
	}

	if h == "" || strings.HasPrefix(h, ":") {
		return "", 0, fmt.Errorf("missing host in address")
	}
	if strings.HasSuffix(h, ":") {
		return "", 0, fmt.Errorf("missing port in address")
	}

	host, portStr, err := net.SplitHostPort(h)
	if err == nil {
		if portStr == "" {
			return "", 0, fmt.Errorf("missing port in address")
		}
		if host == "" {
			return "", 0, fmt.Errorf("missing host in address")
		}
		p, cErr := strconv.Atoi(portStr)
		if cErr != nil {
			return "", 0, cErr
		}
		return host, p, nil
	}
	// If net.SplitHostPort fails, user might have typed "example.com" with no port
	return h, defaultPort, nil
}

// GetCommand exports the command for main.go
func GetCommand() *cobra.Command {
	return RivelaCmd
}
