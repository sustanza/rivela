# 🔒 Rivela: TLS Configuration Scanner

**Rivela** is a command line tool written in Go for quickly inspecting the TLS configuration of one or more hosts. It retrieves certificate information, checks supported protocol versions and, optionally, enumerates available cipher suites.

---

## 🚀 Features

- **Inspect TLS Configurations**: View certificate details, supported protocol versions, negotiated cipher suite, ALPN protocol and OCSP stapling status.
- **Multiple Hosts at Once**: Scan several targets concurrently.
- **Flexible Output**: Display results as text, JSON or CSV.
- **Full Cipher Enumeration**: Use `--full-cipher` to test every cipher suite individually.
- **Compare Mode**: `--compare` prints a side-by-side table for multiple hosts.
- **Progress Bar**: `--progress` shows scan progress.
- **Colorised Output**: `--color` highlights results with ANSI colours.
- **Security Grading**: Assigns an A–F grade based on supported protocol versions.
- **Expiry Warnings**: `--expiry-warning-days` highlights certificates that expire soon.
- **Concise Logging**: Optionally write a CSV or JSON file summarising each host using `--log-file` and `--log-format`.
- **Custom Port and SNI**: Override the port with `--port` and the Server Name Indication with `--sni`.
- **Adjustable Concurrency**: Control scan parallelism via `--concurrency`.
- **Configurable Timeout**: Set handshake timeout with `--timeout`.
- **Read Hosts from a File**: Provide a list via `--file`.
- **Config File Support**: Store defaults in `~/.rivela.yaml` or supply a custom path with `--config`.

---

## 💻 Getting Started

### Installation

```shell
# Install the CLI
go install github.com/sustanza/rivela@latest
```

### Example Configuration

Create a `.rivela.yaml` file in your home directory to persist options:

```yaml
rivela:
  hosts:
    - example.com
  port: 443
  concurrency: 5
  full_cipher: false
  insecure: false
  output_format: text
  timeout: 5s
```

See `.rivela.yaml.example` in this repository for all available fields.

---

## 🔑 Usage

```shell
rivela --host example.com
```

### Key Scenarios
1. **Single Host Analysis**
   ```shell
   rivela --host example.com
   ```
2. **Multiple Hosts**
   ```shell
   rivela --host example.com --host example.org --concurrency 5
   ```
3. **Reading from File**
   ```shell
   rivela --file hosts.txt --concurrency 10
   ```
4. **Allow Self‑Signed Certificates**
   ```shell
   rivela --host internal.local --insecure
   ```
5. **JSON Output**
   ```shell
   rivela --host example.com --format=json
   ```
6. **CSV Output**
   ```shell
   rivela --host example.com --format=csv
   ```
7. **Write Summary Log**
   ```shell
   rivela --host example.com --log-file report.csv
   ```
8. **Full Cipher Enumeration**
   ```shell
   rivela --host example.com --full-cipher
   ```
9. **Compare Multiple Hosts**
   ```shell
   rivela --host example.com --host foo.com --compare
   ```
10. **Show Progress Bar**
   ```shell
   rivela --file hosts.txt --progress
   ```
11. **Enable Colour Output**
   ```shell
   rivela --host example.com --color
   ```
12. **Custom Port**
   ```shell
   rivela --host example.com --port 8443
   ```
13. **Override SNI**
   ```shell
   rivela --host 192.0.2.1 --sni example.com
   ```
14. **Increase Timeout**
   ```shell
   rivela --host example.com --timeout 10s
   ```
15. **Specify Log Format**
   ```shell
   rivela --host example.com --log-file out.json --log-format json
   ```
16. **Custom Expiry Warning**
   ```shell
   rivela --host example.com --expiry-warning-days 14
   ```
17. **Use a Custom Config File**
   ```shell
   rivela --config /path/to/config.yaml
   ```

### Example Research Scenario

Suppose a security team wants to study the adoption of TLS 1.3 among campus
websites. They prepare a `campus.txt` file listing each target domain:

```text
college.example.edu
intranet.example.edu
public.example.edu
```

Running Rivela with logging enabled captures the TLS versions and cipher suites
for later analysis:

```shell
rivela --file campus.txt --progress --full-cipher \
  --log-file research.csv --log-format csv
```

The resulting `research.csv` can then be imported into spreadsheets or scripts
to evaluate which servers still rely on outdated protocols, making it easy to
generate statistics for a report or academic paper.

---

## 🧪 Testing

Run all tests with:

```shell
cd /path/to/rivela
go test ./...
```

---

## 🐞 Reporting Issues

Found a bug or have a feature request? Please open an issue on [GitHub Issues](https://github.com/sustanza/rivela/issues).

---

## 📄 License

This project is licensed under the [MIT License](./LICENSE)
