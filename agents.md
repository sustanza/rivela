

# Agents Package – Contribution Guidelines

This document codifies the expectations for *all* code that lives in the `agents` package or any of its sub‑packages.  The aims are:

* **Standard‑library‑first**: minimise third‑party dependencies.
* **Idiomatic & consistent**: follow the [Google Go Style Guide](https://google.github.io/styleguide/go/).
* **Modern**: leverage features available in the project’s minimum Go version (currently **Go 1.24**).
* **Well‑tested**: maintain ≥ 90 % line coverage and ≥ 80 % branch coverage.

---

## 1. Standard‑Library‑First

* Reach for the Go standard library before adding external modules.  
* When an external dependency is unavoidable, the pull‑request *must* include a **“Dependency Justification”** section explaining:
  1. Why the stdlib is insufficient.
  2. Why this library is the best option (maintenance, licence, size).
  3. How the dependency will be kept up‑to‑date.
* Generated or tooling‑only dependencies should **not** appear in `go.mod`.  

## 2. Coding Style & Practices

* Follow the [Google Go Style Guide](https://google.github.io/styleguide/go/) and the official [Effective Go](https://go.dev/doc/effective_go) recommendations for names, error handling, comments, and file organisation.  
* All code is auto‑formatted with `gofmt -s` and `goimports`; CI will fail on drift.  
* Use table‑driven tests and sub‑tests (`t.Run`) to minimise repetition.  
* Avoid “stutter” in package names (`agents/client.Client` → `client.Client`).  
* Logging: always use the Go standard library's `log` package for logging; avoid third-party logging frameworks.
* Concurrency: leverage Go’s built-in concurrency primitives (goroutines, channels, `sync`, and `context`) for parallelism; adhere to the patterns in the Google Go Style Guide for safe and readable concurrent code.
* Error handling:
  * Wrap external‑boundary errors with `%w`.
  * Prefer sentinel errors (`var ErrFoo = errors.New("...")`) over string matching.

## 3. Using Go 1.24 Features

Go 1.24 is the project’s minimum version. You may (and should) use:

| Area | Feature | Notes |
|------|---------|-------|
| Generics | **Generic type aliases** | Provide versioned API aliases without wrappers. |
| Collections | `maps.Copy`, `maps.EqualFunc` | Use instead of manual loops. |
| Slices | `min`, `max`, `sum` pipeline functions | Leverage for concise numeric reductions. |
| Testing | `t.Setenv`, `testing/slogtest` | Use helpers instead of bespoke env helpers or log bridges. |

Only add `//go:build` version guards when absolutely necessary; otherwise bump the `go` directive for the whole module.

## 4. Testing & Coverage ≥ 90 %

* New exported functions **require** unit tests.  
* Run `go test ./... -race -coverprofile=coverage.out`; PRs that reduce coverage below **90 %** fail CI.  
* Benchmarks (`*_test.go` containing `BenchmarkXxx`) are encouraged for hot paths.  
* Use `t.Cleanup` for teardown and `testing/quick` for property‑based tests where valuable.  

### Fast feedback loop

Developers can run:

```bash
make test   # or: go test ./... -race -count=1
make cover  # opens HTML coverage report
```

## 5. Pull‑Request Checklist

1. `go vet ./...` passes.
2. `golangci-lint run` passes with default linters plus `unused`, `revive`.
3. Tests added/updated; coverage ≥ 90 %.
4. No new dependencies **unless justified** (see §1).
5. Public surface documented with proper Go doc comments.

---

*Last updated: 2025‑06‑07*