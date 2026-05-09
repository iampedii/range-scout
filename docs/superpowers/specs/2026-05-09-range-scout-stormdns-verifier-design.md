# range-scout: Replace DNSTT verifier with StormDNS verifier + add bogon filter

- **Date:** 2026-05-09
- **Author:** rasoultaji
- **Branch:** `feat/stormdns-verifier`
- **Status:** Approved (design phase)

## Summary

Replace range-scout's existing DNSTT verification stage with a StormDNS-protocol verifier that uses a domain + key to confirm each candidate resolver can carry an encrypted upload+download MTU probe. Add an IANA IPv4 special-use bogon filter so private/reserved address space is never scanned.

The verifier mirrors what StormDNS's own client does in `recheckResolverConnection` (`internal/client/resolver_health.go:748`): two encrypted probes per resolver, both must pass. Successful resolvers are emitted both in range-scout's existing `txt`/`csv`/`json` formats and in two new StormDNS-native formats (`client_resolvers.simple` and the cache-log format) so a real StormDNS client can consume the output directly.

## Goals & Scope

### In scope

1. Remove `internal/dnstt/`, `internal/dnsttembed/`, `third_party/dnstt/` (full DNSTT removal).
2. Add `third_party/stormdns/` (vendored StormDNS source, MIT-licensed) and `internal/stormdnsembed/` (thin wrapper exposing an MTU-probe-only `ProbeMTU` API). The orchestrator `Verify` lives in `internal/stormdns/`.
3. Replace the DNSTT TUI screen with a relabeled StormDNS screen. Fields: `StormDNS Domain`, `StormDNS Key`, `Score Threshold`, `Query Size`, `Test Nearby IPs`. Drop `E2E URL`, `SOCKS Username`, `SOCKS Password`.
4. Add an IANA IPv4 special-use bogon filter at `internal/prefixes/prefixes.go` `WalkHosts`.
5. Add two extra exporters:
   - StormDNS cache-log: `<RFC3339> <ip:port> <domain> UP=<n> DOWN=<n>`
   - `client_resolvers.simple`: `<ip>` or `<ip>:<port>`
6. Migrate `config.json` schema (`dnsttConfig` → `stormdnsConfig`) with backward-compat warning.
7. Update artifacts:
   - `README.md` — replace DNSTT-stage prose, update screenshot caption, update config example, update Quick Guide steps 9–13, update Shortcuts section, update Notes section. Same for `README_FA.MD`.
   - `ui.go` — bump `uiVersionLabel` to `v0.8.0` (next major).
   - Top-level README adds a "Third-party code" section pointing at `third_party/stormdns/LICENSE`.

### Out of scope

- Renaming the project (stays "range-scout").
- IPv6 support.
- Adding new pre-filter probes.
- Changing the SlipNet 6-probe scoring.
- Implementing a full StormDNS runtime client (we only build the verifier slice).
- Auto-resync from upstream StormDNS.

### Success criteria

- `make build` produces a working binary with the StormDNS screen.
- A scan-then-verify run against an operator range (with a real StormDNS server reachable at the configured domain+key) returns a passing resolver list and a cache-log file directly usable by a real StormDNS client.
- Any IP in any IANA special-use range is never scanned, even if upstream prefix data includes it.
- All `*_test.go` continue to pass; new tests cover the bogon filter, the StormDNS verifier wrapper, and the new exporters.

## Architecture

### Module layout (after change)

```
range-scout/
├── main.go                          (unchanged)
├── ui.go                            (relabel DNSTT→StormDNS; drop SOCKS/E2E fields)
├── config.go                        (rename dnsttConfig→stormdnsConfig)
├── internal/
│   ├── operators/                   (unchanged)
│   ├── ripestat/                    (unchanged)
│   ├── prefixes/
│   │   ├── prefixes.go              (modified: WalkHosts applies bogon filter)
│   │   ├── bogons.go                (NEW)
│   │   └── bogons_test.go           (NEW)
│   ├── scanner/                     (mostly unchanged; SlipNet scoring kept)
│   ├── stormdns/                    (NEW — replaces internal/dnstt)
│   │   ├── verify.go
│   │   ├── verify_test.go
│   │   └── eligible.go
│   ├── stormdnsembed/               (NEW — replaces internal/dnsttembed)
│   │   ├── client.go
│   │   └── client_test.go
│   ├── export/                      (extended)
│   └── model/                       (Resolver fields swapped)
└── third_party/
    └── stormdns/                    (NEW — vendored)
```

Removed: `internal/dnstt/`, `internal/dnsttembed/`, `third_party/dnstt/`.

### Data flow

```
Load Targets ─▶ Prefix Walk + Bogon Filter ─▶ Scanner (UDP/TCP DNS + SlipNet 6-probe scoring)
                                                     │
                                                     ▼
                                       Score Threshold Gate
                                                     │
                                                     ▼
                              stormdns.Verify (per resolver):
                                stormdnsembed.ProbeMTU
                                  ├─ sendUploadMTUProbe   (vendored)
                                  └─ sendDownloadMTUProbe (vendored)
                                                     │
                                                     ▼
                              Export:
                                stormdns-passed.{txt,csv,json}
                                stormdns-cache-<label>.log     (StormDNS native)
                                stormdns-resolvers-<label>.simple (StormDNS native)
                                stormdns-failures-<label>.txt   (paired)
```

### Boundaries

- `internal/stormdnsembed` is the only package importing `third_party/stormdns/...`. Everyone else talks to `internal/stormdns.Verify`.
- `internal/stormdns` knows nothing about the embedded vendored package — it sees a clean `Verify(ip, domain, key, opts)` signature. Swapping vendor for a reimpl later requires no changes outside `stormdnsembed`.
- `internal/prefixes/bogons.go` is self-contained.

## Component Details

### `internal/prefixes/bogons.go` (NEW)

Static slice of IANA IPv4 special-use prefixes, parsed once into `[]netip.Prefix`:

| Prefix | Purpose |
|---|---|
| 0.0.0.0/8 | "this network" |
| 10.0.0.0/8 | RFC1918 private |
| 100.64.0.0/10 | CGNAT |
| 127.0.0.0/8 | loopback |
| 169.254.0.0/16 | link-local |
| 172.16.0.0/12 | RFC1918 private |
| 192.0.0.0/24 | IETF protocol assignments |
| 192.0.2.0/24 | TEST-NET-1 |
| 192.88.99.0/24 | 6to4 relay anycast (deprecated) |
| 192.168.0.0/16 | RFC1918 private |
| 198.18.0.0/15 | benchmarking |
| 198.51.100.0/24 | TEST-NET-2 |
| 203.0.113.0/24 | TEST-NET-3 |
| 224.0.0.0/4 | multicast |
| 240.0.0.0/4 | reserved (incl. 255.255.255.255) |

Exposes `IsBogon(addr netip.Addr) bool`.

### `internal/prefixes/prefixes.go` (MODIFIED)

- `WalkHosts` adds a bogon check inside the host loop. Filtered IPs increment a `skipped` counter exposed via a new return value, so the TUI can show "X bogons skipped".
- `Merge` drops any input prefix entirely contained in a bogon range and reports it via a new `droppedPrefixes []string` slice.

### `internal/stormdnsembed/client.go` (NEW)

Thin wrapper, ~150 lines. Exposes:

```go
type ProbeOptions struct {
    ResolverIP   string
    ResolverPort int
    Domain       string
    Key          string         // base64-encoded StormDNS encryption key
    QuerySize    int            // 0 = StormDNS default
    Retries      int            // 0 = StormDNS default (mtuTestRetries)
    Timeout      time.Duration
}

type ProbeResult struct {
    Passed       bool
    UpMTUBytes   int
    DownMTUBytes int
    Latency      time.Duration
    Err          error
}

func ProbeMTU(ctx context.Context, opts ProbeOptions) ProbeResult
```

Internally instantiates a minimal `*third_party/stormdns/pkg/client.Client` configured with: only this one resolver, no balancer goroutine, no health-loop goroutine, no SOCKS5 listener, no resolver_cache_log file. Calls `recheckResolverConnection` on it directly. The vendored `internal/client` package is renamed to `pkg/client` during vendoring (one-time fix recorded in SYNC.md).

### `internal/stormdns/verify.go` (NEW)

Replaces `internal/dnstt/dnstt.go`. Same orchestrator shape:

- `Test(ctx, resolvers, cfg, emit)` — orchestrator with a `runCandidateBatch` worker pool, progress events.
- `EligibleResolvers(resolvers, scoreThreshold)` — score-gate helper.

Per resolver, calls `stormdnsembed.ProbeMTU` and writes results back into `model.Resolver`. The `Test Nearby IPs` /24 fan-out logic is reused unchanged: each successful original resolver triggers one extra StormDNS-probe pass over the rest of its `/24` (excluding bogon IPs and IPs already in the result set). Nearby-discovered passes do not expand again. `EligibleResolvers(resolvers, scoreThreshold)` lives in `internal/stormdns/eligible.go`.

### `internal/model/model.go` (MODIFIED)

`Resolver` struct:

- Drop: `DNSTTPubkey`, `E2EURL`, `E2EStatus`, `SOCKSAuth`.
- Add: `UpMTUBytes int`, `DownMTUBytes int`, `StormDNSPassed bool`, `StormDNSLatencyMS int64`.
- Rename: `DNSTTPassed` → `StormDNSPassed`, `DNSTTLatencyMS` → `StormDNSLatencyMS`.

### `internal/export/export.go` (MODIFIED)

Add:

- `WriteStormDNSCacheLog(path string, resolvers []model.Resolver, domain string)` — emits `<RFC3339> <ip:port> <domain> UP=<n> DOWN=<n>` per passed resolver.
- `WriteStormDNSResolversSimple(path string, resolvers []model.Resolver)` — emits `<ip>` (or `<ip>:<port>` when port ≠ 53) per passed resolver.

Filenames follow existing range-scout pattern (`<stage>-<status>-<label>.<ext>`):

- `stormdns-scan-success-<label>.{txt,csv,json}` — passed resolvers in existing exporters
- `stormdns-scan-failures-<label>.txt` — checked-but-failed resolvers (paired with passed file)
- `stormdns-cache-<label>.log` — StormDNS cache-log format
- `stormdns-resolvers-<label>.simple` — StormDNS `client_resolvers.simple` format

### `config.go` (MODIFIED)

`dnsttConfig` → `stormdnsConfig`.

- New keys: `domain`, `key`, `timeoutMS`, `querySize`, `scoreThreshold`, `mtuRetries`, `testNearbyIPs`.
- Removed: `pubkey`, `e2eTimeoutS`, `e2eURL`, `socksUsername`, `socksPassword`.
- Loader keeps backward compat: legacy `dnsttConfig` block migrates `domain` over and warns about the rest being ignored.

### `ui.go` (MODIFIED)

DNSTT screen → StormDNS screen:

- `DNSTT Pubkey` → `StormDNS Key`
- `DNSTT Domain` → `StormDNS Domain`
- Kept (relabeled if needed): `Query Size`, `Score Threshold`, `Test Nearby IPs`.
- Removed: `E2E URL`, `SOCKS Username`, `SOCKS Password`.
- `Start DNSTT` button → `Start StormDNS`.
- `t` shortcut keeps key, label changes.
- Status messages, progress strings, `uiVersionLabel` updated.

## Vendoring & Sync Strategy

### Initial vendor

1. Snapshot upstream at a known commit:
   ```
   git -C /tmp clone https://github.com/nullroute1970/StormDNS
   cd /tmp/StormDNS && git rev-parse HEAD  # capture the commit hash
   ```

2. Copy source tree into `third_party/stormdns/` with these one-time patches:
   - `internal/client/` → `pkg/client/` (so range-scout can import it across modules).
   - `third_party/stormdns/go.mod` module path: `module stormdns-go` → `module range-scout/third_party/stormdns`.
   - `third_party/stormdns/go.mod` Go directive: leave at upstream `go 1.26.3` if range-scout's toolchain supports it; otherwise pin to range-scout's current `go 1.24.1` and verify the vendored code still builds (no Go 1.25/1.26-only stdlib usage).
   - Rewrite imports of `stormdns-go/...` to `range-scout/third_party/stormdns/...` (with `internal/client` → `pkg/client`).
   - Drop server-side packages (`cmd/server/...`, `internal/server/...`, install scripts, server configs).

3. Preserve upstream `LICENSE` / `COPYING` verbatim. Move upstream README to `third_party/stormdns/UPSTREAM_README.md` for reference.

### `SYNC.md` template

```
# third_party/stormdns sync record

Upstream:    https://github.com/nullroute1970/StormDNS
Commit:      <40-char SHA>
Sync date:   YYYY-MM-DD
Synced by:   <name>

## Applied patches (re-apply on every re-sync)

1. Rename `internal/client/` → `pkg/client/`
2. Rewrite go.mod module path to `range-scout/third_party/stormdns`
3. Rewrite imports: `stormdns-go/...` →
   `range-scout/third_party/stormdns/...` (internal/client → pkg/client)
4. Drop server-side packages: <list>

## Re-sync procedure

(short script or manual steps to redo the above on a newer upstream commit)
```

### Build integration

- Top-level `go.mod` declares:
  ```
  require range-scout/third_party/stormdns v0.0.0-local
  replace range-scout/third_party/stormdns => ./third_party/stormdns
  ```
  Same trick range-scout already uses for `third_party/dnstt`.
- `make build`, `make build-all`, `make release`, `make release-windows` work with no extra flags.

### Re-sync policy

- Manual and explicit. Driven by a security fix or protocol change in StormDNS, not on every upstream commit.
- Each re-sync produces one PR titled `chore: sync third_party/stormdns to <short-sha>` updating SYNC.md + the source tree.
- `internal/stormdnsembed/sync_check_test.go` reads SYNC.md and fails loudly if the recorded commit hash is missing or malformed.

### License compliance

StormDNS is MIT-licensed. The `LICENSE` / `COPYING` file is preserved verbatim. Range-scout's top-level README adds a "Third-party code" section pointing at `third_party/stormdns/`.

## Testing

### Unit tests (no network)

- `internal/prefixes/bogons_test.go` — table tests: known bogon IPs return `true`, public IPs return `false`, every IANA range boundary tested at edges.
- `internal/prefixes/prefixes_test.go` — extended: `WalkHosts` skips bogon hosts; `Merge` drops a fully-bogon input prefix.
- `internal/stormdnsembed/client_test.go` — fake DNS server in-process plus a stub StormDNS server speaking the wire protocol. Verifies `ProbeMTU` returns `Passed=true` with non-zero MTU values; covers timeout, wrong key, no reply, malformed reply.
- `internal/stormdns/verify_test.go` — orchestration table tests: empty input, all-pass, all-fail, mixed, batch concurrency, context cancellation. `stormdnsembed.ProbeMTU` is interface-injected so this file uses fakes.
- `internal/export/export_test.go` — extended: cache-log writer produces the exact `<RFC3339> <ip:port> <domain> UP=<n> DOWN=<n>` line; `client_resolvers.simple` writer omits port `53` and includes non-default ports.
- `config_test.go` — extended: legacy `dnsttConfig` migrates correctly; new `stormdnsConfig` round-trips through save/load.

### Integration test (opt-in, network)

- `internal/stormdnsembed/integration_test.go` behind a `// +build integration` tag — runs `ProbeMTU` against a real StormDNS server at a configured domain+key.
- Skipped in `make build` and default `go test ./...`.
- Opt-in via `make integration-test STORMDNS_DOMAIN=... STORMDNS_KEY=...`.

### TUI tests

- `ui_test.go` — extended: StormDNS screen renders renamed fields, dropped fields don't appear, status text uses "StormDNS".

### Vendor sanity test

- `internal/stormdnsembed/sync_check_test.go` — parses `third_party/stormdns/SYNC.md`, fails if commit hash is missing/malformed.

## Error Handling

### Per-resolver in `ProbeMTU`

- **Timeout / connection refused** → `Passed=false`, `Err=ErrProbeTimeout` (typed). Surfaced as one row in failures export with reason "timeout".
- **Wrong key (server replies but decryption fails)** → `Passed=false`, `Err=ErrKeyMismatch`. Treated as user error: after **5 consecutive** `ErrKeyMismatch` results across different resolvers, `verify.Test` aborts with a top-level error "key mismatch — all probes failing decryption; check StormDNS Key". The threshold is a constant (`keyMismatchAbortThreshold = 5`) in `internal/stormdns/verify.go`, not configurable.
- **Malformed reply** → `Passed=false`, `Err=ErrProtocolError`. Counted but not aborting.
- **Context canceled** → `Err=ctx.Err()`, propagated up cleanly.

### Top-level in `verify.Test`

- Empty resolver list → return immediately with empty result, no error.
- StormDNS Domain empty or invalid → fail validation up front.
- StormDNS Key empty or non-base64 → fail validation up front.
- Vendored client init failure → wrapped error pointing at `third_party/stormdns/SYNC.md`.

### Bogon filter

- Quiet by default — skipped IPs increment a counter; TUI scan log shows one summary line: `skipped <N> bogon hosts (<N> distinct prefixes excluded)`.
- A fully-bogon input prefix (e.g. user pastes `10.0.0.0/8`) is **rejected with a visible UI warning**, not silently dropped.

### Configuration migration

- Legacy `dnsttConfig` blocks load with a `WARN`: `legacy dnsttConfig block detected; "domain" migrated to stormdnsConfig.domain; other DNSTT-only fields ignored`. Doesn't crash old configs.

## Rollout

### Commit sequence

Single feature branch `feat/stormdns-verifier`. Each commit keeps `make build` green and `go test ./...` passing.

1. `chore: vendor StormDNS source under third_party/stormdns` — pure source drop + SYNC.md, no callers.
2. `feat(prefixes): add IANA bogon filter to WalkHosts` — independent of StormDNS work.
3. `feat(stormdnsembed): add ProbeMTU wrapper` — uses vendored package, no UI yet.
4. `feat(stormdns): add Verify orchestrator` — replaces internal/dnstt logic.
5. `feat(model): rename DNSTT fields → StormDNS fields`.
6. `feat(export): add stormdns cache-log + resolvers.simple writers`.
7. `feat(ui): replace DNSTT screen with StormDNS screen` — visible end-to-end.
8. `chore: remove third_party/dnstt + internal/dnstt + internal/dnsttembed` — deletions only.
9. `docs: update README + config schema`.

### Versioning

- Bump `uiVersionLabel` to next major (breaking change).
- Tag `v0.8.0-rc1` first, then `v0.8.0`.
- Update README's "version shown in header" example.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Vendored StormDNS imports break after path rewrite | Medium | Build broken | Vendor-and-build is commit #1; SYNC.md re-sync procedure verified day one |
| `internal/client` rename breaks unexported peer access | Medium | Build broken | One-line patch recorded in SYNC.md |
| StormDNS protocol changes upstream | Low | Verifier false-negatives | Manual re-sync; sync_check_test enforces commits |
| Bogon filter excludes a legitimate operator prefix | Very low | Real range skipped | IANA list well-defined; boundary tests; pasted bogon prefix gets visible warning |
| User loads old config with `dnsttConfig` | High | None | Migration in loader; legacy keys logged + ignored |
| Embedded Client spawns balancer/health goroutines | Medium | Resource leak | Wrapper sets minimal config; integration test verifies no extra goroutines after `ProbeMTU` returns |
| StormDNS server requires session before MTU probe | Low | All probes fail | Verified `recheckResolverConnection` is stateless in upstream; integration test catches regressions |

## Deferred (not in this change)

- IPv6 support.
- Auto re-sync from upstream.
- Cross-run historical results.
- Standalone `range-scout verify <ip>` CLI mode.
