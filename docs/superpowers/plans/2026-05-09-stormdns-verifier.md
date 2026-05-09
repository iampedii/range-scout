# range-scout StormDNS Verifier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace range-scout's DNSTT verifier with a StormDNS-protocol verifier (encrypted upload+download MTU probe per resolver) and add an IANA IPv4 special-use bogon filter at prefix expansion.

**Architecture:** Vendor StormDNS source under `third_party/stormdns/` (mirroring the existing `third_party/dnstt/` pattern), expose a thin `ProbeMTU` wrapper from `internal/stormdnsembed/`, build the orchestrator in `internal/stormdns/Verify`. Add `internal/prefixes/bogons.go` and apply bogon filtering in `WalkHosts` and `Merge`.

**Tech Stack:** Go 1.24+, standard `testing` package, `net/netip`, `github.com/miekg/dns` (already a transitive dep), TOML/JSON via existing range-scout config code.

**Spec:** `docs/superpowers/specs/2026-05-09-range-scout-stormdns-verifier-design.md`

**Branch:** `feat/stormdns-verifier`

---

## File Structure

### Created

| Path | Responsibility |
|---|---|
| `third_party/stormdns/` | Vendored StormDNS source (full subtree minus server code) |
| `third_party/stormdns/SYNC.md` | Records upstream commit + applied patches |
| `internal/prefixes/bogons.go` | Static IANA IPv4 special-use prefix list + `IsBogon` |
| `internal/prefixes/bogons_test.go` | Boundary + table tests for bogon detection |
| `internal/stormdnsembed/client.go` | `ProbeMTU(ctx, opts)` wrapper around vendored client |
| `internal/stormdnsembed/client_test.go` | Wrapper unit tests with stub StormDNS server |
| `internal/stormdnsembed/sync_check_test.go` | Validates SYNC.md commit hash format |
| `internal/stormdnsembed/integration_test.go` | Build-tagged opt-in real-server test |
| `internal/stormdns/verify.go` | `Verify` orchestrator, batch worker pool, progress events |
| `internal/stormdns/verify_test.go` | Orchestration tests (interface-injected fakes) |
| `internal/stormdns/eligible.go` | `EligibleResolvers(resolvers, scoreThreshold)` helper |
| `internal/stormdns/eligible_test.go` | Score-gate tests |

### Modified

| Path | What changes |
|---|---|
| `go.mod` | Add `replace`/`require` for `range-scout/third_party/stormdns` |
| `internal/prefixes/prefixes.go` | `WalkHosts` skips bogons; `Merge` reports dropped bogon prefixes |
| `internal/prefixes/prefixes_test.go` | Extended for bogon behavior |
| `internal/model/model.go` | `Resolver` field renames + new MTU fields |
| `internal/export/export.go` | Add `WriteStormDNSCacheLog`, `WriteStormDNSResolversSimple` |
| `internal/export/export_test.go` | Tests for new writers |
| `internal/scanner/scanner.go` | Update field references after model rename |
| `config.go` | `dnsttConfig` → `stormdnsConfig` schema + legacy migration |
| `config_test.go` | Migration + round-trip tests |
| `ui.go` | Replace DNSTT screen, bump `uiVersionLabel` |
| `ui_test.go` | Updated screen rendering tests |
| `Makefile` | Add `integration-test` target |
| `README.md` | Replace DNSTT prose, update config example, add Third-party section |
| `README_FA.MD` | Same updates in Farsi |

### Deleted

- `internal/dnstt/` (entire dir)
- `internal/dnsttembed/` (entire dir)
- `third_party/dnstt/` (entire dir)

---

## Task 1: Vendor StormDNS source under `third_party/stormdns/`

**Files:**
- Create: `third_party/stormdns/` (whole subtree from upstream)
- Create: `third_party/stormdns/SYNC.md`
- Modify: `go.mod`

- [ ] **Step 1.1: Snapshot upstream**

```bash
cd /tmp
rm -rf StormDNS-snapshot
git clone https://github.com/nullroute1970/StormDNS StormDNS-snapshot
cd StormDNS-snapshot
git rev-parse HEAD > /tmp/stormdns-pinned-sha.txt
cat /tmp/stormdns-pinned-sha.txt
```

Expected: prints a 40-char SHA. Save it; you'll write it into SYNC.md.

- [ ] **Step 1.2: Copy source tree into the repo**

```bash
cd /Users/rasoul/Downloads/Scaner/range-scout
mkdir -p third_party/stormdns
rsync -a --exclude '.git' --exclude '.github' --exclude 'cmd/server' --exclude 'internal/server' \
      --exclude 'server_*.sh' --exclude 'server_config*' --exclude 'build.py' --exclude 'scripts' \
      --exclude 'docs' --exclude 'assets' --exclude 'README*.MD' --exclude 'AGENTS.md' \
      /tmp/StormDNS-snapshot/ third_party/stormdns/
```

If `rsync` is unavailable, use `cp -R` and then `rm -rf` the excluded dirs/files manually.

- [ ] **Step 1.3: Rename `internal/client/` → `pkg/client/`**

```bash
cd /Users/rasoul/Downloads/Scaner/range-scout/third_party/stormdns
mkdir -p pkg
git mv internal/client pkg/client 2>/dev/null || mv internal/client pkg/client
```

- [ ] **Step 1.4: Rewrite module path in vendored go.mod**

Edit `third_party/stormdns/go.mod`:

Change:
```
module stormdns-go
```

To:
```
module range-scout/third_party/stormdns
```

Leave the `go 1.26.3` directive as-is for now; we'll verify build in step 1.7.

- [ ] **Step 1.5: Rewrite all imports inside vendored sources**

Two substitutions, applied across all `*.go` files under `third_party/stormdns/`:

1. `stormdns-go/internal/client` → `range-scout/third_party/stormdns/pkg/client`
2. `stormdns-go/` → `range-scout/third_party/stormdns/` (catches all other internal subpackages)

Order matters — do (1) first, then (2).

```bash
cd /Users/rasoul/Downloads/Scaner/range-scout/third_party/stormdns
find . -name '*.go' -type f -exec sed -i '' \
  -e 's|stormdns-go/internal/client|range-scout/third_party/stormdns/pkg/client|g' {} +
find . -name '*.go' -type f -exec sed -i '' \
  -e 's|stormdns-go/|range-scout/third_party/stormdns/|g' {} +
```

(On Linux, drop the empty `''` after `-i`.)

- [ ] **Step 1.6: Drop server-side cmd packages if any remain**

```bash
cd /Users/rasoul/Downloads/Scaner/range-scout/third_party/stormdns
find . -type d -name 'server' -prune -exec rm -rf {} +
ls cmd 2>/dev/null && find cmd -type d -mindepth 1 -maxdepth 1 ! -name 'client' -exec rm -rf {} +
```

- [ ] **Step 1.7: Wire vendored module into the top-level go.mod**

Edit `/Users/rasoul/Downloads/Scaner/range-scout/go.mod`. Append at the bottom (after existing `require` block):

```
require range-scout/third_party/stormdns v0.0.0-local

replace range-scout/third_party/stormdns => ./third_party/stormdns
```

- [ ] **Step 1.8: Verify the vendored package builds**

```bash
cd /Users/rasoul/Downloads/Scaner/range-scout
go build ./third_party/stormdns/pkg/client/
```

Expected: no errors. If you see "go: go.mod requires go >= 1.26.3", edit `third_party/stormdns/go.mod` and lower the directive to `go 1.24.1`, then re-run. If new compile errors appear at that lower version, inspect the failing line; if it's a 1.25/1.26-only stdlib feature, raise it back and bump range-scout's top-level go.mod / Makefile go directive too.

- [ ] **Step 1.9: Verify the rest of range-scout still builds**

```bash
cd /Users/rasoul/Downloads/Scaner/range-scout
go build ./...
go test ./... 2>&1 | tail -20
```

Expected: build succeeds, existing tests still pass (DNSTT tests still pass — we haven't removed them yet).

- [ ] **Step 1.10: Write `third_party/stormdns/SYNC.md`**

Create `third_party/stormdns/SYNC.md`:

```markdown
# third_party/stormdns sync record

Upstream:    https://github.com/nullroute1970/StormDNS
Commit:      <PASTE-40-CHAR-SHA-FROM-/tmp/stormdns-pinned-sha.txt>
Sync date:   2026-05-09
Synced by:   rasoultaji

## Applied patches (must be re-applied on every re-sync)

1. Renamed `internal/client/` → `pkg/client/` (so external modules can import it).
2. Rewrote go.mod module path: `module stormdns-go` → `module range-scout/third_party/stormdns`.
3. Rewrote all imports:
     - `stormdns-go/internal/client`  →  `range-scout/third_party/stormdns/pkg/client`
     - `stormdns-go/`                 →  `range-scout/third_party/stormdns/`
4. Dropped server-side packages: `cmd/server`, `internal/server`, `server_*.sh`,
   `server_config*`, `build.py`, `scripts/`, `docs/`, `assets/`, upstream READMEs, `AGENTS.md`.

## Re-sync procedure

1. Snapshot upstream HEAD into `/tmp/StormDNS-snapshot`.
2. `git rev-parse HEAD` and update Commit + Sync date above.
3. `rsync` the new tree over `third_party/stormdns/` (same excludes as Task 1.2).
4. Re-apply patches 1–3 above (run the sed scripts from Task 1.5).
5. `go build ./third_party/stormdns/pkg/client/ && go build ./... && go test ./...`.
6. Commit as `chore: sync third_party/stormdns to <short-sha>`.
```

Replace `<PASTE-40-CHAR-SHA-FROM-/tmp/stormdns-pinned-sha.txt>` with the actual SHA from Step 1.1.

- [ ] **Step 1.11: Commit the vendor**

```bash
cd /Users/rasoul/Downloads/Scaner/range-scout
git add third_party/stormdns go.mod go.sum
git commit -m "chore: vendor StormDNS source under third_party/stormdns

Vendored from github.com/nullroute1970/StormDNS at <short-sha>.
Patches recorded in third_party/stormdns/SYNC.md.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Add IANA IPv4 bogon filter

**Files:**
- Create: `internal/prefixes/bogons.go`
- Create: `internal/prefixes/bogons_test.go`
- Modify: `internal/prefixes/prefixes.go`
- Modify: `internal/prefixes/prefixes_test.go`

- [ ] **Step 2.1: Write the failing bogon detection test**

Create `internal/prefixes/bogons_test.go`:

```go
package prefixes

import (
	"net/netip"
	"testing"
)

func TestIsBogon(t *testing.T) {
	cases := []struct {
		name   string
		ip     string
		expect bool
	}{
		// All 16 IANA special-use ranges, tested at first + last + middle:
		{"this-network-first", "0.0.0.0", true},
		{"this-network-mid", "0.123.45.6", true},
		{"this-network-last", "0.255.255.255", true},
		{"public-1.1.1.1", "1.1.1.1", false},
		{"rfc1918-10-first", "10.0.0.0", true},
		{"rfc1918-10-last", "10.255.255.255", true},
		{"public-11.0.0.1", "11.0.0.1", false},
		{"cgnat-first", "100.64.0.0", true},
		{"cgnat-last", "100.127.255.255", true},
		{"public-100.128.0.1", "100.128.0.1", false},
		{"loopback-first", "127.0.0.0", true},
		{"loopback-last", "127.255.255.255", true},
		{"public-128.0.0.1", "128.0.0.1", false},
		{"link-local-first", "169.254.0.0", true},
		{"link-local-last", "169.254.255.255", true},
		{"rfc1918-172-first", "172.16.0.0", true},
		{"rfc1918-172-last", "172.31.255.255", true},
		{"public-172.32.0.1", "172.32.0.1", false},
		{"public-172.15.255.255", "172.15.255.255", false},
		{"ietf-protocol", "192.0.0.5", true},
		{"test-net-1", "192.0.2.50", true},
		{"6to4-relay", "192.88.99.1", true},
		{"rfc1918-192-first", "192.168.0.0", true},
		{"rfc1918-192-last", "192.168.255.255", true},
		{"benchmarking-first", "198.18.0.0", true},
		{"benchmarking-last", "198.19.255.255", true},
		{"test-net-2", "198.51.100.10", true},
		{"test-net-3", "203.0.113.10", true},
		{"public-198.20.0.1", "198.20.0.1", false},
		{"multicast-first", "224.0.0.0", true},
		{"multicast-last", "239.255.255.255", true},
		{"reserved-first", "240.0.0.0", true},
		{"reserved-last", "255.255.255.254", true},
		{"broadcast", "255.255.255.255", true},
		{"public-google-dns", "8.8.8.8", false},
		{"public-cloudflare-dns", "1.1.1.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsBogon(netip.MustParseAddr(tc.ip))
			if got != tc.expect {
				t.Fatalf("IsBogon(%s) = %v, want %v", tc.ip, got, tc.expect)
			}
		})
	}
}
```

- [ ] **Step 2.2: Run the test to verify it fails**

```bash
cd /Users/rasoul/Downloads/Scaner/range-scout
go test ./internal/prefixes/ -run TestIsBogon -v
```

Expected: FAIL — `undefined: IsBogon`.

- [ ] **Step 2.3: Implement `bogons.go`**

Create `internal/prefixes/bogons.go`:

```go
package prefixes

import "net/netip"

var bogonPrefixes = func() []netip.Prefix {
	raw := []string{
		"0.0.0.0/8",         // "this network"
		"10.0.0.0/8",        // RFC1918
		"100.64.0.0/10",     // CGNAT
		"127.0.0.0/8",       // loopback
		"169.254.0.0/16",    // link-local
		"172.16.0.0/12",     // RFC1918
		"192.0.0.0/24",      // IETF protocol assignments
		"192.0.2.0/24",      // TEST-NET-1
		"192.88.99.0/24",    // 6to4 relay anycast (deprecated)
		"192.168.0.0/16",    // RFC1918
		"198.18.0.0/15",     // benchmarking
		"198.51.100.0/24",   // TEST-NET-2
		"203.0.113.0/24",    // TEST-NET-3
		"224.0.0.0/4",       // multicast
		"240.0.0.0/4",       // reserved (incl. 255.255.255.255)
	}
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// IsBogon returns true if addr is in any IANA IPv4 special-use range.
// Returns false for non-IPv4 addresses.
func IsBogon(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	for _, p := range bogonPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// PrefixIsFullyBogon reports whether every host in p is a bogon (i.e. p is
// contained in some bogon range). Used by Merge to drop user-supplied
// fully-private prefixes.
func PrefixIsFullyBogon(p netip.Prefix) bool {
	if !p.Addr().Is4() {
		return false
	}
	for _, b := range bogonPrefixes {
		if b.Bits() <= p.Bits() && b.Contains(p.Addr()) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2.4: Run the bogon test to verify it passes**

```bash
go test ./internal/prefixes/ -run TestIsBogon -v
```

Expected: PASS for all 36 sub-tests.

- [ ] **Step 2.5: Write the failing test for `WalkHosts` skipping bogons**

Append to `internal/prefixes/prefixes_test.go`:

```go
func TestWalkHostsSkipsBogons(t *testing.T) {
	entries := []model.PrefixEntry{
		{Prefix: "10.0.0.0/30"},  // entirely bogon
		{Prefix: "8.8.8.0/30"},   // public
	}
	var walked []string
	skipped, err := WalkHosts(entries, 0, func(addr netip.Addr, prefix string) bool {
		walked = append(walked, addr.String())
		return true
	})
	if err != nil {
		t.Fatalf("WalkHosts err: %v", err)
	}
	if skipped == 0 {
		t.Fatalf("expected skipped > 0 for 10.0.0.0/30, got 0")
	}
	for _, ip := range walked {
		if ip == "10.0.0.1" || ip == "10.0.0.2" {
			t.Fatalf("WalkHosts yielded a bogon: %s", ip)
		}
	}
	// 8.8.8.0/30 has 2 usable hosts (.1, .2). Confirm both walked.
	got := map[string]bool{}
	for _, ip := range walked {
		got[ip] = true
	}
	if !got["8.8.8.1"] || !got["8.8.8.2"] {
		t.Fatalf("expected 8.8.8.1 and 8.8.8.2 to be walked, got %v", walked)
	}
}
```

Note: the test references a new return value `skipped uint64`. The existing `WalkHosts` returns `(uint64, error)` — those existing callers need updating too. Plan: rename the existing first return from `emitted` to `walked`, add a new second return `skipped`, keep `error` as third. We'll update the signature in step 2.6.

- [ ] **Step 2.6: Modify `WalkHosts` signature and add bogon skip**

Edit `internal/prefixes/prefixes.go`. Replace the `WalkHosts` function (currently at lines 91-120):

```go
func WalkHosts(entries []model.PrefixEntry, limit uint64, yield func(addr netip.Addr, prefix string) bool) (uint64, error) {
	walked, _, err := WalkHostsCounted(entries, limit, yield)
	return walked, err
}

// WalkHostsCounted is like WalkHosts but additionally returns the number of
// host IPs skipped because they were in an IANA bogon range.
func WalkHostsCounted(entries []model.PrefixEntry, limit uint64, yield func(addr netip.Addr, prefix string) bool) (uint64, uint64, error) {
	var emitted, skipped uint64

	for _, entry := range entries {
		parsed, err := netip.ParsePrefix(entry.Prefix)
		if err != nil {
			return emitted, skipped, fmt.Errorf("parse prefix %q: %w", entry.Prefix, err)
		}
		if !parsed.Addr().Is4() {
			continue
		}

		start, end, ok := hostBounds(parsed)
		if !ok {
			continue
		}

		for current := start; current <= end; current++ {
			if limit > 0 && emitted >= limit {
				return emitted, skipped, nil
			}
			addr := uint64ToIPv4(current)
			if IsBogon(addr) {
				skipped++
				continue
			}
			if !yield(addr, entry.Prefix) {
				return emitted, skipped, nil
			}
			emitted++
		}
	}

	return emitted, skipped, nil
}
```

The signature trick: existing callers using `WalkHosts(...) (uint64, error)` keep working unchanged (it now delegates to `WalkHostsCounted`). New callers wanting the skip count call `WalkHostsCounted` directly. The test uses the *test signature* — adjust the test to use `WalkHostsCounted`:

In `TestWalkHostsSkipsBogons`, change:
```go
skipped, err := WalkHosts(entries, 0, func(...) bool { ... })
```
to:
```go
_, skipped, err := WalkHostsCounted(entries, 0, func(...) bool { ... })
```

- [ ] **Step 2.7: Run prefixes tests**

```bash
go test ./internal/prefixes/ -v
```

Expected: all existing tests still pass + new `TestWalkHostsSkipsBogons` passes.

- [ ] **Step 2.8: Add `Merge` reporting of dropped fully-bogon prefixes**

Edit `internal/prefixes/prefixes.go`. Replace the `Merge` function signature and logic to also return `[]string` for dropped bogon prefixes. Existing callers:

```bash
grep -rn "prefixes\.Merge(" /Users/rasoul/Downloads/Scaner/range-scout --include='*.go'
```

Note their locations — you'll fix them in step 2.10.

Replace the function:

```go
// Merge dedupes prefixes by string, attaches all source ASNs, and returns the
// merged entries sorted by address+bits. Fully-bogon prefixes (entirely inside
// an IANA special-use range) are dropped from the result and returned in
// droppedBogons so the UI can surface a warning.
func Merge(records []SourcePrefix) ([]model.PrefixEntry, uint64, uint64, []string, error) {
	byPrefix := make(map[string]map[string]struct{})
	droppedBogons := []string{}
	seenDropped := map[string]struct{}{}

	for _, record := range records {
		prefix := strings.TrimSpace(record.Prefix)
		if prefix == "" {
			continue
		}

		parsed, err := netip.ParsePrefix(prefix)
		if err != nil {
			return nil, 0, 0, nil, fmt.Errorf("parse prefix %q: %w", prefix, err)
		}
		if !parsed.Addr().Is4() {
			continue
		}

		if PrefixIsFullyBogon(parsed) {
			if _, seen := seenDropped[prefix]; !seen {
				droppedBogons = append(droppedBogons, prefix)
				seenDropped[prefix] = struct{}{}
			}
			continue
		}

		if _, ok := byPrefix[prefix]; !ok {
			byPrefix[prefix] = make(map[string]struct{})
		}
		byPrefix[prefix][record.ASN] = struct{}{}
	}

	entries := make([]model.PrefixEntry, 0, len(byPrefix))
	var totalAddresses uint64
	var totalScanHosts uint64

	for prefix, asnSet := range byPrefix {
		parsed, _ := netip.ParsePrefix(prefix)
		addressCount := addressCount(parsed)
		scanCount := usableHostCount(parsed)
		asns := make([]string, 0, len(asnSet))
		for asn := range asnSet {
			asns = append(asns, asn)
		}
		sort.Strings(asns)

		entries = append(entries, model.PrefixEntry{
			Prefix:         prefix,
			SourceASNs:     asns,
			TotalAddresses: addressCount,
			ScanHosts:      scanCount,
		})
		totalAddresses += addressCount
		totalScanHosts += scanCount
	}

	sort.Slice(entries, func(i, j int) bool {
		left, _ := netip.ParsePrefix(entries[i].Prefix)
		right, _ := netip.ParsePrefix(entries[j].Prefix)
		leftAddr := ipv4AsUint64(left.Masked().Addr())
		rightAddr := ipv4AsUint64(right.Masked().Addr())
		if leftAddr != rightAddr {
			return leftAddr < rightAddr
		}
		return left.Bits() < right.Bits()
	})

	return entries, totalAddresses, totalScanHosts, droppedBogons, nil
}
```

- [ ] **Step 2.9: Add the merge-drops-bogon test**

Append to `internal/prefixes/prefixes_test.go`:

```go
func TestMergeDropsFullyBogonPrefixes(t *testing.T) {
	records := []SourcePrefix{
		{ASN: "1", Prefix: "10.0.0.0/24"},      // fully bogon → dropped
		{ASN: "2", Prefix: "192.168.1.0/24"},   // fully bogon → dropped
		{ASN: "3", Prefix: "8.8.8.0/24"},       // public → kept
	}
	entries, _, _, dropped, err := Merge(records)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(entries) != 1 || entries[0].Prefix != "8.8.8.0/24" {
		t.Fatalf("expected only 8.8.8.0/24 to remain, got %+v", entries)
	}
	if len(dropped) != 2 {
		t.Fatalf("expected 2 dropped bogon prefixes, got %d: %v", len(dropped), dropped)
	}
}
```

- [ ] **Step 2.10: Update `Merge` callers for the new signature**

Find every call site:

```bash
grep -rn "prefixes\.Merge(" /Users/rasoul/Downloads/Scaner/range-scout --include='*.go'
```

Each call returning `(entries, addrs, hosts, err)` becomes `(entries, addrs, hosts, droppedBogons, err)`. For now, ignore the new return at non-UI sites by assigning it to `_`. The UI-side wiring (showing the warning) goes in Task 7.

Example fix:

```go
// before:
entries, addrs, hosts, err := prefixes.Merge(records)
// after:
entries, addrs, hosts, _, err := prefixes.Merge(records)
```

- [ ] **Step 2.11: Verify everything still builds and tests pass**

```bash
go build ./...
go test ./...
```

Expected: all green. If any caller you missed has a signature mismatch, fix it now.

- [ ] **Step 2.12: Commit**

```bash
git add internal/prefixes/ $(grep -rl "prefixes\.Merge(" --include='*.go' .)
git commit -m "feat(prefixes): add IANA IPv4 bogon filter

WalkHosts skips host IPs in IANA special-use ranges; Merge drops
fully-bogon input prefixes and reports them via a new return value
so the UI can surface a warning. Adds IsBogon and PrefixIsFullyBogon
helpers covering the 16 IANA IPv4 special-use prefixes.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Add `internal/stormdnsembed/ProbeMTU` wrapper

**Files:**
- Create: `internal/stormdnsembed/client.go`
- Create: `internal/stormdnsembed/client_test.go`
- Create: `internal/stormdnsembed/sync_check_test.go`

- [ ] **Step 3.1: Write the failing sync check test**

Create `internal/stormdnsembed/sync_check_test.go`:

```go
package stormdnsembed

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestSyncMDHasValidCommit fails if third_party/stormdns/SYNC.md is missing,
// or its "Commit:" line does not contain a 40-char hex SHA. Catches
// half-finished re-syncs.
func TestSyncMDHasValidCommit(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(root, "third_party/stormdns/SYNC.md"))
	if err != nil {
		t.Fatalf("read SYNC.md: %v", err)
	}
	re := regexp.MustCompile(`(?m)^Commit:\s*([0-9a-fA-F]{40})\s*$`)
	if !re.Match(body) {
		t.Fatalf("SYNC.md has no `Commit: <40-char SHA>` line:\n%s", body)
	}
}

// repoRoot walks upward from the current test working dir looking for go.mod.
func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			b, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
			if strings.HasPrefix(string(b), "module range-scout") {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
```

- [ ] **Step 3.2: Verify the sync test passes**

```bash
go test ./internal/stormdnsembed/ -run TestSyncMDHasValidCommit -v
```

Expected: PASS (SYNC.md was written in Task 1).

- [ ] **Step 3.3: Survey the vendored client API**

```bash
grep -n "^type Client struct\|^func NewClient\|^func.*Client.*Run\|sendUploadMTUProbe\|sendDownloadMTUProbe\|recheckResolverConnection" \
  /Users/rasoul/Downloads/Scaner/range-scout/third_party/stormdns/pkg/client/*.go | head -30
```

Note the names. The wrapper in step 3.5 will call `recheckResolverConnection` (or whichever exported equivalent exists). If `recheckResolverConnection` is unexported, you have two options:
- (a) Add an exported method `ProbeOnce(ctx, conn) bool` to `pkg/client/resolver_health.go` that just calls it. Patch must be recorded in SYNC.md "Applied patches".
- (b) Use `recheckConnectionFn` injection field already present in `Client` struct (it's set by tests in upstream).

Prefer (a): add a small exported method. Update SYNC.md to list this patch.

- [ ] **Step 3.4: Write the failing wrapper test**

Create `internal/stormdnsembed/client_test.go`:

```go
package stormdnsembed

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestProbeMTUValidatesInputs(t *testing.T) {
	cases := []struct {
		name string
		opts ProbeOptions
		want error
	}{
		{
			name: "empty domain",
			opts: ProbeOptions{ResolverIP: "1.1.1.1", ResolverPort: 53, Key: "AAAA"},
			want: ErrInvalidDomain,
		},
		{
			name: "empty key",
			opts: ProbeOptions{ResolverIP: "1.1.1.1", ResolverPort: 53, Domain: "t.example.com"},
			want: ErrInvalidKey,
		},
		{
			name: "non-base64 key",
			opts: ProbeOptions{ResolverIP: "1.1.1.1", ResolverPort: 53, Domain: "t.example.com", Key: "not!base64!"},
			want: ErrInvalidKey,
		},
		{
			name: "empty resolver IP",
			opts: ProbeOptions{ResolverPort: 53, Domain: "t.example.com", Key: "AAAA"},
			want: ErrInvalidResolver,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := ProbeMTU(context.Background(), tc.opts)
			if res.Passed {
				t.Fatalf("expected Passed=false")
			}
			if !errors.Is(res.Err, tc.want) {
				t.Fatalf("got err %v, want %v", res.Err, tc.want)
			}
		})
	}
}

func TestProbeMTUTimesOutOnUnreachable(t *testing.T) {
	// 192.0.2.x is TEST-NET-1 — guaranteed not to answer. Tight timeout.
	opts := ProbeOptions{
		ResolverIP:   "192.0.2.1",
		ResolverPort: 53,
		Domain:       "t.example.com",
		Key:          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 32 zero bytes b64
		Timeout:      300 * time.Millisecond,
	}
	res := ProbeMTU(context.Background(), opts)
	if res.Passed {
		t.Fatalf("expected Passed=false on unreachable")
	}
	if res.Err == nil {
		t.Fatalf("expected non-nil Err")
	}
}
```

- [ ] **Step 3.5: Implement `client.go`**

Create `internal/stormdnsembed/client.go`:

```go
package stormdnsembed

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	stormclient "range-scout/third_party/stormdns/pkg/client"
	stormconfig "range-scout/third_party/stormdns/internal/config"
)

// Errors returned in ProbeResult.Err. Inspect with errors.Is.
var (
	ErrInvalidDomain   = errors.New("stormdnsembed: domain is empty or invalid")
	ErrInvalidKey      = errors.New("stormdnsembed: key is empty or not base64")
	ErrInvalidResolver = errors.New("stormdnsembed: resolver IP is empty")
	ErrProbeTimeout    = errors.New("stormdnsembed: probe timed out")
	ErrKeyMismatch     = errors.New("stormdnsembed: server reply failed decryption (wrong key?)")
	ErrProtocolError   = errors.New("stormdnsembed: malformed StormDNS reply")
)

// ProbeOptions are the inputs to a single resolver verification.
type ProbeOptions struct {
	ResolverIP   string
	ResolverPort int
	Domain       string
	Key          string // base64-encoded StormDNS encryption key
	QuerySize    int    // 0 = StormDNS default
	Retries      int    // 0 = StormDNS default
	Timeout      time.Duration
}

// ProbeResult is what one ProbeMTU call returns.
type ProbeResult struct {
	Passed       bool
	UpMTUBytes   int
	DownMTUBytes int
	Latency      time.Duration
	Err          error
}

// ProbeMTU runs an upload+download MTU probe against one resolver, identical
// to what StormDNS's recheckResolverConnection does at runtime. Both probes
// must succeed for Passed=true. UpMTUBytes/DownMTUBytes are the negotiated
// MTU values when Passed=true.
func ProbeMTU(ctx context.Context, opts ProbeOptions) ProbeResult {
	if strings.TrimSpace(opts.Domain) == "" {
		return ProbeResult{Err: ErrInvalidDomain}
	}
	if strings.TrimSpace(opts.Key) == "" {
		return ProbeResult{Err: ErrInvalidKey}
	}
	if _, err := base64.StdEncoding.DecodeString(opts.Key); err != nil {
		return ProbeResult{Err: ErrInvalidKey}
	}
	if strings.TrimSpace(opts.ResolverIP) == "" {
		return ProbeResult{Err: ErrInvalidResolver}
	}

	port := opts.ResolverPort
	if port <= 0 {
		port = 53
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	cfg := stormconfig.ClientConfig{
		// Inspect pkg/client + internal/config to see exact field names.
		// The minimal set is: Domain, Key, single Resolver entry, MTU retries,
		// MTU test timeout. Disable: SOCKS5 server, balancer goroutine,
		// resolver health loop, resolver_cache_log, log emission.
	}
	_ = cfg // populate per upstream config struct

	// Construct a Client with only this one resolver, run a probe-only
	// recheck, capture upload/download MTU values, return.
	cl, err := stormclient.NewProbeOnlyClient(cfg, opts.ResolverIP, port, opts.Domain, opts.Key, opts.QuerySize, opts.Retries)
	if err != nil {
		return ProbeResult{Err: classifyErr(err)}
	}
	defer cl.Close()

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	ok := cl.ProbeOnce(probeCtx)
	elapsed := time.Since(start)

	if !ok {
		return ProbeResult{
			Passed:  false,
			Latency: elapsed,
			Err:     classifyErr(cl.LastProbeError()),
		}
	}

	up, down := cl.NegotiatedMTU()
	return ProbeResult{
		Passed:       true,
		UpMTUBytes:   up,
		DownMTUBytes: down,
		Latency:      elapsed,
	}
}

// classifyErr maps low-level errors from the vendored client into the
// typed errors this package exposes. Implementation depends on what the
// vendored client returns; map context.DeadlineExceeded → ErrProbeTimeout,
// any decryption error → ErrKeyMismatch, any wire-format error →
// ErrProtocolError, fall-through preserves the original.
func classifyErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrProbeTimeout
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "decrypt"), strings.Contains(msg, "auth tag"):
		return ErrKeyMismatch
	case strings.Contains(msg, "malformed"), strings.Contains(msg, "decode"):
		return ErrProtocolError
	}
	return err
}
```

The functions `NewProbeOnlyClient`, `ProbeOnce`, `LastProbeError`, `NegotiatedMTU`, and `Close` need to be added to `third_party/stormdns/pkg/client/`. They are thin wrappers around the existing internal `recheckResolverConnection` flow. Add them in step 3.6.

- [ ] **Step 3.6: Add the probe-only API to vendored client**

Create `third_party/stormdns/pkg/client/probe_api.go`:

```go
package client

import (
	"context"
	"sync"

	"range-scout/third_party/stormdns/internal/config"
)

// ProbeOnlyClient is a stripped Client used only for one-shot resolver
// verification. It does NOT start the balancer goroutine, the health loop,
// or the resolver_cache_log file. Intended for external verification tools
// (e.g. range-scout) that want StormDNS's own MTU-probe semantics.
type ProbeOnlyClient struct {
	c           *Client
	conn        *Connection
	mu          sync.Mutex
	lastErr     error
	upMTU       int
	downMTU     int
}

// NewProbeOnlyClient builds a minimal Client with a single resolver and the
// configured domain/key. It does not start any goroutines. Caller MUST call
// Close to release crypto state.
func NewProbeOnlyClient(cfg config.ClientConfig, resolverIP string, resolverPort int, domain, key string, querySize, retries int) (*ProbeOnlyClient, error) {
	// Populate cfg with the minimal required fields. Inspect upstream
	// internal/config/types.go for exact field names. Likely something like:
	//   cfg.Domain = domain
	//   cfg.Key    = key
	//   cfg.Resolvers = []config.ResolverAddress{{IP: resolverIP, Port: resolverPort}}
	//   cfg.MTUTestRetries = retries (if 0 leave default)
	//   cfg.QuerySize     = querySize (if 0 leave default)
	//   cfg.NoSOCKS5      = true   (or whatever flag disables it)
	//   cfg.NoCacheLog    = true
	//   cfg.NoBalancer    = true
	//   cfg.NoHealthLoop  = true

	c, err := NewClient(cfg) // upstream constructor — verify exact name
	if err != nil {
		return nil, err
	}

	if len(c.connections) != 1 {
		return nil, ErrConfigBadResolverCount
	}
	conn := &c.connections[0]

	return &ProbeOnlyClient{c: c, conn: conn}, nil
}

// ProbeOnce runs upload+download MTU probes against the single configured
// resolver. Returns true iff both probes pass.
func (p *ProbeOnlyClient) ProbeOnce(ctx context.Context) bool {
	ok := p.c.recheckResolverConnection(ctx, p.conn)
	if ok {
		p.mu.Lock()
		p.upMTU = p.c.syncedUploadMTU
		p.downMTU = p.c.syncedDownloadMTU
		p.mu.Unlock()
	} else {
		p.mu.Lock()
		p.lastErr = ctx.Err()
		p.mu.Unlock()
	}
	return ok
}

// NegotiatedMTU returns the upload and download MTU values negotiated by the
// last successful ProbeOnce. Returns (0, 0) if no successful probe yet.
func (p *ProbeOnlyClient) NegotiatedMTU() (up, down int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.upMTU, p.downMTU
}

// LastProbeError returns the most recent error from ProbeOnce, or nil if the
// last probe succeeded.
func (p *ProbeOnlyClient) LastProbeError() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastErr
}

// Close releases any held resources. Safe to call multiple times.
func (p *ProbeOnlyClient) Close() error {
	if p == nil || p.c == nil {
		return nil
	}
	// Tear down whatever the underlying Client created (transports, codecs).
	// Inspect upstream — it may already have a Stop()/Close() method on Client.
	return nil
}

var ErrConfigBadResolverCount = errInternal("ProbeOnlyClient requires exactly one resolver")

type errInternal string

func (e errInternal) Error() string { return string(e) }
```

**Important:** The exact field names of `config.ClientConfig` and the constructor name (`NewClient` vs `New` vs something else) depend on the vendored upstream. After writing this skeleton, run `go build ./third_party/stormdns/pkg/client/` and fix the field names + constructor signature as needed by reading the surrounding upstream code. Document each cross-package referent (e.g. config flags) you needed to discover in `third_party/stormdns/SYNC.md` under "Applied patches".

Then update `SYNC.md` to add this patch:

```
5. Added `pkg/client/probe_api.go` exposing ProbeOnlyClient. This is a
   thin range-scout-specific wrapper around `recheckResolverConnection`;
   it must be re-applied verbatim on every re-sync.
```

- [ ] **Step 3.7: Run wrapper unit tests**

```bash
go test ./internal/stormdnsembed/ -v
```

Expected: `TestProbeMTUValidatesInputs` PASS for all cases. `TestProbeMTUTimesOutOnUnreachable` PASS (returns Err non-nil on unreachable IP). `TestSyncMDHasValidCommit` PASS.

If a sub-case fails, the most likely cause is a missing field or wrong constructor name in `probe_api.go` — fix in place and re-run.

- [ ] **Step 3.8: Add the build-tagged integration test**

Create `internal/stormdnsembed/integration_test.go`:

```go
//go:build integration

package stormdnsembed

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestProbeMTUAgainstRealServer requires:
//   STORMDNS_DOMAIN=t.your-server.example.com
//   STORMDNS_KEY=<base64 key>
//   STORMDNS_RESOLVER=8.8.8.8 (optional, defaults to 8.8.8.8)
// Run via: make integration-test
func TestProbeMTUAgainstRealServer(t *testing.T) {
	domain := os.Getenv("STORMDNS_DOMAIN")
	key := os.Getenv("STORMDNS_KEY")
	if domain == "" || key == "" {
		t.Skip("set STORMDNS_DOMAIN and STORMDNS_KEY to run integration test")
	}
	resolver := os.Getenv("STORMDNS_RESOLVER")
	if resolver == "" {
		resolver = "8.8.8.8"
	}

	res := ProbeMTU(context.Background(), ProbeOptions{
		ResolverIP:   resolver,
		ResolverPort: 53,
		Domain:       domain,
		Key:          key,
		Timeout:      30 * time.Second,
	})
	if !res.Passed {
		t.Fatalf("ProbeMTU failed against real server: err=%v", res.Err)
	}
	if res.UpMTUBytes <= 0 || res.DownMTUBytes <= 0 {
		t.Fatalf("expected positive MTU values, got up=%d down=%d", res.UpMTUBytes, res.DownMTUBytes)
	}
}
```

- [ ] **Step 3.9: Add `integration-test` Makefile target**

Edit `Makefile`. After the existing `test:` target, append:

```makefile
integration-test:
	go test -tags=integration -count=1 ./internal/stormdnsembed/...
```

Add `integration-test` to the `.PHONY` line near the top.

- [ ] **Step 3.10: Commit**

```bash
git add internal/stormdnsembed/ third_party/stormdns/pkg/client/probe_api.go third_party/stormdns/SYNC.md Makefile
git commit -m "feat(stormdnsembed): add ProbeMTU wrapper

ProbeMTU runs StormDNS's own upload+download MTU probe against a single
resolver, mirroring recheckResolverConnection. Adds ProbeOnlyClient to
the vendored pkg/client (recorded in SYNC.md) so the wrapper can drive
the probe without spinning up the balancer/health-loop/SOCKS5 goroutines.
Includes input-validation unit tests and a build-tagged integration test
gated on STORMDNS_DOMAIN/STORMDNS_KEY env vars.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4 ordering note

The orchestrator in this task writes to new fields on `model.Resolver` (`StormDNSPassed`, `UpMTUBytes`, `DownMTUBytes`, `StormDNSLatencyMS`). Those fields must exist before this task compiles. Task 5 has been **reordered to run as Task 4a (additive only)** before this task, and the *removal* of old DNSTT fields is deferred to Task 8 (the DNSTT cleanup). The renumbered sequence is:

```
Task 1 — vendor stormdns
Task 2 — bogon filter
Task 3 — stormdnsembed wrapper
Task 4a — add new StormDNS model fields (additive; old DNSTT fields stay)
Task 4b — Verify orchestrator (uses new fields)
Task 5  — drop old DNSTT model fields  ← MOVED into Task 8
Task 6  — exporters
Task 7  — UI
Task 8  — remove DNSTT (now also drops unused DNSTT model fields)
Task 9  — README
```

The original "Task 5" content below is split: the **add-new-fields** half stays here (renumbered Task 4a), and the **drop-old-fields** half moves into Task 8.

## Task 4a: Add new StormDNS model fields (additive)

**Files:**
- Modify: `internal/model/model.go`

- [ ] **Step 4a.1: Add new StormDNS fields to `Resolver`**

Open `internal/model/model.go`. In the `Resolver` struct, **after** the existing DNSTT-block fields (do NOT remove the old ones yet — that happens in Task 8), append:

```go
StormDNSNearby    bool   `json:"stormdns_nearby,omitempty"`
StormDNSChecked   bool   `json:"stormdns_checked,omitempty"`
StormDNSPassed    bool   `json:"stormdns_passed,omitempty"`
StormDNSLatencyMS int64  `json:"stormdns_latency_ms,omitempty"`
StormDNSError     string `json:"stormdns_error,omitempty"`
UpMTUBytes        int    `json:"up_mtu_bytes,omitempty"`
DownMTUBytes      int    `json:"down_mtu_bytes,omitempty"`
```

The model now has both the legacy DNSTT fields and the new StormDNS fields side-by-side. This is the deliberate intermediate state until Task 8.

- [ ] **Step 4a.2: Verify build + tests**

```bash
cd /Users/rasoul/Downloads/Scaner/range-scout
go build ./...
go test ./...
```

Expected: green. No code reads the new fields yet, so behavior is unchanged.

- [ ] **Step 4a.3: Commit**

```bash
git add internal/model/model.go
git commit -m "feat(model): add StormDNS resolver fields (additive)

Adds StormDNSPassed/StormDNSLatencyMS/UpMTUBytes/DownMTUBytes/etc
alongside the existing DNSTT fields. The old DNSTT fields are kept
until the dnstt package is removed in a later commit; this keeps
every intermediate commit building cleanly.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4b: Add `internal/stormdns/Verify` orchestrator

**Files:**
- Create: `internal/stormdns/verify.go`
- Create: `internal/stormdns/verify_test.go`
- Create: `internal/stormdns/eligible.go`
- Create: `internal/stormdns/eligible_test.go`

- [ ] **Step 4.1: Reference the existing dnstt orchestrator**

Read `/Users/rasoul/Downloads/Scaner/range-scout/internal/dnstt/dnstt.go`. The new orchestrator mirrors its shape:

- `Test(ctx, resolvers, cfg, emit) (Result, error)`
- `EligibleResolvers(resolvers []model.Resolver, scoreThreshold int) []int`
- Worker pool, batch size, progress events.

We're rewriting, not editing in place. The dnstt module is removed in Task 8.

- [ ] **Step 4.2: Write the failing eligible test**

Create `internal/stormdns/eligible_test.go`:

```go
package stormdns

import (
	"testing"

	"range-scout/internal/model"
)

func TestEligibleResolvers(t *testing.T) {
	resolvers := []model.Resolver{
		{IP: "1.0.0.1", TunnelScore: 6},
		{IP: "2.0.0.2", TunnelScore: 3},
		{IP: "3.0.0.3", TunnelScore: 1},
		{IP: "4.0.0.4", TunnelScore: 0},
	}
	got := EligibleResolvers(resolvers, 2)
	want := []int{0, 1}
	if !equalIndexes(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func equalIndexes(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
```

- [ ] **Step 4.3: Implement `eligible.go`**

Create `internal/stormdns/eligible.go`:

```go
package stormdns

import "range-scout/internal/model"

// EligibleResolvers returns indexes (into resolvers) of entries whose
// TunnelScore is >= scoreThreshold.
func EligibleResolvers(resolvers []model.Resolver, scoreThreshold int) []int {
	out := make([]int, 0, len(resolvers))
	for i, r := range resolvers {
		if r.TunnelScore >= scoreThreshold {
			out = append(out, i)
		}
	}
	return out
}
```

- [ ] **Step 4.4: Run eligible test**

```bash
go test ./internal/stormdns/ -run TestEligibleResolvers -v
```

Expected: PASS.

- [ ] **Step 4.5: Write the failing orchestrator tests**

Create `internal/stormdns/verify_test.go`:

```go
package stormdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"range-scout/internal/model"
	"range-scout/internal/stormdnsembed"
)

type stubProber struct {
	results map[string]stormdnsembed.ProbeResult
}

func (s stubProber) ProbeMTU(ctx context.Context, opts stormdnsembed.ProbeOptions) stormdnsembed.ProbeResult {
	if r, ok := s.results[opts.ResolverIP]; ok {
		return r
	}
	return stormdnsembed.ProbeResult{Passed: false, Err: errors.New("stub: no result configured")}
}

func TestVerifyEmptyInputReturnsCleanly(t *testing.T) {
	r, err := Verify(context.Background(), nil, Config{Domain: "t.example.com", Key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}, nil)
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if r.PassedCount != 0 || r.TestedCount != 0 {
		t.Fatalf("expected zero counts, got %+v", r)
	}
}

func TestVerifyMixedResults(t *testing.T) {
	resolvers := []model.Resolver{
		{IP: "1.0.0.1", TunnelScore: 6},
		{IP: "2.0.0.2", TunnelScore: 6},
		{IP: "3.0.0.3", TunnelScore: 6},
	}
	stub := stubProber{
		results: map[string]stormdnsembed.ProbeResult{
			"1.0.0.1": {Passed: true, UpMTUBytes: 64, DownMTUBytes: 120},
			"2.0.0.2": {Passed: false, Err: stormdnsembed.ErrProbeTimeout},
			"3.0.0.3": {Passed: true, UpMTUBytes: 60, DownMTUBytes: 100},
		},
	}
	cfg := Config{
		Domain:         "t.example.com",
		Key:            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ScoreThreshold: 2,
		Workers:        4,
		Timeout:        2 * time.Second,
		Prober:         stub,
	}
	r, err := Verify(context.Background(), resolvers, cfg, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if r.PassedCount != 2 {
		t.Fatalf("expected 2 passes, got %d", r.PassedCount)
	}
	if r.Resolvers[0].StormDNSPassed != true {
		t.Fatalf("expected resolver 0 to pass; got %+v", r.Resolvers[0])
	}
	if r.Resolvers[1].StormDNSPassed != false {
		t.Fatalf("expected resolver 1 to fail; got %+v", r.Resolvers[1])
	}
}

func TestVerifyAbortsOnFiveKeyMismatches(t *testing.T) {
	resolvers := []model.Resolver{
		{IP: "1.0.0.1", TunnelScore: 6},
		{IP: "2.0.0.2", TunnelScore: 6},
		{IP: "3.0.0.3", TunnelScore: 6},
		{IP: "4.0.0.4", TunnelScore: 6},
		{IP: "5.0.0.5", TunnelScore: 6},
		{IP: "6.0.0.6", TunnelScore: 6},
		{IP: "7.0.0.7", TunnelScore: 6},
	}
	results := map[string]stormdnsembed.ProbeResult{}
	for _, r := range resolvers {
		results[r.IP] = stormdnsembed.ProbeResult{Passed: false, Err: stormdnsembed.ErrKeyMismatch}
	}
	cfg := Config{
		Domain:         "t.example.com",
		Key:            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ScoreThreshold: 2,
		Workers:        1, // sequential to make abort behavior deterministic
		Timeout:        2 * time.Second,
		Prober:         stubProber{results: results},
	}
	_, err := Verify(context.Background(), resolvers, cfg, nil)
	if err == nil || !errors.Is(err, ErrKeyMismatchAbort) {
		t.Fatalf("expected ErrKeyMismatchAbort, got %v", err)
	}
}

func TestVerifyValidatesConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want error
	}{
		{"empty domain", Config{Key: "AAAA"}, ErrInvalidConfig},
		{"empty key", Config{Domain: "t.example.com"}, ErrInvalidConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(context.Background(), nil, tc.cfg, nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}
```

- [ ] **Step 4.6: Implement `verify.go`**

Create `internal/stormdns/verify.go`:

```go
package stormdns

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"range-scout/internal/model"
	"range-scout/internal/stormdnsembed"
)

// keyMismatchAbortThreshold is the number of consecutive ErrKeyMismatch
// results across different resolvers that triggers a top-level abort,
// surfaced as ErrKeyMismatchAbort. Not user-configurable.
const keyMismatchAbortThreshold = 5

// Errors returned by Verify.
var (
	ErrInvalidConfig    = errors.New("stormdns.Verify: invalid Config")
	ErrKeyMismatchAbort = errors.New("stormdns.Verify: 5 consecutive ErrKeyMismatch results — check StormDNS Key")
)

// Prober is the surface Verify needs from stormdnsembed. The default
// implementation forwards to stormdnsembed.ProbeMTU; tests inject fakes.
type Prober interface {
	ProbeMTU(ctx context.Context, opts stormdnsembed.ProbeOptions) stormdnsembed.ProbeResult
}

type defaultProber struct{}

func (defaultProber) ProbeMTU(ctx context.Context, opts stormdnsembed.ProbeOptions) stormdnsembed.ProbeResult {
	return stormdnsembed.ProbeMTU(ctx, opts)
}

// Config controls a Verify run.
type Config struct {
	Domain         string
	Key            string
	ScoreThreshold int
	QuerySize      int
	MTURetries     int
	Workers        int
	Timeout        time.Duration
	TestNearbyIPs  bool
	Prober         Prober // nil → default
}

// EventType enumerates progress event kinds.
type EventType int

const (
	EventProgress EventType = iota
	EventResolverPassed
	EventResolverFailed
)

// Event is a progress update emitted during Verify.
type Event struct {
	Type     EventType
	Resolver model.Resolver
	Tested   uint64
	Passed   uint64
	Total    uint64
}

// Result is what Verify returns.
type Result struct {
	Resolvers   []model.Resolver
	PassedCount uint64
	TestedCount uint64
	StartedAt   time.Time
	FinishedAt  time.Time
}

// Verify runs the StormDNS MTU probe against every score-eligible resolver in
// resolvers and returns the updated slice with StormDNSPassed/UpMTU/DownMTU
// fields populated.
func Verify(ctx context.Context, resolvers []model.Resolver, cfg Config, emit func(Event)) (Result, error) {
	if cfg.Domain == "" || cfg.Key == "" {
		return Result{}, fmt.Errorf("%w: Domain and Key are required", ErrInvalidConfig)
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 8
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.Prober == nil {
		cfg.Prober = defaultProber{}
	}

	out := make([]model.Resolver, len(resolvers))
	copy(out, resolvers)

	eligible := EligibleResolvers(out, cfg.ScoreThreshold)
	total := uint64(len(eligible))

	r := Result{Resolvers: out, StartedAt: time.Now()}
	if total == 0 {
		r.FinishedAt = time.Now()
		return r, nil
	}

	jobs := make(chan int, cfg.Workers)
	var tested, passed atomic.Uint64
	var consecutiveKeyMismatch atomic.Int32
	abortCtx, abortCancel := context.WithCancel(ctx)
	defer abortCancel()

	var wg sync.WaitGroup
	for w := 0; w < cfg.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if abortCtx.Err() != nil {
					return
				}
				res := cfg.Prober.ProbeMTU(abortCtx, stormdnsembed.ProbeOptions{
					ResolverIP:   out[idx].IP,
					ResolverPort: 53,
					Domain:       cfg.Domain,
					Key:          cfg.Key,
					QuerySize:    cfg.QuerySize,
					Retries:      cfg.MTURetries,
					Timeout:      cfg.Timeout,
				})
				out[idx].StormDNSPassed = res.Passed
				out[idx].UpMTUBytes = res.UpMTUBytes
				out[idx].DownMTUBytes = res.DownMTUBytes
				out[idx].StormDNSLatencyMS = res.Latency.Milliseconds()

				tested.Add(1)
				if res.Passed {
					passed.Add(1)
					consecutiveKeyMismatch.Store(0)
					if emit != nil {
						emit(Event{Type: EventResolverPassed, Resolver: out[idx], Tested: tested.Load(), Passed: passed.Load(), Total: total})
					}
				} else {
					if errors.Is(res.Err, stormdnsembed.ErrKeyMismatch) {
						if consecutiveKeyMismatch.Add(1) >= keyMismatchAbortThreshold {
							abortCancel()
						}
					} else {
						consecutiveKeyMismatch.Store(0)
					}
					if emit != nil {
						emit(Event{Type: EventResolverFailed, Resolver: out[idx], Tested: tested.Load(), Passed: passed.Load(), Total: total})
					}
				}
			}
		}()
	}

	for _, idx := range eligible {
		select {
		case <-abortCtx.Done():
			break
		case jobs <- idx:
		}
	}
	close(jobs)
	wg.Wait()

	r.PassedCount = passed.Load()
	r.TestedCount = tested.Load()
	r.FinishedAt = time.Now()

	if consecutiveKeyMismatch.Load() >= keyMismatchAbortThreshold && abortCtx.Err() != nil {
		return r, ErrKeyMismatchAbort
	}
	return r, nil
}
```

Note: the spec calls for `Test Nearby IPs` /24 fan-out. The orchestrator above does *not* implement it yet — Task 7 (UI) wires the nearby-IPs expansion by appending fan-out resolvers to the input list before calling Verify. The fan-out logic itself is small and lifts unchanged from `internal/dnstt/dnstt.go` `collectNearbyResolvers`. We'll port it in Task 7 step 7.5.

- [ ] **Step 4.7: Run orchestrator tests**

```bash
go test ./internal/stormdns/ -v
```

Expected: all four tests PASS.

- [ ] **Step 4.8: Commit**

```bash
git add internal/stormdns/
git commit -m "feat(stormdns): add Verify orchestrator and EligibleResolvers

Verify runs StormDNS MTU probes across score-eligible resolvers using a
worker pool, emits progress events, and aborts after 5 consecutive
ErrKeyMismatch results. Prober interface allows test-time injection of
fakes. EligibleResolvers extracted into its own file per spec.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: (intentionally empty — work split across Task 4a and Task 8)

The DNSTT→StormDNS field migration was originally one task; it has been split into:
- **Task 4a** (above): adds the new StormDNS fields to `model.Resolver` additively.
- **Task 8** (below): removes the now-unused DNSTT fields when removing the dnstt package.

Skip this task and continue to Task 6.

---

## Task 6: New exporters + extend existing ones for StormDNS results

**Files:**
- Modify: `internal/export/export.go`
- Modify: `internal/export/export_test.go`

**Note:** `model.Resolver` has no per-resolver `Port` field — port is a scan-wide config (`scanConfig.port`). The writer functions therefore take port as a parameter, not from the Resolver.

- [ ] **Step 6.1: Write the failing cache-log writer test**

Append to `internal/export/export_test.go`:

```go
func TestWriteStormDNSCacheLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.log")
	resolvers := []model.Resolver{
		{IP: "1.1.1.1", StormDNSPassed: true,  UpMTUBytes: 64, DownMTUBytes: 120},
		{IP: "8.8.8.8", StormDNSPassed: true,  UpMTUBytes: 60, DownMTUBytes: 110},
		{IP: "9.9.9.9", StormDNSPassed: false, UpMTUBytes: 0,  DownMTUBytes: 0},
	}
	if err := WriteStormDNSCacheLog(path, resolvers, "t.example.com", 53); err != nil {
		t.Fatalf("write: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (only passed resolvers), got %d:\n%s", len(lines), body)
	}
	// Format: <RFC3339> <ip:port> <domain> UP=<n> DOWN=<n>
	want := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z 1\.1\.1\.1:53 t\.example\.com UP=64 DOWN=120$`)
	if !want.MatchString(lines[0]) {
		t.Fatalf("line 0 wrong format:\n  got: %q", lines[0])
	}
}

func TestWriteStormDNSCacheLogRetainsNonDefaultPort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.log")
	resolvers := []model.Resolver{
		{IP: "1.1.1.1", StormDNSPassed: true, UpMTUBytes: 64, DownMTUBytes: 120},
	}
	if err := WriteStormDNSCacheLog(path, resolvers, "t.example.com", 5353); err != nil {
		t.Fatalf("write: %v", err)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "1.1.1.1:5353") {
		t.Fatalf("expected ip:5353 in output, got %q", body)
	}
}
```

(Remember to import `os`, `path/filepath`, `regexp`, `strings`, and the model package at the top of `export_test.go`.)

- [ ] **Step 6.2: Write the failing client_resolvers.simple writer test**

Append to `internal/export/export_test.go`:

```go
func TestWriteStormDNSResolversSimple(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.simple")
	resolvers := []model.Resolver{
		{IP: "1.1.1.1", StormDNSPassed: true},
		{IP: "8.8.8.8", StormDNSPassed: true},
		{IP: "9.9.9.9", StormDNSPassed: false},
	}
	if err := WriteStormDNSResolversSimple(path, resolvers, 53); err != nil {
		t.Fatalf("write: %v", err)
	}
	body, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (only passed), got %d:\n%s", len(lines), body)
	}
	if lines[0] != "1.1.1.1" {
		t.Fatalf("port 53 should be omitted, got %q", lines[0])
	}
}

func TestWriteStormDNSResolversSimpleNonDefaultPort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.simple")
	resolvers := []model.Resolver{{IP: "8.8.8.8", StormDNSPassed: true}}
	if err := WriteStormDNSResolversSimple(path, resolvers, 5353); err != nil {
		t.Fatalf("write: %v", err)
	}
	body, _ := os.ReadFile(path)
	if strings.TrimSpace(string(body)) != "8.8.8.8:5353" {
		t.Fatalf("expected 8.8.8.8:5353, got %q", body)
	}
}
```

- [ ] **Step 6.3: Run tests to verify they fail**

```bash
go test ./internal/export/ -run "TestWriteStormDNS" -v
```

Expected: FAIL, undefined function names.

- [ ] **Step 6.4: Implement the writers**

Append to `internal/export/export.go`:

```go
// WriteStormDNSCacheLog writes one line per StormDNS-passed resolver in
// the StormDNS native cache-log format:
//   <RFC3339> <ip:port> <domain> UP=<n> DOWN=<n>
// port is the scan-wide DNS port (range-scout's scanConfig.port). Resolvers
// with StormDNSPassed=false are skipped.
func WriteStormDNSCacheLog(path string, resolvers []model.Resolver, domain string, port int) error {
	if port <= 0 {
		port = 53
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	now := time.Now().UTC().Format(time.RFC3339)
	bw := bufio.NewWriter(f)
	for _, r := range resolvers {
		if !r.StormDNSPassed {
			continue
		}
		fmt.Fprintf(bw, "%s %s:%d %s UP=%d DOWN=%d\n", now, r.IP, port, domain, r.UpMTUBytes, r.DownMTUBytes)
	}
	return bw.Flush()
}

// WriteStormDNSResolversSimple writes one line per StormDNS-passed resolver
// in the StormDNS client_resolvers.simple format. port 53 is omitted from
// the output; any other port is retained as <ip>:<port>.
func WriteStormDNSResolversSimple(path string, resolvers []model.Resolver, port int) error {
	if port <= 0 {
		port = 53
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	bw := bufio.NewWriter(f)
	for _, r := range resolvers {
		if !r.StormDNSPassed {
			continue
		}
		if port == 53 {
			fmt.Fprintf(bw, "%s\n", r.IP)
		} else {
			fmt.Fprintf(bw, "%s:%d\n", r.IP, port)
		}
	}
	return bw.Flush()
}
```

Add `bufio`, `fmt`, `os`, `time` imports if not already present.

- [ ] **Step 6.5: Run the new tests + all export tests**

```bash
go test ./internal/export/ -v
```

Expected: all PASS.

- [ ] **Step 6.6: Audit existing exporters for DNSTT-named filename templates**

```bash
grep -rn "dnstt-scan-success\|dnstt-scan-failures\|DNSTTPassed" internal/export/ --include='*.go'
```

For each, rename to the StormDNS equivalent:
- `dnstt-scan-success` → `stormdns-scan-success`
- `dnstt-scan-failures` → `stormdns-scan-failures`
- Field references: any DNSTT-named field that the exporter reads (collapse `DNSTTTunnelOK || DNSTTE2EOK` into `StormDNSPassed`, etc. — see Task 4a for the new field names; old fields still exist until Task 8 so both can be referenced if needed for transition).

- [ ] **Step 6.7: Commit**

```bash
git add internal/export/
git commit -m "feat(export): add StormDNS cache-log + client_resolvers.simple writers

WriteStormDNSCacheLog emits the StormDNS native cache-log format
(<RFC3339> <ip:port> <domain> UP=<n> DOWN=<n>) so range-scout output
can pre-warm a real StormDNS client. WriteStormDNSResolversSimple
emits the resolver-list format. Existing scan-stage exporters renamed
from dnstt-* to stormdns-* prefixes.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Replace DNSTT TUI screen with StormDNS screen

**Files:**
- Modify: `ui.go`
- Modify: `ui_test.go`
- Modify: `config.go`
- Modify: `config_test.go`

- [ ] **Step 7.1: Update `config.go` schema (`dnsttConfig` → `stormdnsConfig`)**

Open `config.go`. Read the existing structure first:

```bash
grep -n "dnsttConfig\|DNSTTConfig\|dnsttConf" config.go | head -20
```

For each `dnsttConfig` mention:
- Rename JSON tag `"dnsttConfig"` → `"stormdnsConfig"`.
- Rename Go field/type names `DNSTTConfig`, `dnsttConf`, etc., to `StormDNSConfig`, `stormdnsConf`.
- Field renames inside the struct:
  - `pubkey` → `key`
  - Drop: `e2eTimeoutS`, `e2eURL`, `socksUsername`, `socksPassword`
  - Keep: `domain`, `timeoutMS`, `querySize`, `scoreThreshold`, `testNearbyIPs`
  - Add: `mtuRetries` (int as string, like other numeric fields)
- In `Save Config` writer logic, drop the e2e/socks keys from the marshaled struct.

- [ ] **Step 7.2: Add legacy migration in the loader**

In `config.go`, the loader (function that decodes JSON or TOML into the Config struct) should handle `dnsttConfig` blocks present in older files:

```go
// Legacy: configs written before v0.8.0 used dnsttConfig instead of stormdnsConfig.
// Migrate the domain field over and warn that the rest is ignored.
if legacy := raw.LegacyDNSTTConfig; legacy != nil {
	if loaded.StormDNSConfig.Domain == "" && legacy.Domain != "" {
		loaded.StormDNSConfig.Domain = legacy.Domain
	}
	log.Println("WARN: legacy dnsttConfig block detected; \"domain\" migrated to stormdnsConfig.domain; other DNSTT-only fields ignored")
}
```

The `raw` intermediate struct should have both `StormDNSConfig` and `LegacyDNSTTConfig` fields with their respective JSON tags so both can decode side-by-side.

- [ ] **Step 7.3: Add migration test**

Append to `config_test.go`:

```go
func TestLoadConfigMigratesLegacyDNSTTBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{
		"dnsttConfig": {
			"domain": "legacy.example.com",
			"pubkey": "ignored",
			"e2eURL": "ignored",
			"socksUsername": "ignored"
		}
	}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := loadConfigFromPath(path) // use the actual loader function name
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.StormDNSConfig.Domain != "legacy.example.com" {
		t.Fatalf("domain not migrated, got %q", cfg.StormDNSConfig.Domain)
	}
}
```

(Adjust `loadConfigFromPath` to whatever the existing exported loader is named.)

- [ ] **Step 7.4: Run config tests**

```bash
go test -run "TestLoadConfig" -v .
```

Expected: existing tests still pass, new migration test passes.

- [ ] **Step 7.5: Update `ui.go` — DNSTT screen → StormDNS screen**

Open `ui.go`. Find the DNSTT screen rendering (look for "DNSTT", "Pubkey", "E2E URL"):

```bash
grep -n "DNSTT\|Pubkey\|E2E URL\|SOCKS Username\|SOCKS Password" ui.go | head -40
```

For each line:
- Field labels: `DNSTT Pubkey` → `StormDNS Key`, `DNSTT Domain` → `StormDNS Domain`.
- Button labels: `Start DNSTT` → `Start StormDNS`, `Test DNSTT` → `Test StormDNS`.
- Status messages: replace "DNSTT" with "StormDNS" everywhere.
- Remove input rows for: `E2E URL`, `SOCKS Username`, `SOCKS Password`.
- Update the `Test Nearby IPs` interaction to call into `internal/stormdns.Verify` (not `internal/dnstt.Test`).
- Bump `uiVersionLabel` to `"v0.8.0-rc1"`.
- Wire the `Merge` call's new `droppedBogons` return into the warnings panel — add a UI line: `dropped %d fully-bogon prefix(es): %s` when non-empty.

- [ ] **Step 7.6: Port `Test Nearby IPs` /24 fan-out**

Open `internal/dnstt/dnstt.go`. Locate `collectNearbyResolvers`. Copy its logic into a new file `internal/stormdns/nearby.go`, adapting the parameter and result types to `model.Resolver` (no DNSTT-specific fields). Make sure the fan-out:
- Excludes IPs already in the resolver set.
- **Excludes bogon IPs** (call `prefixes.IsBogon`).
- Does not expand from nearby-discovered hits (single-pass).

Wire the fan-out into the UI handler that today wires it for DNSTT — invoke `stormdns.CollectNearbyResolvers(...)` after the initial Verify pass, then run a second `Verify` over the nearby seeds with the same Config but `TestNearbyIPs=false` (to prevent recursion).

- [ ] **Step 7.7: Run UI tests + manual smoke build**

```bash
go test ./... 2>&1 | tail -30
make build
./range-scout --help 2>&1 | head -5    # if a help flag exists
```

If `make build` succeeds, you can run `./range-scout` interactively to spot-check the StormDNS screen (skip if you don't have a terminal handy — the unit tests cover the rendering).

- [ ] **Step 7.8: Update `ui_test.go`**

Replace any DNSTT-named tests with StormDNS equivalents:
- `TestRenderDNSTTScreen` → `TestRenderStormDNSScreen`
- Assertions on the field labels: `assertContains(t, screen, "DNSTT Pubkey")` → `assertContains(t, screen, "StormDNS Key")`.
- Drop assertions for fields we removed (`E2E URL`, `SOCKS *`).
- Add assertions that `assertNotContains(t, screen, "DNSTT")` (paranoia).

Run:
```bash
go test -run "Render" -v .
```

- [ ] **Step 7.9: Commit**

```bash
git add ui.go ui_test.go config.go config_test.go internal/stormdns/nearby.go
git commit -m "feat(ui): replace DNSTT screen with StormDNS screen

Renames DNSTT fields to StormDNS, drops E2E URL + SOCKS auth fields,
wires Test Nearby IPs into the new Verify orchestrator (with bogon
filtering), surfaces dropped-bogon prefixes as UI warnings, and
migrates legacy dnsttConfig.json blocks. Bumps uiVersionLabel to
v0.8.0-rc1.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Remove DNSTT and drop unused DNSTT model fields

**Files:**
- Delete: `internal/dnstt/` (entire dir)
- Delete: `internal/dnsttembed/` (entire dir)
- Delete: `third_party/dnstt/` (entire dir)
- Modify: `internal/model/model.go` (drop legacy DNSTT-block fields)
- Modify: `go.mod` (remove DNSTT replace/require if any)

- [ ] **Step 8.1: Confirm no remaining package-level references**

```bash
cd /Users/rasoul/Downloads/Scaner/range-scout
grep -rn "internal/dnstt\|internal/dnsttembed\|third_party/dnstt" --include='*.go' --include='go.mod' .
```

Expected: empty output (only the dnstt package itself referenced from within itself). Task 7's UI rewrite should have replaced all callsites.

- [ ] **Step 8.2: Delete the three directories**

```bash
git rm -r internal/dnstt internal/dnsttembed third_party/dnstt
```

- [ ] **Step 8.3: Drop legacy DNSTT fields from `model.Resolver`**

Edit `internal/model/model.go`. Remove these fields from the `Resolver` struct (added back in Task 4a's intermediate state):

```go
DNSTTNearby          bool   `json:"dnstt_nearby,omitempty"`
DNSTTChecked         bool   `json:"dnstt_checked,omitempty"`
DNSTTTunnelOK        bool   `json:"dnstt_tunnel_ok,omitempty"`
DNSTTE2EOK           bool   `json:"dnstt_e2e_ok,omitempty"`
DNSTTTunnelMillis    int64  `json:"dnstt_tunnel_ms,omitempty"`
DNSTTE2EMillis       int64  `json:"dnstt_e2e_ms,omitempty"`
DNSTTError           string `json:"dnstt_error,omitempty"`
```

After Task 7 the only remaining writers of these fields were inside `internal/dnstt/`, which we just deleted in step 8.2. So removing them now compiles cleanly.

- [ ] **Step 8.4: Sweep for any straggler reads of the old fields**

```bash
grep -rn "DNSTTNearby\|DNSTTChecked\|DNSTTTunnelOK\|DNSTTE2EOK\|DNSTTTunnelMillis\|DNSTTE2EMillis\|DNSTTError" --include='*.go' .
```

Expected: empty. If anything matches (likely in JSON-decode code or a test fixture), migrate it to the StormDNS equivalent or delete it.

- [ ] **Step 8.5: Remove DNSTT lines from `go.mod` / `go.sum`**

```bash
go mod tidy
git diff go.mod go.sum | head -30
```

Expected: `range-scout/third_party/dnstt` replace/require lines disappear from go.mod; transitive deps unique to dnstt drop out of go.sum.

- [ ] **Step 8.6: Build and run all tests**

```bash
go build ./...
go test ./...
```

Expected: all green. If anything breaks, that's a missed reference — fix it.

- [ ] **Step 8.7: Commit**

```bash
git add -u
git commit -m "chore: remove DNSTT and drop legacy DNSTT model fields

Deletes internal/dnstt, internal/dnsttembed, and third_party/dnstt now
that the StormDNS verifier covers the same role. Drops the
DNSTTNearby/DNSTTChecked/DNSTTTunnelOK/DNSTTE2EOK/DNSTTTunnelMillis/
DNSTTE2EMillis/DNSTTError fields from model.Resolver (added back in
Task 4a as a transitional state). go.mod/go.sum cleaned via go mod tidy.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Update README and Farsi README

**Files:**
- Modify: `README.md`
- Modify: `README_FA.MD`

- [ ] **Step 9.1: Update `README.md` overview**

Open `README.md`. Replace DNSTT-stage prose throughout:
- Bullet list at top (lines ~1–13): replace "DNSTT stage" mentions with "StormDNS stage".
- "What It Does" section (lines ~18–31): step 6 references DNSTT — rewrite to describe StormDNS verification (domain + key, MTU upload+download probes).
- Config example (lines ~136–158): replace the `"dnsttConfig"` JSON block with `"stormdnsConfig"`. Remove `"pubkey"`, `"e2eTimeoutS"`, `"e2eURL"`, `"socksUsername"`, `"socksPassword"`. Add `"key"`, `"mtuRetries"`.
- "Quick Guide" (lines ~174–195): rewrite steps 9–13 for the StormDNS screen (domain + key fields only, no SOCKS/E2E).
- "Shortcuts" (lines ~239–250): keep same shortcut keys; only the labels change.
- "Notes" (lines ~252–262): drop DNSTT-only notes, add StormDNS-specific notes (bogon filter, cache-log format output).
- Add a new section "Third-party code":
  ```markdown
  ## Third-party code

  This project bundles a vendored copy of [StormDNS](https://github.com/nullroute1970/StormDNS)
  under `third_party/stormdns/`, used solely for the resolver-verification
  stage. See `third_party/stormdns/SYNC.md` for the pinned upstream commit
  and applied patches, and `third_party/stormdns/LICENSE` for the upstream
  MIT license.
  ```
- Update the version-shown-in-header note: example `v0.7.0` → `v0.8.0`.

- [ ] **Step 9.2: Update `README_FA.MD`**

Apply the equivalent changes to the Farsi README:
- Update the "نحوه کار" (How it works) section: replace DNSTT with StormDNS terminology.
- Update the "چه کاری انجام بدهید" (What to do) section: rewrite the workflow steps for the new fields.
- Update "نکته مهم" (Important notes): drop DNSTT-only bullets, add StormDNS-specific bullets (bogon filter, cache-log file output).

- [ ] **Step 9.3: Bump in-app version label to release form**

In `ui.go`, change `uiVersionLabel = "v0.8.0-rc1"` → `uiVersionLabel = "v0.8.0"` (or leave as `-rc1` if you plan to tag a release candidate first).

- [ ] **Step 9.4: Build + test final time**

```bash
go build ./...
go test ./...
make build
```

Expected: all green; binary builds.

- [ ] **Step 9.5: Final commit**

```bash
git add README.md README_FA.MD ui.go
git commit -m "docs: update README + Farsi README for StormDNS verifier

Replaces DNSTT-stage prose, updates the config.json example to the new
stormdnsConfig schema, rewrites the Quick Guide for the StormDNS screen,
adds a Third-party code section pointing at the vendored StormDNS source,
and bumps in-app version label to v0.8.0.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Final verification

- [ ] **All commits present on branch**

```bash
git log --oneline main..feat/stormdns-verifier
```

Expected: 9 commits matching the spec's commit sequence.

- [ ] **Full test pass**

```bash
go test ./...
```

- [ ] **Optional: integration test against real server**

```bash
make integration-test STORMDNS_DOMAIN=t.your-server.example.com STORMDNS_KEY=<base64>
```

- [ ] **Tag release candidate**

```bash
git tag v0.8.0-rc1
git push origin feat/stormdns-verifier --tags
```

(Push only when you're ready — pushing tags is visible to others.)
