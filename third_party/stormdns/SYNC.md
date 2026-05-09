# third_party/stormdns sync record

Upstream:    https://github.com/nullroute1970/StormDNS
Commit:      87806272a4c6ebd68fa001eccf513051b44c1284
Sync date:   2026-05-09
Synced by:   rasoultaji

## Applied patches (must be re-applied on every re-sync)

1. Renamed `internal/client/` → `pkg/client/` (so external modules can import it).
2. Rewrote go.mod module path: `module stormdns-go` → `module range-scout/third_party/stormdns`.
3. Rewrote all imports in `*.go`:
     - `stormdns-go/internal/client`  →  `range-scout/third_party/stormdns/pkg/client`
     - `stormdns-go/`                 →  `range-scout/third_party/stormdns/`
4. Dropped server-side and installer packages: `cmd/server`, `internal/server`,
   `server_*.sh`, `server_config*`, `client_*.sh`, `build.py`, `scripts/`,
   `docs/`, `assets/`, upstream READMEs, `AGENTS.md`.
5. Lowered `go` directive in `third_party/stormdns/go.mod` from upstream's `go 1.26.3`
   to match the local toolchain (currently `go 1.25.0`). On every re-sync, re-lower
   to whatever the local toolchain supports rather than copying upstream's directive
   verbatim.

## Re-sync procedure

1. Snapshot upstream HEAD into `/tmp/StormDNS-snapshot`:
   ```
   cd /tmp && rm -rf StormDNS-snapshot
   git clone https://github.com/nullroute1970/StormDNS StormDNS-snapshot
   ```
2. Capture the new commit hash and update the `Commit:` and `Sync date:` fields above:
   ```
   git -C /tmp/StormDNS-snapshot rev-parse HEAD
   ```
3. Copy the new tree over `third_party/stormdns/`, applying the same excludes:
   ```
   rsync -a --exclude '.git' --exclude '.github' \
     --exclude 'cmd/server' --exclude 'internal/server' \
     --exclude 'server_*.sh' --exclude 'server_config*' --exclude 'client_*.sh' \
     --exclude 'build.py' --exclude 'scripts' --exclude 'docs' --exclude 'assets' \
     --exclude 'README*.MD' --exclude 'AGENTS.md' \
     /tmp/StormDNS-snapshot/ third_party/stormdns/
   ```
4. Re-apply the patches:
   ```
   cd third_party/stormdns
   # Patch 1: rename internal/client → pkg/client
   [ -d internal/client ] && mkdir -p pkg && mv internal/client pkg/client
   # Patch 2: module path
   sed -i '' 's|^module stormdns-go$|module range-scout/third_party/stormdns|' go.mod
   # Patches 3a + 3b: imports (order matters — 3a before 3b)
   find . -name '*.go' -type f -exec sed -i '' \
     -e 's|stormdns-go/internal/client|range-scout/third_party/stormdns/pkg/client|g' {} +
   find . -name '*.go' -type f -exec sed -i '' \
     -e 's|stormdns-go/|range-scout/third_party/stormdns/|g' {} +
   # Patch 4: drop server-side and install scripts (most should be gone via excludes; safety net)
   find . -type d -name 'server' -prune -exec rm -rf {} +
   ```
   (On Linux, drop the empty `''` after `sed -i`.)
5. Verify build + tests:
   ```
   cd /Users/rasoul/Downloads/Scaner/range-scout
   go build ./third_party/stormdns/pkg/client/
   go build ./...
   go test ./...
   ```
6. Commit as `chore: sync third_party/stormdns to <short-sha>`.
