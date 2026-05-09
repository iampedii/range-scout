# third_party/stormdns sync record

Upstream:    https://github.com/nullroute1970/StormDNS
Commit:      87806272a4c6ebd68fa001eccf513051b44c1284
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
