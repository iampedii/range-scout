# range-scout

`range-scout` is a small TUI for:

- fetching announced IPv4 prefixes for supported Iranian operators from RIPEstat
- choosing a single range to scan
- checking which hosts on that range answer on DNS and allow recursion
- exporting prefixes or scan results on demand as `txt`, `csv`, or `json`

## What It Does

1. Fetches IPv4 prefixes for a selected operator from RIPEstat.
2. Lets you choose one CIDR range from that operator.
3. Scans hosts in that range over UDP/53.
4. Marks hosts as:
   - `dns reachable`
   - `recursive`
   - `stable` if both probe sites resolve successfully

## Build

Requires Go `1.24.0` or newer.

```bash
go build -o range-scout .
```

## Run

```bash
./range-scout
```

For a one-off run without building:

```bash
go run .
```

## Quick Guide

1. Select an operator from the left sidebar.
2. Click `Fetch` to load its prefixes.
3. Click `Scan Setup`.
4. Click `Pick Range` and choose one CIDR.
5. Set the probe URLs.
   Choose sites that are reachable in your network.
6. Click `Start Scan`.
7. Click `Export` if you want to save scan results.
8. In prefix mode, click `Save` if you want to save prefixes.

## Shortcuts

- `p`: prefix view
- `d`: scan setup
- `f`: fetch prefixes
- `s`: save or export current data
- `g`: start scan
- `x`: stop scan
- `Tab` / `Shift+Tab`: move focus
- `Esc`: leave an input field
- `q`: exit

## Notes

- IPv4 only
- Operator definitions are compiled into the app
- Files are saved only on demand
- The scanner uses UDP DNS probes plus recursive and stability checks
