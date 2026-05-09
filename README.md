# range-scout

`range-scout` is a small TUI for:

- loading announced IPv4 prefixes for supported Iranian operators
- importing IPv4 CIDRs or single IPv4 addresses from a local `.txt` file
- pasting IPv4 CIDRs or single IPv4 addresses directly into the TUI
- choosing one or more ranges to scan
- running a SlipNet-style UDP DNS compatibility scan on a configurable port
- opening a dedicated StormDNS stage after the scan for MTU-probe-based resolver verification
- exporting targets, scan results, or StormDNS-passed results on demand as `txt`, `csv`, or `json`
- saving startup defaults to `config.json`

## Screenshot

![range-scout screenshot](./screenshot.png)

## What It Does

1. Loads IPv4 scan targets for a selected operator, from a local `.txt` file, or from pasted text.
2. Lets you choose one or more CIDR ranges or single IPs from that loaded target set.
3. Scans hosts in those ranges over UDP on a configurable port (default `53`).
4. Runs the same six SlipNet-style compatibility probes used by the app's tunnel scoring flow and assigns each resolver a score from `0` to `6`.
5. Treats resolvers at or above the configured score threshold as StormDNS candidates.
6. Opens a dedicated StormDNS screen after the scan where you can:
   - set `StormDNS Domain` and `StormDNS Key` (the key delegated to your StormDNS server)
   - tune `Score Threshold`, `Query Size`, `MTU Retries`, `Test Nearby IPs`
   - run upload+download MTU probes against each score-eligible resolver, mirroring what StormDNS's own client does at startup
7. Exports passed resolvers as the existing `txt`/`csv`/`json` formats, plus two StormDNS-native files: a cache-log (`<RFC3339> <ip:port> <domain> UP=<n> DOWN=<n>`) and a `client_resolvers.simple` resolver list — both directly usable by a real StormDNS client.

## Build

The repo pins the Go toolchain to `1.24.1` for reproducible builds. If your
local `go` command is older, Go will auto-download the pinned toolchain when
needed.

```bash
make build
```

This builds a local development binary at `./range-scout`.

To produce a distributable artifact for the current platform:

```bash
make build-dist
```

To produce a Windows tester build:

```bash
make build-windows
```

That writes `dist/range-scout-windows-amd64.exe`.

To build the full default cross-platform matrix:

```bash
make build-all
```

That writes separate artifacts to `dist/` for:

- `darwin/amd64`
- `darwin/arm64`
- `linux/amd64`
- `linux/arm64`
- `windows/amd64`
- `windows/arm64`

You can override the matrix if needed:

```bash
make build-all BUILD_OSES="linux windows" BUILD_ARCHES="amd64"
```

## Release Builds

The git tag is the release source of truth. This matches a normal GitFlow
process:

- tag `v0.8.0` for a final release
- tag `v0.8.0-rcN` for a release candidate

To build a release artifact from the current tag:

```bash
make release
```

To build a Windows release artifact from the current tag:

```bash
make release-windows
```

To build release artifacts for the full default matrix from the current tag:

```bash
make release-all
```

Release builds are intentionally strict:

- `HEAD` must be exactly on a tag such as `v0.8.0` or `v0.8.0-rcN`
- the git worktree must be clean

If those checks pass, the artifact filename will match the release tag exactly.

The in-app version shown in the header is a manual constant in
`ui.go` (`uiVersionLabel`). Update that value before tagging a new release so
bug reports and release artifacts stay aligned.

## Run

```bash
./range-scout
```

For a one-off run without building:

```bash
make run
```

## Config

You can place an optional `config.json` next to the project and `range-scout`
will load it on startup. The app first looks in the current working directory.
If there is no config there, it also checks next to the `range-scout` binary.

Example:

```json
{
  "importConfig": {
    "importFilePaths": {}
  },
  "scanConfig": {
    "workers": "256",
    "timeoutMS": "15000",
    "port": "53"
  },
  "stormdnsConfig": {
    "domain": "t.example.com",
    "key": "",
    "timeoutMS": "15000",
    "querySize": "",
    "mtuRetries": "3",
    "scoreThreshold": "2",
    "testNearbyIPs": "No"
  }
}
```

Notes:

- `importFilePaths` may be a single string or an object map.
- The app writes UI field values back as strings when you use `Save Config`.
- `stormdnsConfig.key` should be the base64-encoded StormDNS encryption key matching your server.
- `Save Config` currently writes `workers`, `timeoutMS`, `port`, and `protocol` in `scanConfig`, plus `domain`, `key`, `timeoutMS`, `querySize`, `mtuRetries`, `scoreThreshold`, and `testNearbyIPs` in `stormdnsConfig`.
- Use `"default"` to provide a fallback import path for any operator.
- Relative import paths are resolved relative to the `config.json` directory.
- `Save Config` keeps import paths relative to the config file when possible, so shared configs stay portable.
- The config file sets startup defaults; it does not auto-run imports, scans, or StormDNS verification.
- Bogon IP ranges (RFC1918, loopback, link-local, multicast, reserved, TEST-NET-*, etc.) are skipped automatically when expanding scan targets.
- Ask bug reporters to include the version shown in the header, for example `v0.8.0`.

## Quick Guide

1. Select an operator from the left sidebar if you want `Automatic API Fetch`. If you want to work manually, you can leave the operator unselected.
2. Choose `Automatic API Fetch`, `Import TXT`, or `Paste Targets` in `Load From`. Without an operator, only `Import TXT` and `Paste Targets` are available.
3. Click `Load Targets` to load operator prefixes, set `Import File` and click `Import TXT`, or click `Paste Targets` and paste directly into the modal.
4. Click `Scan Setup`.
5. Click `Pick Targets`, use the filter box if needed, and choose one or more CIDRs or single IPs. New target sets start with all targets selected, and the picker has `Select All` / `Deselect All` actions.
6. Set `Workers`, `Timeout`, `Port`, `Protocol`, `StormDNS Domain`, `Query Size`, and `Score Threshold`. `Protocol` can be `UDP`, `TCP`, or `BOTH`.
7. Click `Start Scan`.
8. Review the cached scan state in the details pane. If the app detected a transparent DNS proxy during the scan, it will warn you there.
9. Click `Test StormDNS` after the scan to open the dedicated StormDNS setup screen. The staged flow is `Load Targets -> DNS Scan -> StormDNS Verify`.
10. On the StormDNS screen:
    - set `StormDNS Domain` to the subdomain you delegated to your StormDNS server
    - set `StormDNS Key` to the base64 encryption key matching your server
    - leave `Query Size` empty unless you specifically want smaller probe queries
    - tune `Score Threshold` to control how strict the scan was before a resolver qualifies
    - enable `Test Nearby IPs` if you want each successful resolver to expand into a `/24` sweep
11. Click `Start StormDNS`.
12. Use `Export` on the scanner screen to save scan-stage successes. Use `Export Passed` on the StormDNS screen to save passed resolvers in `txt`/`csv`/`json`, plus the StormDNS-native cache-log and `client_resolvers.simple` files.
13. Use `Copy Passed` on the StormDNS screen if you want the passed resolver IPs in the clipboard.
14. Use `Save Config` whenever you want the current startup defaults written back to `config.json`.

## User Guidance

`range-scout` is mainly a tool for finding IPv4 resolvers from operator ranges or custom target sets, then pushing only the best candidates through a second-stage StormDNS verification flow.

How it works:

1. The app loads public IPv4 ranges for the selected operator, imports IPv4 CIDRs / single IPv4s from a local `.txt` file, or accepts pasted IPv4 CIDRs / single IPv4s.
2. You choose one or more CIDR ranges or imported / pasted single IPs that you want to scan.
3. The scanner probes each host in those ranges over the selected DNS transport on the port you choose.
4. If a host answers DNS, the app records it and runs the six SlipNet-style compatibility probes that feed the tunnel score.
5. The app treats resolvers at or above the current score threshold as StormDNS candidates.
6. If you want, the app can then test only those qualified resolvers against your StormDNS domain using upload and download MTU probes.
7. You can export scan-stage or StormDNS-stage outputs after the relevant stage finishes.

What to do:

1. Choose `Automatic API Fetch` if you want to load operator prefixes from a selected operator. If no operator is selected, use `Import TXT` or `Paste Targets`.
2. For file import or pasted text, put one IPv4 CIDR or IPv4 address on each line. Empty lines and `#` comments are ignored.
3. Load the targets first.
4. Use `Pick Targets` to limit the scan to the CIDRs or single IPs you want. All loaded targets start selected by default, and you can use `Select All` / `Deselect All` in the picker. The scan automatically covers all scannable hosts in the selected targets, so there is no separate host-limit field to tune.
5. Keep port `53` unless you specifically need another DNS port.
6. Set `StormDNS Domain` before the scan so the compatibility probes and tunnel-score workflow use the right domain.
7. Leave `Query Size` empty or `0` unless you specifically want smaller StormDNS probe queries.
8. Set `Score Threshold` to control how strict the scan should be before a resolver qualifies for the StormDNS stage.
9. Run the scan first, then use `Test StormDNS` to open the dedicated StormDNS screen and start the StormDNS stage there.
10. Set `StormDNS Key` to the base64 encryption key matching your server. Without a key, upload/download MTU probes cannot authenticate to the StormDNS server.
11. Tune `MTU Retries` to set how many times each MTU probe step is retried before giving up on a resolver.
12. Enable `Test Nearby IPs` if you want each successful original IPv4 seed to trigger one extra StormDNS run across the rest of its `/24`. Nearby-discovered IPs do not expand again.
13. Export the results you want to keep. Export filenames are stage-specific:
    `cidr-<label>`, `dns-scan-success-<label>`, `dns-scan-failures-<label>`, and `stormdns-scan-success-<label>`.

Important:

- This tool helps you get available IPs and candidate DNS resolvers.
- StormDNS checks only run against resolvers that meet the current SlipNet compatibility score threshold from the latest scan.
- `Score Threshold` filters which resolvers go through the StormDNS MTU probe (the heavier per-resolver test).
- `Export Passed` on the StormDNS screen writes the passed resolver file in `txt`/`csv`/`json` formats, plus a StormDNS-native cache-log file and a `client_resolvers.simple` resolver list, both directly usable by a real StormDNS client.
- A positive result here still does not guarantee that every real-world client or route will behave the same way on your network.

## Shortcuts

- `p`: target view
- `d`: scan setup
- `f`: load from the selected source
- `s`: save or export current data
- `g`: start scan
- `t`: start StormDNS test from the latest scan
- `x`: stop the active scan or StormDNS task
- `Tab` / `Shift+Tab`: move focus
- `Esc`: leave an input field
- `q`: exit

## Notes

- IPv4 only
- Operator definitions are compiled into the app
- Files are saved only on demand
- The TUI scanner supports `UDP`, `TCP`, and `BOTH` compatibility probes and defaults to port `53`
- StormDNS verification is a second-stage check over score-qualified resolvers, not a raw host scan
- `Score Threshold` filters which resolvers go through the StormDNS MTU probe (the heavier per-resolver test)
- `Test Nearby IPs` expands only one extra `/24` pass from successful original IPv4 seeds
- Bogon IP ranges (RFC1918, loopback, link-local, multicast, reserved, TEST-NET-*, etc.) are skipped automatically when expanding scan targets
- Passed resolvers are also written in StormDNS native formats: a cache-log file (compatible with StormDNS's startup cache) and `client_resolvers.simple` (compatible with StormDNS's resolver list format)
- `Save Config` updates startup defaults only; it does not start jobs automatically

## Third-party code

This project bundles a vendored copy of [StormDNS](https://github.com/nullroute1970/StormDNS)
under `third_party/stormdns/`, used solely for the resolver-verification stage.
See `third_party/stormdns/SYNC.md` for the pinned upstream commit and applied
patches, and `third_party/stormdns/LICENSE` for the upstream MIT license.

## راهنمای فارسی

`range-scout` در اصل ابزاری برای پیدا کردن resolverهای IPv4 از رنج اپراتورها یا تارگت‌های دستی است و بعد resolverهای بهتر را وارد مرحله جداگانه StormDNS می‌کند.

نحوه کار:

1. برنامه می‌تواند تارگت‌ها را با `Automatic API Fetch` بگیرد، از `Import TXT` بخواند، یا با `Paste Targets` مستقیم از داخل TUI دریافت کند. اگر اپراتوری انتخاب نشده باشد، فقط `Import TXT` و `Paste Targets` در دسترس هستند.
2. شما یک یا چند رنج CIDR یا IP تکی را برای اسکن انتخاب می‌کنید.
3. اسکنر هر هاست را با پروتکل انتخابی `UDP` یا `TCP` یا `BOTH` روی پورتی که مشخص می‌کنید بررسی می‌کند.
4. اگر یک هاست به DNS پاسخ بدهد، شش probe به سبک SlipNet روی آن اجرا می‌شود و یک tunnel score از `0` تا `6` می‌گیرد.
5. فقط resolverهایی که به `Score Threshold` برسند وارد مرحله StormDNS می‌شوند.
6. بعد از اسکن، یک صفحه جداگانه برای StormDNS باز می‌شود که در آن می‌توانید `StormDNS Domain` و `StormDNS Key` را تنظیم کنید و MTU probe های upload و download را روی resolverهای واجد شرایط اجرا کنید — دقیقاً مثل چیزی که کلاینت StormDNS هنگام راه‌اندازی انجام می‌دهد.
7. بعد از تمام شدن هر مرحله می‌توانید خروجی همان مرحله را بگیرید. StormDNS علاوه بر فرمت‌های `txt`/`csv`/`json`، یک فایل cache-log و یک فایل `client_resolvers.simple` هم می‌سازد که مستقیماً توسط کلاینت StormDNS قابل استفاده هستند.

چه کاری انجام بدهید:

1. ابتدا یکی از سه روش `Automatic API Fetch` یا `Import TXT` یا `Paste Targets` را انتخاب کنید. اگر اپراتوری انتخاب نشده باشد، فقط `Import TXT` و `Paste Targets` در دسترس هستند.
2. اگر از فایل یا paste استفاده می‌کنید، در هر خط فقط یک `IPv4 CIDR` یا `IPv4` تکی قرار دهید. خط خالی و `#` نادیده گرفته می‌شود.
3. با `Pick Targets` فقط تارگت‌هایی را انتخاب کنید که واقعا می‌خواهید اسکن شوند. به صورت پیش‌فرض همه تارگت‌های لودشده انتخاب می‌شوند و داخل پنجره انتخاب هم گزینه `Select All` و `Deselect All` دارید. برنامه به صورت خودکار همه هاست‌های قابل اسکن داخل همان انتخاب را بررسی می‌کند و دیگر فیلد جداگانه‌ای برای host limit ندارد.
4. اگر نیاز خاصی ندارید، پورت را روی `53` نگه دارید.
5. در مرحله اسکن می‌توانید `UDP` یا `TCP` یا `BOTH` را انتخاب کنید و فیلد `StormDNS Domain` از همان مرحله روی tunnel score اثر دارد، پس قبل از اسکن آن را درست تنظیم کنید.
6. فیلد `Query Size` را خالی بگذارید مگر این که بخواهید اندازه payload پرس‌وجوهای StormDNS را کمتر کنید.
7. با `Score Threshold` مشخص می‌کنید چه resolverهایی برای مرحله StormDNS به اندازه کافی خوب محسوب شوند.
8. اول اسکن را اجرا کنید، بعد `Test StormDNS` را بزنید تا وارد صفحه جداگانه StormDNS شوید.
9. `StormDNS Key` را روی کلید رمزنگاری base64 متناسب با سرور خود تنظیم کنید. بدون کلید، MTU probeهای upload و download نمی‌توانند به سرور StormDNS احراز هویت کنند.
10. با `MTU Retries` تعداد دفعاتی را که هر مرحله MTU probe قبل از رد شدن یک resolver تلاش می‌کند تنظیم کنید.
11. اگر `Test Nearby IPs` را روی `Yes` بگذارید، هر IPv4 موفق اصلی یک بار دیگر بقیه IPهای همان `/24` را برای StormDNS امتحان می‌کند. IPهایی که از nearby پیدا می‌شوند دوباره expand نمی‌شوند.
12. روی صفحه اسکن از `Export` و روی صفحه StormDNS از `Export Passed` یا `Copy Passed` استفاده کنید.
13. اگر می‌خواهید همین تنظیمات دفعه بعد هم لود شوند، `Save Config` را بزنید.

نکته مهم:

- این ابزار برای پیدا کردن IPهای در دسترس و resolverهای کاندید است.
- تست StormDNS فقط روی resolverهایی اجرا می‌شود که در اسکن قبلی به `Score Threshold` رسیده باشند، نه روی همه هاست‌ها.
- `Score Threshold` تعیین می‌کند کدام resolverها وارد MTU probe سنگین‌تر StormDNS بشوند.
- رنج‌های Bogon (RFC1918، loopback، link-local، multicast، reserved، TEST-NET-* و غیره) هنگام expand کردن تارگت‌های اسکن به صورت خودکار نادیده گرفته می‌شوند.
- در صفحه StormDNS، گزینه `Export Passed` علاوه بر فرمت‌های `txt`/`csv`/`json`، یک فایل cache-log (سازگار با cache راه‌اندازی StormDNS) و یک فایل `client_resolvers.simple` (سازگار با فرمت resolver list کلاینت StormDNS) هم می‌سازد.
- مثبت بودن نتیجه در این برنامه باز هم تضمین کامل برای همه مسیرهای واقعی شبکه شما نیست.
