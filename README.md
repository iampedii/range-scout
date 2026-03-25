# range-scout

`range-scout` is a small TUI for:

- loading announced IPv4 prefixes for supported Iranian operators
- importing IPv4 CIDRs or single IPv4 addresses from a local `.txt` file
- pasting IPv4 CIDRs or single IPv4 addresses directly into the TUI
- choosing one or more ranges to scan
- running a SlipNet-style UDP DNS compatibility scan on a configurable port
- opening a dedicated DNSTT stage after the scan for tunnel-only or end-to-end checks
- exporting targets, scan results, or DNSTT-passed results on demand as `txt`, `csv`, or `json`
- saving startup defaults to `config.json`

## Screenshot

![range-scout screenshot](./screenshot.png)

## What It Does

1. Loads IPv4 scan targets for a selected operator, from a local `.txt` file, or from pasted text.
2. Lets you choose one or more CIDR ranges or single IPs from that loaded target set.
3. Scans hosts in those ranges over UDP on a configurable port (default `53`).
4. Runs the same six SlipNet-style compatibility probes used by the app’s tunnel scoring flow and assigns each resolver a score from `0` to `6`.
5. Treats resolvers at or above the configured score threshold as DNSTT candidates.
6. Opens a dedicated DNSTT screen after the scan where you can:
   - leave `DNSTT Pubkey` empty for tunnel-only validation
   - set `DNSTT Pubkey` for full embedded DNSTT E2E validation
   - optionally set `SOCKS Username` and `SOCKS Password` if the remote SOCKS service requires authentication
   - optionally enable `Test Nearby IPs` to fan out one extra DNSTT pass across the rest of a successful resolver’s `/24`
7. Exports targets, scan successes, DNSTT-passed resolvers, and paired failure files when those stages complete.

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

## Release Builds

The git tag is the release source of truth. This matches a normal GitFlow
process:

- tag `v0.1.6` for a final release
- tag `v0.1.6-rcN` for a release candidate

To build a release artifact from the current tag:

```bash
make release
```

To build a Windows release artifact from the current tag:

```bash
make release-windows
```

Release builds are intentionally strict:

- `HEAD` must be exactly on a tag such as `v0.1.6` or `v0.1.6-rcN`
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
    "port": "53",
    "protocol": "UDP",
    "recursionHost": "google.com",
    "probeHost1": "github.com",
    "probeHost2": "example.com"
  },
  "dnsttConfig": {
    "domain": "t.example.com",
    "pubkey": "",
    "timeoutMS": "15000",
    "e2eTimeoutS": "20",
    "querySize": "",
    "scoreThreshold": "2",
    "e2eURL": "http://www.gstatic.com/generate_204",
    "testNearbyIPs": "No",
    "socksUsername": "",
    "socksPassword": ""
  }
}
```

Notes:

- `importFilePaths` may be a single string or an object map.
- The app writes UI field values back as strings when you use `Save Config`.
- `socksUsername` and `socksPassword` are optional. A SOCKS password without a username is invalid for DNSTT E2E.
- The current UI reads and writes these startup fields: `workers`, `timeoutMS`, `port`, `protocol`, `recursionHost`, `probeHost1`, `probeHost2`, `domain`, `pubkey`, `timeoutMS`, `e2eTimeoutS`, `querySize`, `scoreThreshold`, `e2eURL`, `testNearbyIPs`, `socksUsername`, and `socksPassword`.
- `protocol`, `recursionHost`, `probeHost1`, `probeHost2`, and `e2ePort` may still appear in `config.json` for compatibility with older saved configs. The current scanner workflow in the TUI uses UDP-only SlipNet-style compatibility probes.
- Use `"default"` to provide a fallback import path for any operator.
- Relative import paths are resolved relative to the `config.json` directory.
- `Save Config` keeps import paths relative to the config file when possible, so shared configs stay portable.
- The config file sets startup defaults; it does not auto-run imports, scans, or DNSTT.
- Ask bug reporters to include the version shown in the header, for example `v0.1.6`.

## Quick Guide

1. Select an operator from the left sidebar if you want `Automatic API Fetch`. If you want to work manually, you can leave the operator unselected.
2. Choose `Automatic API Fetch`, `Import TXT`, or `Paste Targets` in `Load From`. Without an operator, only `Import TXT` and `Paste Targets` are available.
3. Click `Load Targets` to load operator prefixes, set `Import File` and click `Import TXT`, or click `Paste Targets` and paste directly into the modal.
4. Click `Scan Setup`.
5. Click `Pick Targets`, use the filter box if needed, and choose one or more CIDRs or single IPs. New target sets start with all targets selected, and the picker has `Select All` / `Deselect All` actions.
6. Set `Workers`, `Timeout`, `Port`, `DNSTT Domain`, `Query Size`, and `Score Threshold`. The current scan UI uses UDP probes.
7. Click `Start Scan`.
8. Review the cached scan state in the details pane. If the app detected a transparent DNS proxy during the scan, it will warn you there.
9. Click `Test DNSTT` after the scan to open the dedicated DNSTT setup screen. The staged flow is `Load Targets -> DNS Scan -> DNSTT E2E`.
10. On the DNSTT screen:
    - leave `DNSTT Pubkey` empty for tunnel-only validation
    - set `DNSTT Pubkey` for full end-to-end validation
    - leave `Query Size` empty unless you specifically want smaller embedded DNSTT queries
    - keep `E2E URL` at `http://www.gstatic.com/generate_204` unless you need a different HTTP or HTTPS probe
    - set `SOCKS Username` and `SOCKS Password` only when the remote SOCKS service requires authentication
    - enable `Test Nearby IPs` if you want successful original IPv4 resolvers to trigger one extra `/24` DNSTT sweep
11. Click `Start DNSTT`.
12. Use `Export` on the scanner screen to save scan-stage successes, and use `Export Passed` on the DNSTT screen to save only DNSTT-passed resolvers plus a paired checked-failures file.
13. Use `Copy Passed` on the DNSTT screen if you want the passed resolver IPs in the clipboard without writing a file.
14. Use `Save Config` whenever you want the current startup defaults written back to `config.json`.

## User Guidance

`range-scout` is mainly a tool for finding IPv4 resolvers from operator ranges or custom target sets, then pushing only the best candidates through a second-stage DNSTT validation flow.

How it works:

1. The app loads public IPv4 ranges for the selected operator, imports IPv4 CIDRs / single IPv4s from a local `.txt` file, or accepts pasted IPv4 CIDRs / single IPv4s.
2. You choose one or more CIDR ranges or imported / pasted single IPs that you want to scan.
3. The scanner probes each host in those ranges over UDP on the port you choose.
4. If a host answers DNS, the app records it and runs the six SlipNet-style compatibility probes that feed the tunnel score.
5. The app treats resolvers at or above the current score threshold as DNSTT candidates.
6. If you want, the app can then test only those qualified resolvers against your DNSTT domain.
7. You can export scan-stage or DNSTT-stage outputs after the relevant stage finishes.

What to do:

1. Choose `Automatic API Fetch` if you want to load operator prefixes from a selected operator. If no operator is selected, use `Import TXT` or `Paste Targets`.
2. For file import or pasted text, put one IPv4 CIDR or IPv4 address on each line. Empty lines and `#` comments are ignored.
3. Load the targets first.
4. Use `Pick Targets` to limit the scan to the CIDRs or single IPs you want. All loaded targets start selected by default, and you can use `Select All` / `Deselect All` in the picker. The scan automatically covers all scannable hosts in the selected targets, so there is no separate host-limit field to tune.
5. Keep port `53` unless you specifically need another DNS port.
6. Set `DNSTT Domain` before the scan so the compatibility probes and tunnel-score workflow use the right domain.
7. Leave `Query Size` empty or `0` unless you specifically want smaller DNSTT queries.
8. Set `Score Threshold` to control how strict the scan should be before a resolver qualifies for the DNSTT stage.
9. Run the scan first, then use `Test DNSTT` to open the dedicated DNSTT screen and start the DNSTT stage there.
10. Leave `DNSTT Pubkey` empty if you only want the tunnel precheck. Set `DNSTT Pubkey` if you want a full end-to-end DNSTT check.
11. `E2E URL` is fetched through the local SOCKS5 proxy after the embedded DNSTT runtime starts. The request must return an HTTP status in the `2xx` or `3xx` range to pass.
12. If the remote SOCKS service requires authentication, fill in `SOCKS Username` and `SOCKS Password` on the DNSTT screen.
13. Enable `Test Nearby IPs` if you want each successful original IPv4 seed to trigger one extra DNSTT run across the rest of its `/24`. Nearby-discovered IPs do not expand again.
14. Export the results you want to keep. Export filenames are stage-specific:
    `cidr-<label>`, `dns-scan-success-<label>`, `dns-scan-failures-<label>`, and `dnstt-scan-success-<label>`.

Important:

- This tool helps you get available IPs and candidate DNS resolvers.
- DNSTT checks only run against resolvers that meet the current SlipNet compatibility score threshold from the latest scan.
- End-to-end DNSTT validation now uses an embedded runtime inside `range-scout`; no separate `dnstt-client` binary is required.
- The e2e check follows SlipNet's HTTP-style verification. After the embedded DNSTT runtime starts a local SOCKS5 proxy, the app fetches `E2E URL` through that proxy and treats HTTP `2xx` or `3xx` as success.
- Authenticated SOCKS5 E2E checks are supported through the optional `SOCKS Username` and `SOCKS Password` fields.
- `Export Passed` on the DNSTT screen writes both the passed resolver file and a paired checked-failures file. Scanner-stage failure export only happens when the full selected target set finished scanning.
- A positive result here still does not guarantee that every real-world client or route will behave the same way on your network.

## Shortcuts

- `p`: target view
- `d`: scan setup
- `f`: load from the selected source
- `s`: save or export current data
- `g`: start scan
- `t`: start DNSTT test from the latest scan
- `x`: stop the active scan or DNSTT task
- `Tab` / `Shift+Tab`: move focus
- `Esc`: leave an input field
- `q`: exit

## Notes

- IPv4 only
- Operator definitions are compiled into the app
- Files are saved only on demand
- The current TUI scanner uses UDP compatibility probes and defaults to port `53`
- DNSTT testing is a second-stage check over score-qualified resolvers, not a raw host scan
- Leave `DNSTT Pubkey` empty if you only want the tunnel precheck
- `Test Nearby IPs` expands only one extra `/24` pass from successful original IPv4 seeds
- `Save Config` updates startup defaults only; it does not start jobs automatically

## راهنمای فارسی

`range-scout` در اصل ابزاری برای پیدا کردن resolverهای IPv4 از رنج اپراتورها یا تارگت‌های دستی است و بعد resolverهای بهتر را وارد مرحله جداگانه `DNSTT` می‌کند.

نحوه کار:

1. برنامه می‌تواند تارگت‌ها را با `Automatic API Fetch` بگیرد، از `Import TXT` بخواند، یا با `Paste Targets` مستقیم از داخل TUI دریافت کند. اگر اپراتوری انتخاب نشده باشد، فقط `Import TXT` و `Paste Targets` در دسترس هستند.
2. شما یک یا چند رنج CIDR یا IP تکی را برای اسکن انتخاب می‌کنید.
3. اسکنر هر هاست را فعلا با `UDP` روی پورتی که مشخص می‌کنید بررسی می‌کند.
4. اگر یک هاست به DNS پاسخ بدهد، شش probe به سبک SlipNet روی آن اجرا می‌شود و یک tunnel score از `0` تا `6` می‌گیرد.
5. فقط resolverهایی که به `Score Threshold` برسند وارد مرحله `DNSTT` می‌شوند.
6. بعد از اسکن، یک صفحه جداگانه برای `DNSTT` باز می‌شود که در آن می‌توانید tunnel-only یا تست کامل end-to-end اجرا کنید.
7. بعد از تمام شدن هر مرحله می‌توانید خروجی همان مرحله را بگیرید.

چه کاری انجام بدهید:

1. ابتدا یکی از سه روش `Automatic API Fetch` یا `Import TXT` یا `Paste Targets` را انتخاب کنید. اگر اپراتوری انتخاب نشده باشد، فقط `Import TXT` و `Paste Targets` در دسترس هستند.
2. اگر از فایل یا paste استفاده می‌کنید، در هر خط فقط یک `IPv4 CIDR` یا `IPv4` تکی قرار دهید. خط خالی و `#` نادیده گرفته می‌شود.
3. با `Pick Targets` فقط تارگت‌هایی را انتخاب کنید که واقعا می‌خواهید اسکن شوند. به صورت پیش‌فرض همه تارگت‌های لودشده انتخاب می‌شوند و داخل پنجره انتخاب هم گزینه `Select All` و `Deselect All` دارید. برنامه به صورت خودکار همه هاست‌های قابل اسکن داخل همان انتخاب را بررسی می‌کند و دیگر فیلد جداگانه‌ای برای host limit ندارد.
4. اگر نیاز خاصی ندارید، پورت را روی `53` نگه دارید.
5. در اسکن فعلی برنامه از probeهای `UDP` استفاده می‌شود و فیلد `DNSTT Domain` از همان مرحله روی tunnel score اثر دارد، پس قبل از اسکن آن را درست تنظیم کنید.
6. فیلد `Query Size` را خالی بگذارید مگر این که بخواهید اندازه payload پرس‌وجوهای DNSTT را کمتر کنید.
7. با `Score Threshold` مشخص می‌کنید چه resolverهایی برای مرحله `DNSTT` به اندازه کافی خوب محسوب شوند.
8. اول اسکن را اجرا کنید، بعد `Test DNSTT` را بزنید تا وارد صفحه جداگانه `DNSTT` شوید.
9. اگر فقط precheck می‌خواهید، `DNSTT Pubkey` را خالی بگذارید. اگر تست کامل end-to-end می‌خواهید، `DNSTT Pubkey` را هم وارد کنید.
10. فیلد `E2E URL` مشخص می‌کند بعد از بالا آمدن پراکسی `SOCKS5` محلی، چه آدرس `HTTP/HTTPS` از داخل تانل درخواست شود. مقدار پیش‌فرض `http://www.gstatic.com/generate_204` است.
11. اگر SOCKS5 سمت سرور نیاز به احراز هویت دارد، `SOCKS Username` و `SOCKS Password` را در صفحه `DNSTT` وارد کنید.
12. اگر `Test Nearby IPs` را روی `Yes` بگذارید، هر IPv4 موفق اصلی یک بار دیگر بقیه IPهای همان `/24` را برای DNSTT امتحان می‌کند. IPهایی که از nearby پیدا می‌شوند دوباره expand نمی‌شوند.
13. روی صفحه اسکن از `Export` و روی صفحه DNSTT از `Export Passed` یا `Copy Passed` استفاده کنید.
14. اگر می‌خواهید همین تنظیمات دفعه بعد هم لود شوند، `Save Config` را بزنید.

نکته مهم:

- این ابزار برای پیدا کردن IPهای در دسترس و resolverهای کاندید است.
- تست `DNSTT` فقط روی resolverهایی اجرا می‌شود که در اسکن قبلی به `Score Threshold` رسیده باشند، نه روی همه هاست‌ها.
- برای تست کامل end-to-end دیگر به باینری جداگانه `dnstt-client` نیاز نیست و runtime به‌صورت embedded داخل برنامه اجرا می‌شود.
- تست end-to-end حالا مثل SlipNet با یک درخواست `HTTP/HTTPS` از داخل پراکسی `SOCKS5` محلی انجام می‌شود و پاسخ موفق یعنی کد وضعیت `2xx` یا `3xx` از `E2E URL` برگشته باشد.
- اگر سرویس SOCKS5 مقصد نیاز به username/password داشته باشد، برنامه از فیلدهای `SOCKS Username` و `SOCKS Password` برای handshake استفاده می‌کند.
- در صفحه `DNSTT`، گزینه `Export Passed` علاوه بر فایل resolverهای موفق، یک فایل failure برای resolverهای checked-but-failed هم می‌سازد.
- مثبت بودن نتیجه در این برنامه باز هم تضمین کامل برای همه مسیرهای واقعی شبکه شما نیست.
