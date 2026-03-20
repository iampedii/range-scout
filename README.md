# range-scout

`range-scout` is a small TUI for:

- loading announced IPv4 prefixes for supported Iranian operators
- importing IPv4 CIDRs or single IPv4 addresses from a local `.txt` file
- pasting IPv4 CIDRs or single IPv4 addresses directly into the TUI
- choosing one or more ranges to scan
- checking which hosts on that range answer on DNS and allow recursion
- testing healthy recursive resolvers against a DNSTT domain after the scan
- exporting prefixes or scan results on demand as `txt`, `csv`, or `json`

## Screenshot

![range-scout screenshot](./screenshot.png)

## What It Does

1. Loads IPv4 scan targets for a selected operator, from a local `.txt` file, or from pasted text.
2. Lets you choose one or more CIDR ranges or single IPs from that loaded target set.
3. Scans hosts in those ranges over UDP, TCP, or both on a configurable port (default `53`).
4. Marks hosts as:
   - `dns reachable`
   - `recursive`
   - `stable` if both probe sites resolve successfully
5. Optionally runs a DNSTT pass only on healthy recursive resolvers from the latest scan:
   - `tunnel` when the TXT-based tunnel precheck succeeds
   - `e2e` when `dnstt-client` is available and the full tunnel works with your pubkey

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

1. Select an operator from the left sidebar if you want `Automatic API Fetch`. If you want to work manually, you can leave the operator unselected.
2. Choose `Automatic API Fetch`, `Import TXT`, or `Paste Targets` in `Load From`. Without an operator, only `Import TXT` and `Paste Targets` are available.
3. Click `Load Targets` to load operator prefixes, set `Import File` and click `Import TXT`, or click `Paste Targets` and paste directly into the modal.
4. Click `Scan Setup`.
5. Click `Pick Targets`, use the filter box if needed, and choose one or more CIDRs or single IPs. New target sets start with all targets selected, and the picker has `Select All` / `Deselect All` actions.
6. Set the port, protocol, recursion host, and probe hosts.
   Enter hostnames only, without `http://` or `https://`.
7. Click `Start Scan`.
8. If you want DNSTT validation, set `DNSTT Domain`. Leave `DNSTT Pubkey` empty for tunnel-only checks, or set it for full end-to-end validation. `E2E Port` defaults to `53`, and the final `SOCKS5 CONNECT` target is the resolver IP currently being tested on that port.
9. Leave `Query Size` empty unless you specifically want to pass `-mtu` to `dnstt-client` and your installed binary supports it.
10. Click `Test DNSTT` after the scan to open the dedicated DNSTT setup screen. The flow is `Load Targets -> DNS Scan -> DNSTT E2E`.
11. Click `Export` if you want to save scan results.
12. In target mode, `Save Targets` uses the `cidr-<label>` filename prefix.
13. In scanner mode before DNSTT, `Export` writes successful scan hits to `dns-scan-success-<label>` and completed-scan failures to `dns-scan-failures-<label>`.
14. After DNSTT finishes, `Export Passed` uses the `dnstt-scan-success-<label>` filename prefix.

## User Guidance

`range-scout` is mainly a tool for finding available IPs from operator ranges that answer DNS on the selected port and protocol.

How it works:

1. The app loads public IPv4 ranges for the selected operator, imports IPv4 CIDRs / single IPv4s from a local `.txt` file, or accepts pasted IPv4 CIDRs / single IPv4s.
2. You choose one or more CIDR ranges or imported / pasted single IPs that you want to scan.
3. The scanner probes each host in those ranges over `UDP`, `TCP`, or `BOTH` on the port you choose.
4. If a host answers DNS, the app records it as a candidate IP.
5. The app then checks whether recursion works and whether the resolver is stable by testing the probe hostnames you set.
6. If you want, the app can then test only the healthy recursive resolvers against your DNSTT domain.
7. You can export the discovered IPs after the scan finishes.

What to do:

1. Choose `Automatic API Fetch` if you want to load operator prefixes from a selected operator. If no operator is selected, use `Import TXT` or `Paste Targets`.
2. For file import or pasted text, put one IPv4 CIDR or IPv4 address on each line. Empty lines and `#` comments are ignored.
3. Load the targets first.
4. Use `Pick Targets` to limit the scan to the CIDRs or single IPs you want. All loaded targets start selected by default, and you can use `Select All` / `Deselect All` in the picker. The scan automatically covers all scannable hosts in the selected targets, so there is no separate host-limit field to tune.
5. Keep port `53` unless you specifically need another DNS port.
6. Use `UDP` for the normal DNS path, `TCP` if you want TCP-only testing, or `BOTH` if you want the scanner to try UDP first and then TCP.
7. Set `Recursion Host` to an outside hostname you want to use for the first recursive lookup check.
8. Set probe hosts that are accessible from the restricted network you care about. These probes are used to judge stable recursive resolution.
9. If you want DNSTT validation, set `DNSTT Domain`. Leave `DNSTT Pubkey` empty if you only want the tunnel precheck. Set `DNSTT Pubkey` if you want a full end-to-end DNSTT check.
10. `E2E Port` controls the final `SOCKS5 CONNECT` request used for the DNSTT e2e check. The app uses the scanned resolver IP as the host and this port as the destination.
11. Leave `Query Size` empty or `0` unless your `dnstt-client` build supports the `-mtu` flag.
12. Run the scan first, then use `Test DNSTT` to open the dedicated DNSTT screen and start the DNSTT stage there.
13. Export the results you want to keep. Export filenames are stage-specific:
    `cidr-<label>`, `dns-scan-success-<label>`, `dns-scan-failures-<label>`, and `dnstt-scan-success-<label>`.

Important:

- This tool helps you get available IPs and candidate DNS resolvers.
- DNSTT checks only run against healthy recursive resolvers from the latest scan.
- End-to-end DNSTT validation requires `dnstt-client` to be available in `PATH`, in the current directory, or next to the `range-scout` binary.
- The e2e check uses a no-auth SOCKS5 probe, matching the `findns` approach. The target is `<resolver IP>:<E2E Port>`, and success means a valid SOCKS5 `CONNECT` reply came back through the tunnel.
- `range-scout` also checks common release-style names such as `dnstt-client-linux`, `dnstt-client-darwin`, and `dnstt-client.exe`, and shows a warning in the scanner view when `Pubkey` is set but the client is missing.
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
- The scanner supports UDP, TCP, or BOTH DNS probes and defaults to port `53`
- DNSTT testing is a second-stage check over healthy recursive resolvers, not a raw host scan
- Leave `DNSTT Pubkey` empty if you only want the tunnel precheck

## راهنمای فارسی

`range-scout` در اصل ابزاری برای پیدا کردن IPهای در دسترس از رنج اپراتورها است؛ یعنی IPهایی که روی پورت و پروتکل انتخابی شما به DNS پاسخ می‌دهند.

نحوه کار:

1. برنامه می‌تواند تارگت‌ها را با `Automatic API Fetch` بگیرد، از `Import TXT` بخواند، یا با `Paste Targets` مستقیم از داخل TUI دریافت کند. اگر اپراتوری انتخاب نشده باشد، فقط `Import TXT` و `Paste Targets` در دسترس هستند.
2. شما یک یا چند رنج CIDR یا IP تکی را برای اسکن انتخاب می‌کنید.
3. اسکنر هر هاست را با `UDP` یا `TCP` یا `BOTH` روی پورتی که مشخص می‌کنید بررسی می‌کند.
4. اگر یک هاست به DNS پاسخ بدهد، به عنوان یک IP کاندید ثبت می‌شود.
5. بعد از آن برنامه بررسی می‌کند که recursion کار می‌کند یا نه و همچنین با استفاده از آدرس‌های probe که شما وارد می‌کنید پایداری resolver را می‌سنجد.
6. در صورت نیاز، فقط resolverهای recursive و stable با تنظیمات `DNSTT` تست می‌شوند.
7. بعد از تمام شدن اسکن می‌توانید IPهای پیدا شده را خروجی بگیرید.

چه کاری انجام بدهید:

1. ابتدا یکی از سه روش `Automatic API Fetch` یا `Import TXT` یا `Paste Targets` را انتخاب کنید. اگر اپراتوری انتخاب نشده باشد، فقط `Import TXT` و `Paste Targets` در دسترس هستند.
2. اگر از فایل یا paste استفاده می‌کنید، در هر خط فقط یک `IPv4 CIDR` یا `IPv4` تکی قرار دهید. خط خالی و `#` نادیده گرفته می‌شود.
3. با `Pick Targets` فقط تارگت‌هایی را انتخاب کنید که واقعا می‌خواهید اسکن شوند. به صورت پیش‌فرض همه تارگت‌های لودشده انتخاب می‌شوند و داخل پنجره انتخاب هم گزینه `Select All` و `Deselect All` دارید. برنامه به صورت خودکار همه هاست‌های قابل اسکن داخل همان انتخاب را بررسی می‌کند و دیگر فیلد جداگانه‌ای برای host limit ندارد.
4. اگر نیاز خاصی ندارید، پورت را روی `53` نگه دارید.
5. اگر تست معمول DNS می‌خواهید از `UDP` استفاده کنید، اگر فقط TCP می‌خواهید `TCP` را انتخاب کنید، و اگر می‌خواهید اول UDP و بعد TCP امتحان شود از `BOTH` استفاده کنید.
6. در فیلد `Recursion Host` فقط نام هاست را بدون `http://` یا `https://` وارد کنید و برای اولین تست recursive lookup از یک هاست بیرون از شبکه محدود استفاده کنید.
7. برای `Probe Host`ها نام‌هایی را وارد کنید که از داخل شبکه محدود مورد نظر شما واقعا قابل دسترس باشند. این آدرس‌ها برای تشخیص stable recursive resolution استفاده می‌شوند.
8. اگر تست `DNSTT` می‌خواهید، `DNSTT Domain` را وارد کنید. اگر فقط precheck می‌خواهید، `DNSTT Pubkey` را خالی بگذارید. اگر تست کامل end-to-end می‌خواهید، `DNSTT Pubkey` را هم وارد کنید.
9. فیلد `E2E Port` مشخص می‌کند برنامه در انتهای تست `SOCKS5 CONNECT` از چه پورتی روی همان resolver در حال تست استفاده کند. مقدار پیش‌فرض `53` است.
10. فیلد `Query Size` را خالی بگذارید مگر این که مطمئن باشید باینری `dnstt-client` شما از `-mtu` پشتیبانی می‌کند.
11. اول اسکن را اجرا کنید، بعد `Test DNSTT` را بزنید.
12. در پایان نتیجه‌ها را خروجی بگیرید.

نکته مهم:

- این ابزار برای پیدا کردن IPهای در دسترس و resolverهای کاندید است.
- تست `DNSTT` فقط روی resolverهای سالم مرحله قبل اجرا می‌شود، نه روی همه هاست‌ها.
- برای تست کامل end-to-end باید `dnstt-client` در `PATH`، پوشه فعلی، یا کنار باینری `range-scout` در دسترس باشد.
- تست end-to-end با یک پروب `SOCKS5` بدون auth انجام می‌شود و با رفتار `findns` هماهنگ است؛ مقصد آن هم `<resolver IP>:<E2E Port>` است و موفقیت یعنی یک پاسخ معتبر `SOCKS5 CONNECT` از داخل تانل برگشته باشد.
- برنامه نام‌های رایج فایل release مثل `dnstt-client-linux` و `dnstt-client-darwin` و `dnstt-client.exe` را هم پیدا می‌کند و اگر `Pubkey` تنظیم شده باشد ولی کلاینت پیدا نشود، در صفحه اسکن هشدار نشان می‌دهد.
- مثبت بودن نتیجه در این برنامه باز هم تضمین کامل برای همه مسیرهای واقعی شبکه شما نیست.
