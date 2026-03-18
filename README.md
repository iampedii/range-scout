# range-scout

`range-scout` is a small TUI for:

- fetching announced IPv4 prefixes for supported Iranian operators from RIPEstat
- choosing one or more ranges to scan
- checking which hosts on that range answer on DNS and allow recursion
- exporting prefixes or scan results on demand as `txt`, `csv`, or `json`

## Screenshot

![range-scout screenshot](./screenshot.png)

## What It Does

1. Fetches IPv4 prefixes for a selected operator from RIPEstat.
2. Lets you choose one or more CIDR ranges from that operator.
3. Scans hosts in those ranges over UDP, TCP, or both on a configurable port (default `53`).
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
4. Click `Pick Range`, use the filter box if needed, and choose one or more CIDRs.
5. Set the port, protocol, and probe URLs.
   Choose sites that are reachable in your network.
6. Click `Start Scan`.
7. Click `Export` if you want to save scan results.
8. In prefix mode, click `Save` if you want to save prefixes.

## User Guidance

`range-scout` is mainly a tool for finding available IPs from operator ranges that answer DNS on the selected port and protocol.

How it works:

1. The app fetches public IPv4 ranges for the selected operator from RIPEstat.
2. You choose one or more CIDR ranges that you want to scan.
3. The scanner probes each host in those ranges over `UDP`, `TCP`, or `BOTH` on the port you choose.
4. If a host answers DNS, the app records it as a candidate IP.
5. The app then checks whether recursion works and whether the resolver is stable by testing the probe hostnames you set.
6. You can export the discovered IPs after the scan finishes.

What to do:

1. Use `Fetch` first.
2. Use `Pick Range` to limit the scan to the CIDRs you want.
3. Keep port `53` unless you specifically need another DNS port.
4. Use `UDP` for the normal DNS path, `TCP` if you want TCP-only testing, or `BOTH` if you want the scanner to try UDP first and then TCP.
5. Set probe URLs that are accessible through your network. These probes are used to judge stable recursive resolution.
6. Run the scan and export the results you want to keep.

Important:

- This tool helps you get available IPs and candidate DNS resolvers.
- A positive result here does not mean the resolver is fully usable end to end in your real setup.
- After you collect IPs here, you should still test them end to end with tools such as [findns](https://github.com/SamNet-dev/findns).

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
- The scanner supports UDP, TCP, or BOTH DNS probes and defaults to port `53`

## راهنمای فارسی

`range-scout` در اصل ابزاری برای پیدا کردن IPهای در دسترس از رنج اپراتورها است؛ یعنی IPهایی که روی پورت و پروتکل انتخابی شما به DNS پاسخ می‌دهند.

نحوه کار:

1. برنامه رنج‌های عمومی IPv4 اپراتور انتخاب‌شده را از RIPEstat می‌گیرد.
2. شما یک یا چند رنج CIDR را برای اسکن انتخاب می‌کنید.
3. اسکنر هر هاست را با `UDP` یا `TCP` یا `BOTH` روی پورتی که مشخص می‌کنید بررسی می‌کند.
4. اگر یک هاست به DNS پاسخ بدهد، به عنوان یک IP کاندید ثبت می‌شود.
5. بعد از آن برنامه بررسی می‌کند که recursion کار می‌کند یا نه و همچنین با استفاده از آدرس‌های probe که شما وارد می‌کنید پایداری resolver را می‌سنجد.
6. بعد از تمام شدن اسکن می‌توانید IPهای پیدا شده را خروجی بگیرید.

چه کاری انجام بدهید:

1. اول `Fetch` را بزنید.
2. با `Pick Range` فقط رنج‌هایی را انتخاب کنید که واقعا می‌خواهید اسکن شوند.
3. اگر نیاز خاصی ندارید، پورت را روی `53` نگه دارید.
4. اگر تست معمول DNS می‌خواهید از `UDP` استفاده کنید، اگر فقط TCP می‌خواهید `TCP` را انتخاب کنید، و اگر می‌خواهید اول UDP و بعد TCP امتحان شود از `BOTH` استفاده کنید.
5. برای Probe آدرس‌هایی را وارد کنید که از داخل شبکه شما واقعا قابل دسترس باشند. این آدرس‌ها برای تشخیص stable recursive resolution استفاده می‌شوند.
6. اسکن را اجرا کنید و در پایان نتیجه‌ها را خروجی بگیرید.

نکته مهم:

- این ابزار برای پیدا کردن IPهای در دسترس و resolverهای کاندید است.
- مثبت بودن نتیجه در این برنامه به معنی سالم بودن کامل resolver در سناریوی واقعی شما نیست.
- بعد از پیدا کردن IPها در اینجا، همچنان باید آن‌ها را به صورت end-to-end با ابزارهایی مثل [findns](https://github.com/SamNet-dev/findns) تست کنید.
