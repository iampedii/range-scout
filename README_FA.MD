# range-scout

`range-scout` یک TUI کوچک برای موارد زیر است:

- لود کردن پیشوندهای IPv4 اعلام‌شده برای اپراتورهای ایرانی پشتیبانی‌شده
- وارد کردن IPv4 CIDR یا آدرس‌های تکی از یک فایل `.txt` محلی
- الصاق مستقیم IPv4 CIDR یا آدرس‌های تکی داخل TUI
- انتخاب یک یا چند رنج برای اسکن
- اجرای اسکن سازگاری UDP DNS به سبک SlipNet روی پورت قابل تنظیم
- باز کردن صفحه جداگانه StormDNS بعد از اسکن برای تایید resolver با MTU probe
- خروجی گرفتن از تارگت‌ها، نتایج اسکن، یا resolverهای تایید‌شده StormDNS به‌صورت `txt`، `csv`، یا `json`
- ذخیره تنظیمات پیش‌فرض در `config.json`

## اسکرین‌شات

![range-scout screenshot](./screenshot.png)

## نحوه کار

`range-scout` در اصل ابزاری برای پیدا کردن resolverهای IPv4 از رنج اپراتورها یا تارگت‌های دستی است و بعد resolverهای بهتر را وارد مرحله جداگانه StormDNS می‌کند.

1. برنامه می‌تواند تارگت‌ها را با `Automatic API Fetch` بگیرد، از `Import TXT` بخواند، یا با `Paste Targets` مستقیم از داخل TUI دریافت کند. اگر اپراتوری انتخاب نشده باشد، فقط `Import TXT` و `Paste Targets` در دسترس هستند.
2. شما یک یا چند رنج CIDR یا IP تکی را برای اسکن انتخاب می‌کنید.
3. اسکنر هر هاست را با پروتکل انتخابی `UDP` یا `TCP` یا `BOTH` روی پورتی که مشخص می‌کنید بررسی می‌کند.
4. اگر یک هاست به DNS پاسخ بدهد، شش probe به سبک SlipNet روی آن اجرا می‌شود و یک tunnel score از `0` تا `6` می‌گیرد.
5. فقط resolverهایی که به `Score Threshold` برسند وارد مرحله StormDNS می‌شوند.
6. بعد از اسکن، یک صفحه جداگانه برای StormDNS باز می‌شود که در آن می‌توانید `StormDNS Domain` و `StormDNS Key` را تنظیم کنید و MTU probe های upload و download را روی resolverهای واجد شرایط اجرا کنید — دقیقاً مثل چیزی که کلاینت StormDNS هنگام راه‌اندازی انجام می‌دهد.
7. بعد از تمام شدن هر مرحله می‌توانید خروجی همان مرحله را بگیرید. StormDNS علاوه بر فرمت‌های `txt`/`csv`/`json`، یک فایل cache-log و یک فایل `client_resolvers.simple` هم می‌سازد که مستقیماً توسط کلاینت StormDNS قابل استفاده هستند.

## ساخت

مخزن toolchain گو را روی `1.24.1` پین کرده تا بیلدها تکرارپذیر باشند. اگر نسخه محلی `go` شما قدیمی‌تر باشد، گو به‌صورت خودکار toolchain پین‌شده را دانلود می‌کند.

```bash
make build
```

این دستور یک باینری توسعه محلی در `./range-scout` می‌سازد.

برای ساختن artifact قابل توزیع برای پلتفرم فعلی:

```bash
make build-dist
```

برای ساختن بیلد تستر ویندوز:

```bash
make build-windows
```

این دستور `dist/range-scout-windows-amd64.exe` را می‌نویسد.

برای ساختن ماتریس کامل پیش‌فرض چند-پلتفرمی:

```bash
make build-all
```

این دستور artifact های جداگانه‌ای در `dist/` برای موارد زیر می‌نویسد:

- `darwin/amd64`
- `darwin/arm64`
- `linux/amd64`
- `linux/arm64`
- `windows/amd64`
- `windows/arm64`

در صورت نیاز می‌توانید ماتریس را override کنید:

```bash
make build-all BUILD_OSES="linux windows" BUILD_ARCHES="amd64"
```

## بیلدهای رسمی

تگ گیت منبع اصلی برای نسخه‌بندی است. این با فرایند معمول GitFlow مطابقت دارد:

- تگ `v0.8.0` برای نسخه نهایی
- تگ `v0.8.0-rcN` برای release candidate

برای ساختن artifact رسمی از تگ فعلی:

```bash
make release
```

برای ساختن artifact رسمی ویندوز از تگ فعلی:

```bash
make release-windows
```

برای ساختن artifact های رسمی برای ماتریس کامل پیش‌فرض از تگ فعلی:

```bash
make release-all
```

بیلدهای رسمی به صورت عمدی سخت‌گیرانه هستند:

- `HEAD` باید دقیقاً روی یک تگ مثل `v0.8.0` یا `v0.8.0-rcN` باشد
- worktree گیت باید تمیز باشد

اگر این بررسی‌ها پاس شوند، نام فایل artifact دقیقاً با تگ نسخه مطابقت خواهد داشت.

نسخه نمایش‌داده‌شده در هدر برنامه یک ثابت دستی در `ui.go` است (`uiVersionLabel`). قبل از زدن تگ جدید آن را به‌روز کنید تا گزارش‌های اشکال و artifact های نسخه همسو بمانند.

## اجرا

```bash
./range-scout
```

برای اجرای یک‌باره بدون بیلد:

```bash
make run
```

## تنظیمات

می‌توانید یک `config.json` اختیاری کنار پروژه قرار دهید و `range-scout` آن را هنگام راه‌اندازی لود می‌کند. برنامه ابتدا در دایرکتوری کاری جاری جستجو می‌کند. اگر آنجا config‌ای نباشد، کنار باینری `range-scout` هم بررسی می‌کند.

مثال:

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

نکات:

- `importFilePaths` می‌تواند یک رشته تکی یا یک object map باشد.
- برنامه مقادیر فیلدهای UI را هنگام استفاده از `Save Config` به‌صورت رشته می‌نویسد.
- `stormdnsConfig.key` باید کلید رمزنگاری base64 متناسب با سرور StormDNS شما باشد.
- `Save Config` در حال حاضر `workers`، `timeoutMS`، `port`، و `protocol` را در `scanConfig`، و `domain`، `key`، `timeoutMS`، `querySize`، `mtuRetries`، `scoreThreshold`، و `testNearbyIPs` را در `stormdnsConfig` می‌نویسد.
- از `"default"` برای ارائه یک مسیر import پشتیبان برای هر اپراتور استفاده کنید.
- مسیرهای import نسبی نسبت به دایرکتوری `config.json` حل می‌شوند.
- `Save Config` در صورت امکان مسیرهای import را نسبت به فایل config نگه می‌دارد تا config های مشترک قابل حمل بمانند.
- فایل config تنظیمات پیش‌فرض راه‌اندازی را تعیین می‌کند؛ import، اسکن، یا تایید StormDNS را به‌صورت خودکار اجرا نمی‌کند.
- رنج‌های Bogon (RFC1918، loopback، link-local، multicast، reserved، TEST-NET-* و غیره) هنگام expand کردن تارگت‌های اسکن به صورت خودکار نادیده گرفته می‌شوند.
- از bug reporterها بخواهید نسخه نمایش‌داده‌شده در هدر را وارد کنند، مثلاً `v0.8.0`.

## راهنمای سریع

1. اگر می‌خواهید `Automatic API Fetch` داشته باشید، یک اپراتور از sidebar چپ انتخاب کنید. اگر می‌خواهید به صورت دستی کار کنید، می‌توانید اپراتور را انتخاب نشده بگذارید.
2. در `Load From` یکی از `Automatic API Fetch`، `Import TXT`، یا `Paste Targets` را انتخاب کنید. بدون اپراتور، فقط `Import TXT` و `Paste Targets` در دسترس هستند.
3. برای لود پیشوندهای اپراتور روی `Load Targets` کلیک کنید، یا `Import File` را تنظیم کنید و روی `Import TXT` کلیک کنید، یا روی `Paste Targets` کلیک کنید و مستقیم داخل modal paste کنید.
4. روی `Scan Setup` کلیک کنید.
5. روی `Pick Targets` کلیک کنید، در صورت نیاز از فیلتر استفاده کنید، و یک یا چند CIDR یا IP تکی انتخاب کنید. مجموعه تارگت‌های جدید با همه تارگت‌ها انتخاب‌شده شروع می‌شوند و picker دارای اکشن‌های `Select All` / `Deselect All` است.
6. `Workers`، `Timeout`، `Port`، `Protocol`، `StormDNS Domain`، `Query Size`، و `Score Threshold` را تنظیم کنید. `Protocol` می‌تواند `UDP`، `TCP`، یا `BOTH` باشد.
7. روی `Start Scan` کلیک کنید.
8. وضعیت اسکن کش‌شده را در پنل جزئیات بررسی کنید. اگر برنامه حین اسکن یک DNS proxy شفاف شناسایی کرده باشد، آنجا به شما هشدار می‌دهد.
9. بعد از اسکن روی `Test StormDNS` کلیک کنید تا صفحه جداگانه StormDNS باز شود. جریان مراحل این است: `Load Targets -> DNS Scan -> StormDNS Verify`.
10. در صفحه StormDNS:
    - `StormDNS Domain` را روی subdomain‌ای که به سرور StormDNS خود delegate کرده‌اید تنظیم کنید
    - `StormDNS Key` را روی کلید رمزنگاری base64 متناسب با سرور خود تنظیم کنید
    - `Query Size` را خالی بگذارید مگر این که بخواهید probe query های کوچک‌تری داشته باشید
    - `Score Threshold` را برای کنترل سختگیری اسکن قبل از واجد شرایط بودن یک resolver تنظیم کنید
    - `Test Nearby IPs` را فعال کنید اگر می‌خواهید هر resolver موفق به یک sweep از `/24` گسترش یابد
11. روی `Start StormDNS` کلیک کنید.
12. از `Export` در صفحه اسکنر برای ذخیره موفقیت‌های مرحله اسکن استفاده کنید. از `Export Passed` در صفحه StormDNS برای ذخیره resolverهای تایید‌شده در `txt`/`csv`/`json`، به‌علاوه فایل‌های cache-log و `client_resolvers.simple` بومی StormDNS استفاده کنید.
13. از `Copy Passed` در صفحه StormDNS استفاده کنید اگر می‌خواهید IP های resolver تایید‌شده در clipboard باشند.
14. هروقت می‌خواهید تنظیمات پیش‌فرض راه‌اندازی جاری را در `config.json` بنویسید از `Save Config` استفاده کنید.

## راهنمای کاربر

`range-scout` عمدتاً ابزاری برای پیدا کردن resolverهای IPv4 از رنج‌های اپراتور یا مجموعه تارگت‌های دستی است و سپس فقط بهترین کاندیداها را از طریق جریان تایید StormDNS دومرحله‌ای عبور می‌دهد.

چه کاری انجام بدهید:

1. `Automatic API Fetch` را انتخاب کنید اگر می‌خواهید پیشوندهای اپراتور را از یک اپراتور انتخاب‌شده لود کنید. اگر اپراتوری انتخاب نشده، از `Import TXT` یا `Paste Targets` استفاده کنید.
2. برای import فایل یا متن paste‌شده، یک IPv4 CIDR یا آدرس IPv4 در هر خط قرار دهید. خطوط خالی و کامنت‌های `#` نادیده گرفته می‌شوند.
3. ابتدا تارگت‌ها را لود کنید.
4. از `Pick Targets` برای محدود کردن اسکن به CIDRها یا IPهای تکی که می‌خواهید استفاده کنید. همه تارگت‌های لودشده به صورت پیش‌فرض انتخاب‌شده شروع می‌شوند و می‌توانید در picker از `Select All` / `Deselect All` استفاده کنید. اسکن به صورت خودکار همه هاست‌های قابل اسکن در تارگت‌های انتخاب‌شده را پوشش می‌دهد، پس فیلد جداگانه host-limit برای تنظیم وجود ندارد.
5. پورت `53` را نگه دارید مگر این که به پورت DNS دیگری نیاز خاص داشته باشید.
6. `StormDNS Domain` را قبل از اسکن تنظیم کنید تا probe های سازگاری و جریان tunnel-score از domain درستی استفاده کنند.
7. `Query Size` را خالی یا `0` بگذارید مگر این که بخواهید probe query های StormDNS کوچک‌تری داشته باشید.
8. `Score Threshold` را برای کنترل سختگیری اسکن قبل از واجد شرایط بودن یک resolver برای مرحله StormDNS تنظیم کنید.
9. ابتدا اسکن را اجرا کنید، سپس از `Test StormDNS` برای باز کردن صفحه جداگانه StormDNS و شروع مرحله StormDNS استفاده کنید.
10. `StormDNS Key` را روی کلید رمزنگاری base64 متناسب با سرور خود تنظیم کنید. بدون کلید، MTU probe های upload و download نمی‌توانند به سرور StormDNS احراز هویت کنند.
11. `MTU Retries` را برای تنظیم تعداد دفعاتی که هر مرحله MTU probe قبل از رد شدن یک resolver تلاش می‌کند تنظیم کنید.
12. `Test Nearby IPs` را فعال کنید اگر می‌خواهید هر seed IPv4 موفق اصلی یک StormDNS اضافه در سراسر `/24` آن را trigger کند. IPهای کشف‌شده از nearby دوباره expand نمی‌شوند.
13. نتایجی را که می‌خواهید نگه دارید export کنید. نام فایل‌های export مرحله-محور هستند:
    `cidr-<label>`، `dns-scan-success-<label>`، `dns-scan-failures-<label>`، و `stormdns-scan-success-<label>`.

نکته مهم:

- این ابزار برای پیدا کردن IPهای در دسترس و resolverهای کاندید است.
- تست StormDNS فقط روی resolverهایی اجرا می‌شود که در اسکن قبلی به `Score Threshold` رسیده باشند، نه روی همه هاست‌ها.
- `Score Threshold` تعیین می‌کند کدام resolverها وارد MTU probe سنگین‌تر StormDNS بشوند.
- رنج‌های Bogon (RFC1918، loopback، link-local، multicast، reserved، TEST-NET-* و غیره) هنگام expand کردن تارگت‌های اسکن به صورت خودکار نادیده گرفته می‌شوند.
- در صفحه StormDNS، گزینه `Export Passed` علاوه بر فرمت‌های `txt`/`csv`/`json`، یک فایل cache-log (سازگار با cache راه‌اندازی StormDNS) و یک فایل `client_resolvers.simple` (سازگار با فرمت resolver list کلاینت StormDNS) هم می‌سازد.
- مثبت بودن نتیجه در این برنامه باز هم تضمین کامل برای همه مسیرهای واقعی شبکه شما نیست.

## میانبرها

- `p`: نمای تارگت
- `d`: تنظیم اسکن
- `f`: لود از منبع انتخاب‌شده
- `s`: ذخیره یا export داده‌های جاری
- `g`: شروع اسکن
- `t`: شروع تست StormDNS از آخرین اسکن
- `x`: توقف اسکن یا وظیفه StormDNS فعال
- `Tab` / `Shift+Tab`: جابجایی focus
- `Esc`: خروج از یک فیلد ورودی
- `q`: خروج

## نکات

- فقط IPv4
- تعریف اپراتورها داخل برنامه کامپایل شده‌اند
- فایل‌ها فقط در صورت درخواست ذخیره می‌شوند
- اسکنر TUI از probe های سازگاری `UDP`، `TCP`، و `BOTH` پشتیبانی می‌کند و پیش‌فرض آن پورت `53` است
- تایید StormDNS یک بررسی دومرحله‌ای روی resolverهای واجد امتیاز است، نه یک اسکن هاست خام
- `Score Threshold` تعیین می‌کند کدام resolverها وارد MTU probe سنگین‌تر StormDNS بشوند
- `Test Nearby IPs` فقط یک pass اضافه `/24` از seedهای IPv4 موفق اصلی گسترش می‌دهد
- رنج‌های Bogon (RFC1918، loopback، link-local، multicast، reserved، TEST-NET-* و غیره) هنگام expand کردن تارگت‌های اسکن به صورت خودکار نادیده گرفته می‌شوند
- Resolverهای تایید‌شده همچنین در فرمت‌های بومی StormDNS نوشته می‌شوند: یک فایل cache-log (سازگار با cache راه‌اندازی StormDNS) و `client_resolvers.simple` (سازگار با فرمت resolver list کلاینت StormDNS)
- `Save Config` فقط تنظیمات پیش‌فرض راه‌اندازی را به‌روز می‌کند؛ کارها را به صورت خودکار شروع نمی‌کند

## کد شخص ثالث

این پروژه یک نسخه vendor‌شده از [StormDNS](https://github.com/nullroute1970/StormDNS)
را در `third_party/stormdns/` بسته‌بندی کرده که فقط برای مرحله تایید resolver استفاده می‌شود.
برای commit پین‌شده upstream و patch های اعمال‌شده فایل `third_party/stormdns/SYNC.md` را ببینید،
و برای مجوز MIT upstream فایل `third_party/stormdns/LICENSE` را ببینید.
