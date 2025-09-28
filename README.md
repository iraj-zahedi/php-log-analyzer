# تحلیلگر جامع لاگ سرور با PHP
[اسکرین شات 1](https://raw.githubusercontent.com/iraj-zahedi/php-log-analyzer/refs/heads/main/log-analyzer1.png)

[اسکرین شات 2](https://raw.githubusercontent.com/iraj-zahedi/php-log-analyzer/refs/heads/main/log-analyzer2.png)

[اسکرین شات 3](https://raw.githubusercontent.com/iraj-zahedi/php-log-analyzer/refs/heads/main/log-analyzer3.png)

[اسکرین شات 4](https://raw.githubusercontent.com/iraj-zahedi/php-log-analyzer/refs/heads/main/log-analyzer4.png)

ابزاری قدرتمند، سبک و **تک-فایلی** برای تحلیل آنی لاگ‌های سرور لینوکس. این اسکریپت به شما کمک می‌کند تا حملات، خطاهای سیستمی و رویدادهای امنیتی را به سرعت شناسایی کرده و از طریق یک داشبورد گرافیکی و تعاملی، وضعیت سرور خود را مانیتور کنید.

این ابزار بدون نیاز به دیتابیس، کامپوزر یا هرگونه وابستگی خارجی کار می‌کند و برای مدیران سرور، توسعه‌دهندگان وب و متخصصان امنیت ایده‌آل است.


---

## ✨ ویژگی‌های کلیدی

### ۱. داشبورد تعاملی و هوشمند
-   **داشبورد مبتنی بر تب:** تفکیک گزارش‌ها در بخش‌های "رویدادهای زنده"، "آمارها" و "مهاجمان برتر".
-   **جستجوی سراسری قدرتمند:** جستجوی یک عبارت (مانند IP یا پیام خطا) در **تمام** فایل‌های لاگ به صورت آنی.
-   **نمودارهای گرافیکی (Google Charts):** نمایش تصویری آمارها، از جمله نقشه جغرافیایی حملات، رویدادها در ۲۴ ساعت گذشته و درصد انواع رویدادها.
-   **لینک‌های هوشمند:** امکان کلیک مستقیم بر روی IP مهاجمان برای مشاهده تمام فعالیت‌های ثبت‌شده از آن‌ها.
-   **فیلترسازی پیشرفته:** فعال یا غیرفعال کردن نمایش انواع خاصی از لاگ‌ها.

### ۲. تحلیل جامع امنیتی
-   **وب‌سرور (Apache):** شناسایی خطاهای دسترسی، مشکلات SSL و خطاهای مربوط به PHP-FPM.
-   **فایروال وب (ModSecurity):** نمایش حملات شناسایی‌شده و مسدود شده توسط WAF.
-   **سرویس‌ها (SSH, Email):** تشخیص حملات Brute-Force به سرویس‌های SSH و سرور ایمیل (Dovecot/Exim).
-   **نرم‌افزار امنیتی (Fail2ban):** مانیتور کردن عملکرد Fail2ban و شناسایی IPهای مسدود یا آزاد شده و خطاهای اجرایی آن.
-   **حملات وب:** شناسایی تلاش برای حملات رایج مانند SQL Injection, XSS, Path Traversal و Command Injection.

### ۳. مانیتورینگ سلامت سیستم
-   **خطاهای بحرانی کرنل:** شناسایی Kernel Panic و خطاهای سخت‌افزاری (I/O) که نشان‌دهنده مشکلات جدی سرور هستند.
-   **مدیریت منابع:** تشخیص مشکلات کمبود حافظه (OOM Killer) و فرآیندهایی که به اجبار متوقف شده‌اند.
-   **رویدادهای سیستمی:** ثبت ری‌استارت‌های سرور و استفاده از دستورات با دسترسی بالا (Sudo).

---

## 🚀 نصب و راه‌اندازی

نصب این ابزار بسیار ساده است. کافیست یک فایل را آپلود و پیکربندی کنید.

### پیش‌نیازها
-   سرور لینوکس (VPS یا اختصاصی).
-   PHP نسخه ۷.۰ یا بالاتر.
-   دسترسی به ترمینال سرور (SSH).

### مراحل نصب

1.  **آپلود اسکریپت:** فایل اسکریپت (`log_analyzer.php`) را در مسیر دلخواه خود روی سرور آپلود کنید (مثلاً در یک ساب‌دامین مانند `analyzer.yourdomain.com`).

2.  **پیکربندی مسیر لاگ‌ها:** اسکریپت را باز کرده و در بخش پیکربندی، آرایه `$logFiles` را متناسب با سیستم‌عامل سرور خود ویرایش کنید. **خطوط مربوط به لاگ‌های موجود در سرور خود را از حالت کامنت خارج کنید:**
    ```php
    $logFiles = [
        // مثال برای سرور CentOS/RHEL با آپاچی
        '/var/log/httpd/access_log',
        '/var/log/httpd/error_log',
        '/var/log/secure',
        '/var/log/messages',
        '/var/log/maillog',
        '/var/log/fail2ban.log',

        // مثال برای سرور Debian/Ubuntu با آپاچی
        // '/var/log/apache2/access.log',
        // '/var/log/apache2/error.log',
        // '/var/log/auth.log',
        // '/var/log/syslog',
    ];
    ```

3.  **تنظیم دسترسی‌ها (مهم‌ترین مرحله):**
    کاربر وب‌سرور شما (معمولاً `apache` در CentOS یا `www-data` در Ubuntu) باید اجازه خواندن این فایل‌ها را داشته باشد. دستورات زیر را از طریق SSH اجرا کنید:
    
    > **نکته:** برای نصب `setfacl` در صورت عدم وجود، از `sudo yum install acl` یا `sudo apt-get install acl` استفاده کنید.

    ```bash
    # مثال برای CentOS/RHEL (کاربر apache)
    sudo setfacl -m u:apache:r /var/log/messages /var/log/secure /var/log/maillog /var/log/fail2ban.log

    # مثال برای Debian/Ubuntu (کاربر www-data)
    sudo setfacl -m u:www-data:r /var/log/syslog /var/log/auth.log /var/log/mail.log /var/log/fail2ban.log
    ```

4.  **🔒 امن‌سازی اسکریپت (بسیار مهم):**
    این اسکریپت اطلاعات حساسی را نمایش می‌دهد. **حتماً** دسترسی به آن را با رمز عبور محدود کنید.
    -   یک فایل `.htaccess` در کنار اسکریپت خود ایجاد کرده و محتوای زیر را در آن قرار دهید (مسیر فایل رمز را اصلاح کنید):
        ```apache
        AuthType Basic
        AuthName "Restricted Area"
        AuthUserFile /path/to/your/.htpasswd
        Require valid-user
        ```
    -   با دستور `htpasswd` یک فایل رمز عبور بسازید (your_username را با نام کاربری دلخواه جایگزین کنید):
        ```bash
        htpasswd -c /path/to/your/.htpasswd your_username
        ```

5.  **مشاهده گزارش:** فایل PHP را در مرورگر خود باز کرده و با نام کاربری و رمز عبوری که ساختید، وارد شوید.

---

### درباره توسعه‌دهنده

این افزونه توسط [ایرج زاهدی](https://blueserver.ir/author/iraj-zahedi)، بنیان‌گذار و متخصص فنی زیرساخت در [بلوسرور](https://blueserver.ir/)، توسعه داده شده است. تخصص ما در ارائه راهکارهای میزبانی بهینه و امن برای وردپرس است و این ابزار حاصل تجربه ما در این زمینه است.

برای آشنایی کامل‌تر با این ابزار، مطالعه مقاله زیر را در سایت بلوسرور توصیه می‌کنیم:
[تحلیلگر لاگ سرور با PHP – ابزار متن‌باز بلوسرور برای امنیت و مانیتورینگ](https://blueserver.ir/blueserver-php-log-analyzer)





A powerful, lightweight, **single-file** PHP script for real-time analysis of Linux server logs. This tool helps you quickly identify attacks, system errors, and security events through an interactive, graphical dashboard.

This analyzer works without a database, Composer, or any external dependencies, making it ideal for server administrators, web developers, and security specialists.

---

## ✨ Key Features

### 1. Interactive & Smart Dashboard
-   **Tab-based Interface:** Cleanly separates reports into "Live Events," "Statistics," and "Top Attackers."
-   **Powerful Global Search:** Instantly search for any term (like an IP address or error message) across **all** configured log files.
-   **Graphical Charts (Google Charts):** Visualize your data, including a geo-map of attack origins, an event timeline for the last 24 hours, and a breakdown of event types.
-   **Smart, Clickable Links:** Click directly on an attacker's IP to view a comprehensive list of all their logged activities.
-   **Advanced Filtering:** Easily toggle the visibility of specific log types to focus on what matters.

### 2. Comprehensive Security Analysis
-   **Web Server (Apache):** Detects access errors, SSL negotiation issues, and PHP-FPM-related faults.
-   **Web Application Firewall (ModSecurity):** Displays attacks that have been identified and blocked by the WAF.
-   **Services (SSH, Email):** Identifies Brute-Force attacks against SSH and email servers (Dovecot/Exim).
-   **Security Software (Fail2ban):** Monitors Fail2ban's performance, showing banned/unbanned IPs and any operational errors.
-   **Web Attacks:** Detects common attack attempts like SQL Injection, XSS, Path Traversal, and Command Injection.

### 3. System Health Monitoring
-   **Critical Kernel Errors:** Identifies Kernel Panics and hardware I/O errors that may indicate serious server issues.
-   **Resource Management:** Detects out-of-memory problems (OOM Killer) and processes that were forcibly terminated.
-   **System Events:** Logs server reboots and the use of privileged commands (Sudo).

---

## 🚀 Installation & Setup

Setup is incredibly simple. Just upload and configure a single file.

### Prerequisites
-   A Linux server (VPS or Dedicated).
-   PHP version 7.0 or higher.
-   SSH access to the server.

### Installation Steps

1.  **Upload the Script:** Upload the `log_analyzer.php` file to your desired path on the server (e.g., within a subdomain like `analyzer.yourdomain.com`).

2.  **Configure Log Paths:** Open the script and, in the configuration section, edit the `$logFiles` array to match your server's operating system. **Uncomment the lines corresponding to the logs that exist on your server:**
    ```php
    $logFiles = [
        // Example for a CentOS/RHEL server with Apache
        '/var/log/httpd/access_log',
        '/var/log/httpd/error_log',
        '/var/log/secure',
        '/var/log/messages',
        '/var/log/maillog',
        '/var/log/fail2ban.log',

        // Example for a Debian/Ubuntu server with Apache
        // '/var/log/apache2/access.log',
        // '/var/log/apache2/error.log',
        // '/var/log/auth.log',
        // '/var/log/syslog',
    ];
    ```

3.  **Set Permissions (Crucial Step):**
    Your web server user (typically `apache` on CentOS or `www-data` on Ubuntu) needs permission to read these files. Run the following commands via SSH:
    
    > **Note:** If `setfacl` is not installed, use `sudo yum install acl` or `sudo apt-get install acl`.

    ```bash
    # Example for CentOS/RHEL (apache user)
    sudo setfacl -m u:apache:r /var/log/messages /var/log/secure /var/log/maillog /var/log/fail2ban.log

    # Example for Debian/Ubuntu (www-data user)
    sudo setfacl -m u:www-data:r /var/log/syslog /var/log/auth.log /var/log/mail.log /var/log/fail2ban.log
    ```

4.  **🔒 Secure the Script (Very Important!):**
    This script displays sensitive information. You **must** restrict access to it with a password.
    -   Create a `.htaccess` file in the same directory as your script and add the following content (adjust the path to your password file):
        ```apache
        AuthType Basic
        AuthName "Restricted Area"
        AuthUserFile /path/to/your/.htpasswd
        Require valid-user
        ```
    -   Use the `htpasswd` command to create a password file (replace `your_username` with a username of your choice):
        ```bash
        htpasswd -c /path/to/your/.htpasswd your_username
        ```

5.  **View the Report:** Open the PHP file in your browser and log in with the username and password you just created.

---
