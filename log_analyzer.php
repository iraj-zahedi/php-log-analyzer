<?php
// --- ١. پیکربندی ---
$logFiles = [
    'access.log', // فایل نمونه شما
    '/var/log/fail2ban.log',           // لاگ Fail2ban
    '/var/log/maillog',                // لاگ ایمیل (Dovecot, Exim, Postfix)
    // --- مسیرهای رایج در سرورهای لینوکسی (حتماً متناسب با سرور خود فعال کنید) ---
    // '/var/log/httpd/access_log',      // لاگ دسترسی آپاچی
    '/var/log/httpd/error_log',       // لاگ خطای آپاچی
    // '/var/log/secure',                // لاگ‌های امنیتی (SSH, Sudo) در CentOS/RHEL
    // '/var/log/auth.log',              // لاگ‌های امنیتی (SSH, Sudo) در Debian/Ubuntu
    // '/var/log/messages',              // لاگ عمومی سیستم در CentOS/RHEL (شامل کرنل)
    // '/var/log/syslog',                // لاگ عمومی سیستم در Debian/Ubuntu (شامل کرنل)
    // '/var/log/modsec_audit.log',      // لاگ ModSecurity
    // '/var/log/mysql/error.log',       // لاگ خطای MySQL/MariaDB در Debian/Ubuntu
    // '/var/lib/mysql/error.log',       // لاگ خطای MySQL/MariaDB در CentOS/RHEL
];
$events_per_page = 50; // تعداد رویدادها در هر صفحه

// --- ٢. توابع اصلی ---
function get_all_parsers() {
    return [
        'apache_logs'       => ['label' => 'لاگ‌های آپاچی', 'parser' => function($line) {
            $p = '/^\[.*?\] \[ssl:warn\].*? AH01909: (?<vhost>.*?) server certificate does NOT include an ID which matches the server name/';
            if (preg_match($p, $line, $m)) return ['type' => 'service_warning', 'ts' => date("Y-m-d H:i:s"), 'ip' => 'SERVER', 'msg' => $line, 'details' => ['type' => 'Server Config', 'subtype' => 'SSL Mismatch', 'desc' => 'نام سرور با گواهی SSL برای هاست '.htmlspecialchars($m['vhost']).' مطابقت ندارد.', 'miti' => 'گواهی SSL را بررسی و در صورت نیاز مجدداً صادر کنید.']];
            $p = '/^\[.*?\] \[(?:core|mpm_event):notice\].*? (AH00489|AH00094|AH00493)/';
            if (preg_match($p, $line, $m)) return ['type' => 'system_event', 'ts' => date("Y-m-d H:i:s"), 'ip' => 'SYSTEM', 'msg' => $line, 'details' => ['type' => 'Server Event', 'subtype' => 'Apache Status', 'desc' => 'آپاچی در حال شروع به کار یا ری‌استارت است.', 'miti' => 'این یک پیام اطلاعاتی است و نیاز به اقدامی ندارد.']];
            $p = '/^\[.*?\] \[proxy_fcgi:error\].*? \[client (?<ip>[\d\.:a-fA-F]+)\:\d+\] AH01071: Got error \'Primary script unknown\'/';
            if (preg_match($p, $line, $m)) return ['type' => 'service_error', 'ts' => date("Y-m-d H:i:s"), 'ip' => $m['ip'], 'msg' => $line, 'details' => ['type' => 'Application Error', 'subtype' => 'FCGI Script Not Found', 'desc' => 'وب سرور نتوانست اسکریپت PHP درخواستی را پیدا کند.', 'miti' => 'مسیر فایل‌ها و تنظیمات FPM/FCGI را در کانفیگ وب سرور بررسی کنید.']];
            $p = '/^\[.*?\] \[access_compat:error\].*? \[client (?<ip>[\d\.:a-fA-F]+)\:\d+\] AH01797: client denied by server configuration/';
            if (preg_match($p, $line, $m)) return ['type' => 'access_denied', 'ts' => date("Y-m-d H:i:s"), 'ip' => $m['ip'], 'msg' => $line, 'details' => ['type' => 'Access Control', 'subtype' => 'Config Deny', 'desc' => 'دسترسی به یک مسیر توسط تنظیمات آپاچی (مثلاً .htaccess) رد شد.', 'miti' => 'این رفتار مورد انتظار است اگر مسیر محافظت شده باشد. در غیر این صورت، فایل .htaccess را بررسی کنید.']];
            return null;
        }],
        'mail_server_logs'  => ['label' => 'لاگ‌های سرور ایمیل', 'parser' => function($line) {
            $p = '/^(?<ts>\w{3}\s+\d+\s+[\d:]+) .*? dovecot.*?: (?:imap|pop3)-login: Disconnected:.*?SSL_accept\(\) failed:.*?error:.*?:\s*(?<reason>no shared cipher|unsupported protocol|version too low|wrong version number|http request|bad key share).*?rip=(?<ip>[\d\.:a-fA-F]+),/i';
            if (preg_match($p, $line, $m)) return ['type' => 'service_warning', 'ts' => $m['ts'], 'ip' => $m['ip'], 'msg' => $line, 'details' => ['type' => 'Mail Server Warning', 'subtype' => 'SSL/TLS Handshake Failure', 'desc' => 'اتصال ایمیل به دلیل خطای SSL رد شد: ' . htmlspecialchars($m['reason']), 'miti' => 'این IP احتمالاً یک اسکنر امنیتی یا یک کلاینت قدیمی است. اگر تکرار شد آن را مسدود کنید.']];
            $p = '/^(?<ts>\w{3}\s+\d+\s+[\d:]+) .*? dovecot.*?: (?:imap|pop3)-login: Disconnected: Too many invalid commands.*?rip=(?<ip>[\d\.:a-fA-F]+),/';
            if (preg_match($p, $line, $m)) return ['type' => 'service_warning', 'ts' => $m['ts'], 'ip' => $m['ip'], 'msg' => $line, 'details' => ['type' => 'Potential Attack', 'subtype' => 'Mail Server Probe', 'desc' => 'اتصال به دلیل ارسال دستورات نامعتبر زیاد قطع شد.', 'miti' => 'این IP در حال بررسی سرور ایمیل است. آن را مسدود کنید.']];
            $p = '/^(?<ts>\w{3}\s+\d+\s+[\d:]+) .*? dovecot.*?: (?:imap|pop3)-login: Login: user=<(?<user>.*?)>.*?rip=(?<ip>[\d\.:a-fA-F]+),/';
            if (preg_match($p, $line, $m)) return ['type' => 'system_event', 'ts' => $m['ts'], 'ip' => $m['ip'], 'msg' => $line, 'details' => ['type' => 'User Authentication', 'subtype' => 'Mail Login Success', 'desc' => 'کاربر ' . htmlspecialchars($m['user']) . ' با موفقیت وارد شد.', 'miti' => 'پیام اطلاعاتی. در صورت مشکوک بودن به فعالیت، آن را بررسی کنید.']];
            $p = '/^(?<ts>\S+ \S+) login authenticator failed for .*? \[(?<ip>[\d\.:a-fA-F]+)\]: .*?\(set_id=(?<user>.*?)\)$/';
            if (preg_match($p, $line, $m)) return ['type' => 'mail_log', 'ts' => $m['ts'], 'ip' => $m['ip'], 'msg' => $line, 'details' => ['type' => 'Brute-Force', 'subtype' => 'SMTP/IMAP Auth', 'desc' => 'تلاش ناموفق ورود به ایمیل '.htmlspecialchars($m['user']), 'miti' => 'IP را مسدود و از رمزهای قوی استفاده کنید.']];
            return null;
        }],
        'modsec_log'        => ['label' => 'لاگ ModSecurity', 'parser' => function($line) { $p = '/^\[.*?\] \[security2:error\].*? \[client (?<ip>[\d\.:a-fA-F]+)(?::\d+)?\] ModSecurity: .*? \[msg "(?<msg>.*?)"\].*? \[id "(?<id>\d+)"\]/'; if (preg_match($p, $line, $m)) return ['type' => 'modsec_log', 'ts' => date("Y-m-d H:i:s"), 'ip' => $m['ip'], 'msg' => $line, 'details' => ['type' => 'WAF Block', 'subtype' => 'ModSecurity Rule #'.$m['id'], 'desc' => htmlspecialchars($m['msg']), 'miti' => 'این یک حمله وب شناسایی شده است. IP را بررسی و مسدود کنید.']]; return null; }],
        'kernel_panic'      => ['label' => 'کرنل پنیک (کرش سرور)', 'parser' => function($line) { $p = '/^(?<ts>\w{3}\s+\d+\s+[\d:]+) .*? kernel: Kernel panic.*?$/'; if (preg_match($p, $line, $m)) return ['type' => 'system_critical', 'ts' => $m['ts'], 'ip' => 'CRITICAL', 'msg' => $line, 'details' => ['type' => 'System Crash', 'subtype' => 'Kernel Panic', 'desc' => 'کرش کامل سرور به دلیل خطای هسته.', 'miti' => 'مشکلات سخت‌افزاری (RAM) یا درایورها را بررسی کنید.']]; return null; }],
        'oom_killer'        => ['label' => 'کمبود حافظه (OOM Killer)', 'parser' => function($line) { $p = '/^(?<ts>\w{3}\s+\d+\s+[\d:]+) .*? kernel: Out of memory: Kill process \d+ \((?<proc>.*?)\)/'; if (preg_match($p, $line, $m)) return ['type' => 'system_warning', 'ts' => $m['ts'], 'ip' => 'SYSTEM', 'msg' => $line, 'details' => ['type' => 'Resource Exhaustion', 'subtype' => 'OOM Killer', 'desc' => 'سرور به دلیل کمبود RAM، پروسه "'.htmlspecialchars($m['proc']).'" را بسته.', 'miti' => 'مصرف حافظه را با `free -h` بررسی کنید.']]; return null; }],
        'hardware_error'    => ['label' => 'خطاهای سخت‌افزاری', 'parser' => function($line) { $p = '/^(?<ts>\w{3}\s+\d+\s+[\d:]+) .*? kernel: .*?(I\/O error|Hardware Error|MCE).*? on device (?<dev>\S+)/i'; if (preg_match($p, $line, $m)) return ['type' => 'system_critical', 'ts' => $m['ts'], 'ip' => 'HARDWARE', 'msg' => $line, 'details' => ['type' => 'System Failure', 'subtype' => 'Hardware Error', 'desc' => 'خطای سخت‌افزاری روی دستگاه '.htmlspecialchars($m['dev']), 'miti' => 'سلامت سخت‌افزار را با S.M.A.R.T بررسی کنید.']]; return null; }],
        'system_boot'       => ['label' => 'راه‌اندازی مجدد سیستم', 'parser' => function($line) { $p = '/^(?<ts>\w{3}\s+\d+\s+[\d:]+) .*? kernel: Linux version .*?$/'; if (preg_match($p, $line, $m)) return ['type' => 'system_event', 'ts' => $m['ts'], 'ip' => 'SYSTEM', 'msg' => $line, 'details' => ['type' => 'System Event', 'subtype' => 'System Boot', 'desc' => 'سیستم راه‌اندازی شده است.', 'miti' => 'برای یافتن علت ری‌استارت، از `journalctl -b -1` استفاده کنید.']]; return null; }],
        'sudo_usage'        => ['label' => 'استفاده از Sudo', 'parser' => function($line) { $p = '/^(?<ts>\w{3}\s+\d+\s+[\d:]+) .*? (?:sudo|su): \s*(?<user>\S+) : .*?session opened/'; if (preg_match($p, $line, $m)) return ['type' => 'system_security', 'ts' => $m['ts'], 'ip' => 'LOCAL', 'msg' => $line, 'details' => ['type' => 'Security Event', 'subtype' => 'Root Access', 'desc' => 'کاربر "'.htmlspecialchars($m['user']).'" به دسترسی ریشه رسید.', 'miti' => 'اطمینان حاصل کنید که این فعالیت مجاز بوده است.']]; return null; }],
        'phpfpm_warning'    => ['label' => 'خطاهای PHP-FPM', 'parser' => function($line) { $p = '/^(?<ts>\w{3}\s+\d+\s+[\d:]+) .*? php-fpm: .*? WARNING: .*? max_children setting \((?<limit>\d+)\)/'; if (preg_match($p, $line, $m)) return ['type' => 'service_warning', 'ts' => $m['ts'], 'ip' => 'SERVICE', 'msg' => $line, 'details' => ['type' => 'Service Health', 'subtype' => 'PHP-FPM Limit', 'desc' => 'PHP-FPM به حداکثر پردازش ('.htmlspecialchars($m['limit']).') رسیده.', 'miti' => 'مقدار `pm.max_children` را افزایش دهید.']]; return null; }],
        'ssh_log'           => ['label' => 'ورود ناموفق SSH', 'parser' => function($line) { $p = '/^(?<ts>\w{3}\s+\d+\s+[\d:]+) .*? sshd\[\d+\]: Failed password for .*?(?<user>\S+) from (?<ip>[\d\.]+) port/'; if (preg_match($p, $line, $m)) return ['type' => 'ssh_log', 'ts' => $m['ts'], 'ip' => $m['ip'], 'msg' => $line, 'details' => ['type' => 'Brute-Force', 'subtype' => 'SSH Auth Failure', 'desc' => 'تلاش ناموفق ورود SSH با نام '.htmlspecialchars($m['user']), 'miti' => 'این IP را مسدود کنید. از کلید SSH استفاده کنید.']]; return null; }],
        'mysql_auth_fail'   => ['label' => 'خطای اتصال به دیتابیس', 'parser' => function($line) { $p = '/Access denied for user \'(?<user>.*?)\'@\'(?<ip>.*?)\'/'; if (preg_match($p, $line, $m)) return ['type' => 'database_error', 'ts' => date("Y-m-d H:i:s"), 'ip' => $m['ip'], 'msg' => $line, 'details' => ['type' => 'Database Security', 'subtype' => 'Auth Failure', 'desc' => 'اتصال ناموفق به دیتابیس با کاربر '.htmlspecialchars($m['user']), 'miti' => 'رمزهای عبور دیتابیس را بررسی کنید و دسترسی از این IP را محدود کنید.']]; return null; }],
        'fail2ban_logs'     => ['label' => 'لاگ Fail2ban', 'parser' => function($line) {
            $p = '/^(?<ts>[\d\s\-\,:]+) fail2ban\.actions\s+\[\d+\]: NOTICE\s+\[(?<jail>.*?)\] Ban (?<ip>[\d\.]+)$/';
            if (preg_match($p, $line, $m)) return ['type' => 'system_security', 'ts' => date("Y-m-d H:i:s", strtotime($m['ts'])), 'ip' => $m['ip'], 'msg' => $line, 'details' => ['type' => 'Security Action', 'subtype' => 'Fail2ban Ban', 'desc' => 'IP به دلیل تخلف در قانون "'.htmlspecialchars($m['jail']).'" مسدود شد.', 'miti' => 'این یک اقدام خودکار و مورد انتظار است. Fail2ban به درستی کار کرده است.']];
            $p = '/^(?<ts>[\d\s\-\,:]+) fail2ban\.actions\s+\[\d+\]: NOTICE\s+\[(?<jail>.*?)\] Unban (?<ip>[\d\.]+)$/';
            if (preg_match($p, $line, $m)) return ['type' => 'system_event', 'ts' => date("Y-m-d H:i:s", strtotime($m['ts'])), 'ip' => $m['ip'], 'msg' => $line, 'details' => ['type' => 'System Event', 'subtype' => 'Fail2ban Unban', 'desc' => 'IP پس از اتمام دوره مسدودیت توسط قانون "'.htmlspecialchars($m['jail']).'" آزاد شد.', 'miti' => 'این یک پیام اطلاعاتی است و نیاز به اقدامی ندارد.']];
            $p = '/^(?<ts>[\d\s\-\,:]+) fail2ban\.actions\s+\[\d+\]: ERROR\s+Failed to execute ban jail \'(?<jail>.*?)\'.*?Error banning (?<ip>[\d\.]+)/';
            if (preg_match($p, $line, $m)) return ['type' => 'system_critical', 'ts' => date("Y-m-d H:i:s", strtotime($m['ts'])), 'ip' => $m['ip'], 'msg' => $line, 'details' => ['type' => 'System Failure', 'subtype' => 'Fail2ban Action Failed', 'desc' => 'Fail2ban نتوانست IP را برای قانون "'.htmlspecialchars($m['jail']).'" مسدود کند.', 'miti' => 'فوراً وضعیت فایروال سرور (مانند FirewallD یا UFW) را بررسی کنید. به احتمال زیاد فایروال خاموش است. با دستور `systemctl status firewalld` آن را چک کنید.']];
            return null;
        }],
        'firewall_log'      => ['label' => 'لاگ فایروال', 'parser' => function($line) { $p = '/^(?<ts>\w{3}\s+\d+\s+[\d:]+) .*? kernel: .*?Blocked.*?SRC=(?<ip>[\d\.]+) .*?PROTO=(?<prot>\S+)/'; if (preg_match($p, $line, $m)) return ['type' => 'firewall_log', 'ts' => $m['ts'], 'ip' => $m['ip'], 'msg' => $line, 'details' => ['type' => 'Firewall Block', 'subtype' => 'Port Scan', 'desc' => 'ترافیک '.($m['prot']).' توسط فایروال مسدود شد.', 'miti' => 'فایروال به درستی کار کرده است.']]; return null; }],
        'vuln_scan'         => ['label' => 'اسکن آسیب‌پذیری', 'parser' => function($line) { $p = '/^(?<ip>[\d\.]+) .*? \[(?<ts>.*?)\] "GET (?<url>.*?) HTTP.*?" (404|403)/'; if (preg_match($p, $line, $m)) { if (preg_match('/(wp-content|wp-includes|xmlrpc\.php|jmx-console|phpmyadmin|\.git|\.env)/i', $m['url'])) return ['type' => 'vuln_scan', 'ts' => $m['ts'], 'ip' => $m['ip'], 'msg' => $line, 'url' => $m['url'], 'details' => ['type' => 'Reconnaissance', 'subtype' => 'Vulnerability Scan', 'desc' => 'تلاش برای یافتن فایل یا افزونه آسیب‌پذیر.', 'miti' => 'IP را مسدود کنید. این یک فعالیت شناسایی است.']]; } return null; }],
        'command_injection' => ['label' => 'حمله تزریق دستور', 'parser' => function($line) { $p = '/^(?<ip>[\d\.]+) .*? \[(?<ts>.*?)\] "(?<method>GET|POST) (?<url>.*?) HTTP.*?" \d+ \d+ ".*?" "(?<agent>.*?)"$/'; if (preg_match($p, $line, $m)) { if (preg_match('/(&&|;|\`|\|)\s*(wget|curl|cat)/i', urldecode($m['url']))) return ['type' => 'command_injection', 'ts' => $m['ts'], 'ip' => $m['ip'], 'msg' => $line, 'ua_info' => analyze_user_agent($m['agent']), 'url' => $m['url'], 'details' => ['type' => 'Critical Attack', 'subtype' => 'Command Injection', 'desc' => 'تلاش برای اجرای دستورات سیستم‌عامل.', 'miti' => 'فوراً IP را مسدود و کد را برای آسیب‌پذیری RCE بازبینی کنید.']]; } return null; }],
        'wordpress_attacks' => ['label' => 'حملات وردپرس', 'parser' => function($line) { $p = '/^(?<ip>[\d\.]+) .*? \[(?<ts>.*?)\] "(?<method>POST|GET) (?<url>.*?) HTTP.*?" \d+ \d+ ".*?" "(?<agent>.*?)"$/'; if (preg_match($p, $line, $m)) { if (strpos($m['url'], 'wp-login.php') !== false && $m['method'] === 'POST') return ['type' => 'wordpress_bruteforce', 'ts' => $m['ts'], 'ip' => $m['ip'], 'msg' => $line, 'ua_info' => analyze_user_agent($m['agent']), 'url' => $m['url'], 'details' => ['type' => 'Brute-Force', 'subtype' => 'WordPress Login', 'desc' => 'تلاش برای ورود انبوه به وردپرس.', 'miti' => 'از افزونه‌های امنیتی و کپچا استفاده کنید.']]; } return null; }],
        'seo_404_finder'    => ['label' => 'خطاهای سئو (404)', 'parser' => function($line) { $p = '/^(?<ip>[\d\.]+) .*? \[(?<ts>.*?)\] "GET (?<url>.*?) HTTP.*?" 404 \d+ "(?<ref>.*?)".*?"(?<agent>.*?)"$/'; if (preg_match($p, $line, $m) && !empty($m['ref']) && $m['ref'] !== '-') return ['type' => 'seo_warning', 'ts' => $m['ts'], 'ip' => $m['ip'], 'msg' => $line, 'ua_info' => analyze_user_agent($m['agent']), 'url' => $m['url'], 'details' => ['type' => 'SEO Issue', 'subtype' => 'Broken Link (404)', 'desc' => 'لینک شکسته از: '.htmlspecialchars($m['ref']), 'miti' => 'صفحه را ریدایرکت ۳۰۱ کنید یا لینک را اصلاح نمایید.']]; return null; }],
        'sql_injection'     => ['label' => 'حمله تزریق SQL', 'parser' => function($line) { $p = '/^(?<ip>[\d\.]+) .*? \[(?<ts>.*?)\] "(?<method>GET|POST) (?<url>.*?) HTTP.*?" \d+ \d+ ".*?" "(?<agent>.*?)"$/'; if (preg_match($p, $line, $m)) { if (preg_match('/\b(union|select|insert|concat)\b/i', urldecode($m['url']))) return ['type' => 'sql_injection', 'ts' => $m['ts'], 'ip' => $m['ip'], 'msg' => $line, 'ua_info' => analyze_user_agent($m['agent']), 'url' => $m['url'], 'details' => ['type' => 'Potential Attack', 'subtype' => 'SQL Injection', 'desc' => 'تلاش برای حمله تزریق SQL.', 'miti' => 'همیشه از Prepared Statements استفاده کنید.']]; } return null; }],
        'path_traversal'    => ['label' => 'حمله پیمایش مسیر', 'parser' => function($line) { $p = '/^(?<ip>[\d\.]+) .*? \[(?<ts>.*?)\] "(?<method>GET|POST) (?<url>.*?) HTTP.*?" \d+ \d+ ".*?" "(?<agent>.*?)"$/'; if (preg_match($p, $line, $m)) { if (preg_match('/(\.\.\/|%2e%2e%2f)/i', urldecode($m['url']))) return ['type' => 'path_traversal', 'ts' => $m['ts'], 'ip' => $m['ip'], 'msg' => $line, 'ua_info' => analyze_user_agent($m['agent']), 'url' => $m['url'], 'details' => ['type' => 'Potential Attack', 'subtype' => 'Path Traversal', 'desc' => 'تلاش برای دسترسی به فایل‌های حساس.', 'miti' => 'ورودی‌های فایل را به شدت اعتبارسنجی کنید.']]; } return null; }],
        'xss_attack'        => ['label' => 'حمله XSS', 'parser' => function($line) { $p = '/^(?<ip>[\d\.]+) .*? \[(?<ts>.*?)\] "(?<method>GET|POST) (?<url>.*?) HTTP.*?" \d+ \d+ ".*?" "(?<agent>.*?)"$/'; if (preg_match($p, $line, $m)) { if (preg_match('/(<script>|alert\(|onerror=)/i', urldecode($m['url']))) return ['type' => 'xss_attack', 'ts' => $m['ts'], 'ip' => $m['ip'], 'msg' => $line, 'ua_info' => analyze_user_agent($m['agent']), 'url' => $m['url'], 'details' => ['type' => 'Potential Attack', 'subtype' => 'XSS Attempt', 'desc' => 'تلاش برای حمله XSS.', 'miti' => 'خروجی‌ها را با `htmlspecialchars` پاکسازی کنید.']]; } return null; }],
        'content_scan'      => ['label' => 'اسکن محتوای سایت', 'parser' => function($line) { return null; }], // Virtual parser
    ];
}

function analyze_user_agent($agent) { if (empty($agent) || $agent === '-') return null; if (stripos($agent, 'Googlebot') !== false) return ['type' => 'Good Bot', 'name' => 'Googlebot', 'icon' => '🟢']; if (stripos($agent, 'Bingbot') !== false) return ['type' => 'Good Bot', 'name' => 'Bingbot', 'icon' => '🟢']; if (stripos($agent, 'sqlmap') !== false) return ['type' => 'Attack Tool', 'name' => 'SQLMap', 'icon' => '🔴']; if (stripos($agent, 'nikto') !== false) return ['type' => 'Attack Tool', 'name' => 'Nikto', 'icon' => '🔴']; if (stripos($agent, 'nmap') !== false) return ['type' => 'Attack Tool', 'name' => 'Nmap', 'icon' => '🔴']; return ['type' => 'Browser', 'name' => substr($agent, 0, 40).'...', 'icon' => '']; }
function parse_line($line, $enabled_filters) { $line = trim($line); if (empty($line)) return null; $all_parsers = get_all_parsers(); foreach ($enabled_filters as $key) { if ($key === 'content_scan') continue; if (isset($all_parsers[$key])) { if ($parsed = $all_parsers[$key]['parser']($line)) return $parsed; } } return null; }
function get_country_from_ip($ip) { static $cache = []; if (isset($cache[$ip])) { return $cache[$ip]; } if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) { return ['name' => 'N/A', 'code' => '']; } if (!function_exists('curl_init')) { return ['name' => 'cURL needed', 'code' => '']; } $url = "http://ip-api.com/json/{$ip}?fields=status,country,countryCode"; $ch = curl_init(); curl_setopt_array($ch, [CURLOPT_URL => $url, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 3, CURLOPT_CONNECTTIMEOUT => 3]); $response = curl_exec($ch); curl_close($ch); if ($response) { $data = json_decode($response, true); if ($data && $data['status'] === 'success') { $cache[$ip] = ['name' => htmlspecialchars($data['country']), 'code' => htmlspecialchars($data['countryCode'])]; return $cache[$ip]; } } $cache[$ip] = ['name' => 'Unknown', 'code' => '']; return $cache[$ip]; }
function country_code_to_emoji($code) { if (empty($code)) return '🌍'; $code = strtoupper($code); $a = 0x1F1E6; return mb_convert_encoding('&#' . ($a + ord($code[0]) - 65) . ';', 'UTF-8', 'HTML-ENTITIES') . mb_convert_encoding('&#' . ($a + ord($code[1]) - 65) . ';', 'UTF-8', 'HTML-ENTITIES'); }

// --- ٣. پردازش و تجمیع داده‌ها ---
$all_parsers = get_all_parsers();
$enabled_filters = isset($_GET['filters']) && is_array($_GET['filters']) ? $_GET['filters'] : array_keys($all_parsers);
$search_term = isset($_GET['search']) ? trim($_GET['search']) : '';
$stats = ['total_lines' => 0, 'total_events' => 0, 'event_counts' => []];
$all_logs = []; $ip_counts = [];
$safe_event_types = ['system_event', 'seo_warning'];
$hourly_events = array_fill(0, 24, 0); $top_urls = [];
$country_cache = [];

foreach ($logFiles as $logFile) {
    if (file_exists($logFile) && is_readable($logFile)) {
        if ($handle = fopen($logFile, "r")) {
            while (($line = fgets($handle)) !== false) {
                $stats['total_lines']++;
                $parsed = parse_line($line, $enabled_filters);
                if ($parsed && !empty($parsed['details'])) {
                    $all_logs[] = $parsed;
                }
            }
            fclose($handle);
        }
    }
}

// <<< اصلاح شد: جستجوی سراسری قبل از هر پردازش دیگری >>>
if (!empty($search_term)) {
    $all_logs = array_filter($all_logs, function($log) use ($search_term) {
        return stripos($log['msg'], $search_term) !== false;
    });
}

// پردازش آمارها پس از فیلتر و جستجو
foreach($all_logs as &$log) {
    $stats['total_events']++;
    $type = $log['details']['type'];
    $stats['event_counts'][$type] = ($stats['event_counts'][$type] ?? 0) + 1;
    
    if (!empty($log['ip']) && !in_array($log['ip'], ['LOCAL', 'SYSTEM', 'CRITICAL', 'HARDWARE', 'SERVICE', '::1']) && !in_array($log['type'], $safe_event_types)) {
        $ip_counts[$log['ip']] = ($ip_counts[$log['ip']] ?? 0) + 1;
    }
    
    $log['ts_unix'] = isset($log['ts']) ? strtotime(str_replace(['/',' '], ':', $log['ts'])) : time();

    if ($log['ts_unix'] > strtotime('-24 hours')) {
        $hour = date('H', $log['ts_unix']);
        $hourly_events[(int)$hour]++;
    }
    if (isset($log['url'])) {
        $url = strtok($log['url'], '?');
        $top_urls[$url] = ($top_urls[$url] ?? 0) + 1;
    }
}
unset($log);

usort($all_logs, function($a, $b) { return $b['ts_unix'] <=> $a['ts_unix']; });
arsort($ip_counts);
arsort($top_urls);
$top_urls = array_slice($top_urls, 0, 10);

// --- ٤. آماده‌سازی داده‌ها برای نمودارهای Google Charts ---
$map_data = [];
$top_attackers_slice = array_slice($ip_counts, 0, 20, true);
foreach (array_keys($top_attackers_slice) as $ip) {
    if (!isset($country_cache[$ip])) {
        $country_cache[$ip] = get_country_from_ip($ip);
    }
    $country_info = $country_cache[$ip];
    if ($country_info['code']) {
        $map_data[$country_info['code']] = ($map_data[$country_info['code']] ?? 0) + $ip_counts[$ip];
    }
}

$geochart_data = [['Country', 'Events']];
foreach ($map_data as $code => $count) { $geochart_data[] = [$code, $count]; }
$geochart_data_json = json_encode($geochart_data);

$piechart_data = [['Type', 'Count']];
if (!empty($stats['event_counts'])) { foreach ($stats['event_counts'] as $type => $count) { $piechart_data[] = [$type, $count]; } }
$piechart_data_json = json_encode($piechart_data);

$timechart_data = [['Hour', 'Events']];
for ($i=0; $i<24; $i++) { $timechart_data[] = [sprintf('%02d:00', $i), $hourly_events[$i]]; }
$timechart_data_json = json_encode($timechart_data);

$barchart_data = [['URL', 'Hits']];
if (!empty($top_urls)) { foreach ($top_urls as $url => $count) { $barchart_data[] = [htmlspecialchars($url), $count]; } }
$barchart_data_json = json_encode($barchart_data);

$total_events = count($all_logs);
$total_pages = ceil($total_events / $events_per_page);
$current_page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$current_page = max(1, min($total_pages, $current_page));
$offset = ($current_page - 1) * $events_per_page;
$paginated_logs = array_slice($all_logs, $offset, $events_per_page);

// پارامترهای فعلی برای حفظ در لینک‌ها
$current_params = $_GET;
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl"><head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>داشبورد امنیتی و تحلیلگر لاگ سرور</title>
    <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root { --color-bg: #f4f7f9; --color-card: #ffffff; --color-text: #333333; --color-primary: #007bff; --color-border: #e0e5eb; --color-danger: #dc3545; --color-warning: #fd7e14; --color-system-critical: #721c24; --color-system-warning: #856404; --color-seo: #0dcaf0; }
        body { font-family: 'Vazirmatn', sans-serif; background-color: var(--color-bg); color: var(--color-text); margin: 0; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .card { background-color: var(--color-card); padding: 25px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); margin-bottom: 25px; }
        h1, h2 { color: var(--color-primary); border-bottom: 2px solid var(--color-border); padding-bottom: 10px; margin-top: 0; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; }
        .stat-card { background-color: var(--color-bg); padding: 20px; border-radius: 8px; text-align: center; border: 1px solid var(--color-border); }
        .stat-card .number { font-size: 2.2em; font-weight: 700; color: var(--color-primary); }
        .stat-card .label { font-size: 1em; color: #666; }
        .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); gap: 25px; }
        .chart-container { width: 100%; height: 450px; }
        .tabs { border-bottom: 2px solid var(--color-border); margin-bottom: 25px; display: flex; flex-wrap: wrap; }
        .tabs button { background-color: transparent; border: none; padding: 15px 20px; font-family: 'Vazirmatn', sans-serif; font-size: 1.1em; cursor: pointer; position: relative; color: #555; }
        .tabs button.active { font-weight: 700; color: var(--color-primary); }
        .tabs button.active::after { content: ''; position: absolute; bottom: -2px; left: 0; right: 0; height: 2px; background-color: var(--color-primary); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        details { border-left: 5px solid #ccc; border-radius: 8px; margin-bottom: 15px; overflow: hidden; border: 1px solid var(--color-border); }
        details[data-type="system_critical"] { border-left-color: var(--color-system-critical); background-color: #f8d7da; }
        details[data-type="system_warning"], details[data-type="correlated_event"], details[data-type="service_warning"] { border-left-color: var(--color-warning); background-color: #fff3cd; }
        details[data-type="seo_warning"] { border-left-color: var(--color-seo); background-color: #cff4fc; }
        summary { padding: 15px; cursor: pointer; display: grid; grid-template-columns: 140px auto 180px; gap: 15px; align-items: center; font-size: 0.9em; background-color: #f8f9fa; }
        .summary-ip { font-weight: 700; color: var(--color-danger); font-family: monospace; }
        .summary-msg { color: #444; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .summary-type { font-weight: 700; }
        .attack-content { padding: 15px; background-color: #fff; }
        .attack-content code { background-color: #e9ecef; padding: 10px; border-radius: 4px; direction: ltr; display: block; text-align: left; white-space: pre-wrap; word-wrap: break-word; font-size: 0.85em; }
        .mitigation { background-color: #e3f2fd; border-right: 4px solid var(--color-primary); padding: 10px; margin-top: 10px; border-radius: 4px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: right; padding: 12px; border-bottom: 1px solid var(--color-border); }
        .block-code { background-color: #e9ecef; color: #495057; padding: 5px 10px; border-radius: 4px; font-family: monospace; direction: ltr; text-align: left; display:block; margin-top: 5px;}
        .search-form { display: flex; gap: 10px; margin-bottom: 20px; }
        .search-box { flex-grow: 1; box-sizing: border-box; padding: 12px; border: 1px solid var(--color-border); border-radius: 5px; font-family: 'Vazirmatn', sans-serif; }
        .search-btn { background-color: var(--color-primary); color: white; border: none; padding: 12px 20px; border-radius: 5px; cursor: pointer; font-family: 'Vazirmatn', sans-serif; font-size: 1em; }
        .clear-search-btn { background-color: #6c757d; text-decoration: none; display:inline-block; }
        .pagination { text-align: center; margin-top: 20px; }
        .pagination a { color: var(--color-primary); padding: 8px 16px; text-decoration: none; border: 1px solid var(--color-border); margin: 0 4px; border-radius: 5px; }
        .pagination a.active { background-color: var(--color-primary); color: white; }
        .footer-card { text-align: center; padding: 20px; margin-top: 25px; font-size: 0.9em; color: #555; }
        .footer-card a { color: var(--color-primary); text-decoration: none; font-weight: bold; }
        .filter-form { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; }
        .filter-form label { display: flex; align-items: center; background-color: #f8f9fa; padding: 10px; border-radius: 5px; border: 1px solid var(--color-border); cursor: pointer; font-size: 0.9em; }
        .filter-form input { margin-left: 10px; }
        .filter-btn { background-color: var(--color-primary); color: white; border: none; padding: 12px; border-radius: 5px; cursor: pointer; font-family: 'Vazirmatn', sans-serif; font-size: 1em; grid-column: 1 / -1; }
    </style>
</head><body>
    <div class="container">
        <h1>داشبورد امنیتی و تحلیلگر لاگ سرور</h1>
        
        <div class="card">
            <h2>آمار کلی</h2>
            <div class="stats-grid">
                <div class="stat-card"><div class="number"><?php echo number_format($stats['total_lines']); ?></div><div class="label">کل خطوط خوانده شده</div></div>
                <div class="stat-card"><div class="number" style="color:var(--color-danger)"><?php echo number_format($stats['total_events']); ?></div><div class="label">رویدادهای نمایش داده شده</div></div>
                <?php foreach($stats['event_counts'] as $type => $count): ?>
                    <div class="stat-card"><div class="number"><?php echo number_format($count); ?></div><div class="label"><?php echo htmlspecialchars($type); ?></div></div>
                <?php endforeach; ?>
            </div>
        </div>

        <div class="tabs">
            <button class="tab-button active" onclick="openTab(event, 'events')">رویدادهای زنده</button>
            <button class="tab-button" onclick="openTab(event, 'stats')">آمارها</button>
            <button class="tab-button" onclick="openTab(event, 'attackers')">مهاجمان برتر</button>
        </div>

        <div id="events" class="tab-content active">
            <div class="card">
                <h2>فیلتر و جستجو</h2>
                <form method="GET" action="">
                    <div class="search-form">
                        <input type="text" name="search" class="search-box" placeholder="جستجو در تمام رویدادها..." value="<?php echo htmlspecialchars($search_term); ?>">
                        <button type="submit" class="search-btn">جستجو</button>
                        <?php if (!empty($search_term)):
                            unset($current_params['search']);
                            $clear_url = '?' . http_build_query($current_params);
                        ?>
                            <a href="<?php echo $clear_url; ?>" class="search-btn clear-search-btn">پاک کردن جستجو</a>
                        <?php endif; ?>
                    </div>
                    <div class="filter-form">
                        <?php foreach ($all_parsers as $key => $details): ?>
                            <label><input type="checkbox" name="filters[]" value="<?php echo $key; ?>" <?php echo in_array($key, $enabled_filters) ? 'checked' : ''; ?>> <?php echo htmlspecialchars($details['label']); ?></label>
                        <?php endforeach; ?>
                    </div>
                    <br><button type="submit" class="filter-btn">اعمال فیلترها</button>
                </form>
            </div>
            <div class="card">
                <h2>جزئیات رویدادها (<?php echo $total_events; ?> مورد)</h2>
                <div id="log-details-list">
                    <?php if (empty($paginated_logs)): ?>
                        <p>هیچ رویدادی مطابق با فیلترها یا جستجوی شما یافت نشد.</p>
                    <?php else: foreach ($paginated_logs as $log): ?>
                        <details data-type="<?php echo htmlspecialchars($log['type'] ?? 'unknown'); ?>" class="log-item">
                            <summary>
                                <span class="summary-ip"><?php echo htmlspecialchars($log['ip']); ?></span>
                                <span class="summary-msg" title="<?php echo htmlspecialchars($log['msg']); ?>"><?php echo htmlspecialchars($log['details']['desc']); ?></span>
                                <span class="summary-type"><?php echo htmlspecialchars($log['details']['subtype']); ?></span>
                            </summary>
                            <div class="attack-content">
                                <p><strong>نوع رویداد:</strong> <?php echo htmlspecialchars($log['details']['type']); ?><br><strong>زمان:</strong> <?php echo htmlspecialchars($log['ts']); ?><br>
                                <?php if(isset($log['ua_info']) && is_array($log['ua_info'])): ?><strong>User-Agent:</strong> <?php echo $log['ua_info']['icon']; ?> <?php echo htmlspecialchars($log['ua_info']['name']); ?><br><?php endif; ?></p>
                                <p><strong>پیام کامل لاگ:</strong><br><code><?php echo htmlspecialchars($log['msg']); ?></code></p>
                                <div class="mitigation"><strong>راهکار پیشنهادی:</strong><br><?php echo ($log['details']['miti']); ?></div>
                            </div>
                        </details>
                    <?php endforeach; endif; ?>
                </div>
                <div class="pagination">
                    <?php for ($i = 1; $i <= $total_pages; $i++):
                        $page_params = $current_params;
                        $page_params['page'] = $i;
                    ?><a href="?<?php echo http_build_query($page_params); ?>" class="<?php echo ($i == $current_page) ? 'active' : ''; ?>"><?php echo $i; ?></a><?php endfor; ?>
                </div>
            </div>
        </div>

        <div id="stats" class="tab-content">
            <div class="dashboard-grid">
                <div class="card"><h2>نقشه جغرافیایی حملات</h2><div id="world-map" class="chart-container"></div></div>
                <div class="card"><h2>رویدادها در ٢٤ ساعت گذشته</h2><div id="time-chart" class="chart-container"></div></div>
                <div class="card"><h2>درصد انواع رویدادها</h2><div id="pie-chart" class="chart-container"></div></div>
                <div class="card"><h2>١٠ آدرس پرتکرار در حملات</h2><div id="bar-chart" class="chart-container"></div></div>
            </div>
        </div>
        
        <div id="attackers" class="tab-content">
            <div class="card"><h2>مهاجمان برتر</h2><table>
                <thead><tr><th>IP آدرس</th><th>کشور</th><th>تعداد رویداد</th><th>دستورات مسدودسازی</th></tr></thead>
                <tbody><?php foreach($top_attackers_slice as $ip => $count): $country_info = $country_cache[$ip] ?? get_country_from_ip($ip); ?>
                    <tr>
                        <td><a href="?search=<?php echo urlencode($ip); ?>"><?php echo htmlspecialchars($ip); ?></a></td>
                        <td><?php echo country_code_to_emoji($country_info['code']); ?> <?php echo $country_info['name']; ?></td>
                        <td><?php echo number_format($count); ?></td>
                        <td>
                            <code class="block-code">ufw deny from <?php echo htmlspecialchars($ip); ?></code>
                            <code class="block-code">csf -d <?php echo htmlspecialchars($ip); ?> "Log Analyzer Block"</code>
                            <code class="block-code">fail2ban-client set YOUR_JAIL_NAME banip <?php echo htmlspecialchars($ip); ?></code>
                        </td>
                    </tr>
                <?php endforeach; ?></tbody>
            </table></div>
        </div>
        
        <div class="footer-card"><p>این ابزار متن‌باز با ❤️ توسط <a href="https://blueserver.ir/author/iraj-zahedi/" target="_blank">ایرج زاهدی</a> برای <a href="https://blueserver.ir/" target="_blank">بلوسرور</a> توسعه داده شده است.</p></div>
    </div>
    
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
    <script type="text/javascript">
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tab-button");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";

            if (tabName === 'stats') {
                setTimeout(function() {
                    drawCharts();
                }, 10);
            }
        }

        google.charts.load('current', {'packages':['geochart', 'corechart']});
        google.charts.setOnLoadCallback(drawCharts);

        function drawCharts() {
            try { drawRegionsMap(); } catch(e) { console.error("Could not draw GeoChart:", e); }
            try { drawPieChart(); } catch(e) { console.error("Could not draw PieChart:", e); }
            try { drawTimeChart(); } catch(e) { console.error("Could not draw TimeChart:", e); }
            try { drawBarChart(); } catch(e) { console.error("Could not draw BarChart:", e); }
        }

        function drawRegionsMap() {
            var data = google.visualization.arrayToDataTable(<?php echo $geochart_data_json; ?>);
            if (data.getNumberOfRows() === 0) return;
            var options = { colorAxis: {colors: ['#E6F2F8', '#0071A4']}, backgroundColor: 'transparent', datalessRegionColor: '#f0f0f0' };
            var chart = new google.visualization.GeoChart(document.getElementById('world-map'));
            chart.draw(data, options);
        }

        function drawPieChart() {
            var data = google.visualization.arrayToDataTable(<?php echo $piechart_data_json; ?>);
            if (data.getNumberOfRows() === 0) return;
            var options = {
                title: 'تفکیک انواع رویدادها',
                is3D: true,
                backgroundColor: 'transparent',
                legend: { textStyle: { color: '#333' } },
                titleTextStyle: { color: '#333' },
                chartArea: {'width': '90%', 'height': '80%'}
            };
            var chart = new google.visualization.PieChart(document.getElementById('pie-chart'));
            chart.draw(data, options);
        }

        function drawTimeChart() {
            var data = google.visualization.arrayToDataTable(<?php echo $timechart_data_json; ?>);
            if (data.getNumberOfRows() === 0) return;
            var options = {
                title: 'تعداد رویدادها در ساعت',
                curveType: 'function',
                legend: { position: 'bottom' },
                backgroundColor: 'transparent',
                hAxis: { textStyle: { color: '#333' }, slantedText: true, slantedTextAngle: 45 },
                vAxis: { textStyle: { color: '#333' } },
                titleTextStyle: { color: '#333' },
                chartArea: {'width': '85%', 'height': '75%'}
            };
            var chart = new google.visualization.LineChart(document.getElementById('time-chart'));
            chart.draw(data, options);
        }

        function drawBarChart() {
            var data = google.visualization.arrayToDataTable(<?php echo $barchart_data_json; ?>);
            if (data.getNumberOfRows() === 0) return;
            var options = {
                title: 'آدرس‌های پرتکرار',
                legend: { position: 'none' },
                backgroundColor: 'transparent',
                hAxis: { textStyle: { color: '#333' } },
                vAxis: { textStyle: { color: '#333' } },
                titleTextStyle: { color: '#333' },
                chartArea: {'width': '80%', 'height': '80%'}
            };
            var chart = new google.visualization.BarChart(document.getElementById('bar-chart'));
            chart.draw(data, options);
        }
    </script>
</body></html>
