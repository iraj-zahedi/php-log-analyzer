<?php

// --- پیکربندی ---
// !!! مهم: مسیر واقعی فایل‌های لاگ سرور خود را در این آرایه وارد کنید.
$logFiles = [
    'access.log', // فایل نمونه شما
    // --- مسیرهای رایج در سرورهای لینوکسی (حتماً متناسب با سرور خود فعال کنید) ---
    // '/var/log/httpd/access_log',      // لاگ دسترسی آپاچی
    // '/var/log/httpd/error_log',       // لاگ خطای آپاچی
    // '/var/log/secure',                // لاگ‌های امنیتی (SSH, Sudo) در CentOS/RHEL
    // '/var/log/auth.log',              // لاگ‌های امنیتی (SSH, Sudo) در Debian/Ubuntu
    // '/var/log/maillog',               // لاگ ایمیل
    // '/var/log/messages',              // لاگ عمومی سیستم در CentOS/RHEL (شامل کرنل)
    // '/var/log/syslog',                // لاگ عمومی سیستم در Debian/Ubuntu (شامل کرنل)
    // '/var/log/php-fpm/www-error.log', // لاگ خطای PHP-FPM
];

// --- توابع اصلی ---

// [تابع parse_line با تمام تحلیلگرهای سیستمی و امنیتی بدون تغییر باقی می‌ماند]
function parse_line($line) {
    $line = trim($line);
    if (empty($line)) return null;
    $patterns = [
        'kernel_panic' => function($line) { $pattern = '/^(?<timestamp>\w{3}\s+\d+\s+[\d:]+) .*? kernel: Kernel panic - not syncing: (?<message>.*)$/'; if (preg_match($pattern, $line, $matches)) { return ['type' => 'system_critical', 'timestamp' => $matches['timestamp'], 'timestamp_unix' => strtotime($matches['timestamp']), 'ip' => 'CRITICAL', 'message' => 'Kernel Panic!', 'full_log_message' => $line, 'attack_details' => ['type' => 'System Crash', 'subtype' => 'Kernel Panic', 'description' => 'یک خطای بسیار جدی در سطح هسته (Kernel Panic) رخ داده که منجر به کرش کامل سرور شده است.', 'mitigation' => 'این خطاها معمولاً به دلیل مشکلات سخت‌افزاری (RAM خراب)، درایورهای ناسازگار یا باگ‌های هسته رخ می‌دهają. سرور را از نظر سخت‌افزاری بررسی کرده و سیستم‌عامل را به‌روز کنید.']]; } return null; },
        'oom_killer' => function($line) { $pattern = '/^(?<timestamp>\w{3}\s+\d+\s+[\d:]+) .*? kernel: Out of memory: Kill process (?<pid>\d+) \((?<process>.*?)\)/'; if (preg_match($pattern, $line, $matches)) { return ['type' => 'system_warning', 'timestamp' => $matches['timestamp'], 'timestamp_unix' => strtotime($matches['timestamp']), 'ip' => 'SYSTEM', 'message' => 'Out of Memory Killer invoked', 'full_log_message' => $line, 'attack_details' => ['type' => 'Resource Exhaustion', 'subtype' => 'OOM Killer', 'description' => 'سرور با کمبود شدید حافظه RAM مواجه شده و هسته برای جلوگیری از کرش، پروسه "'.htmlspecialchars($matches['process']).'" را به اجبار بسته است.', 'mitigation' => 'مصرف حافظه سرور را با دستور `free -h` و `top` بررسی کنید. ممکن است نیاز به افزایش RAM یا Swap داشته باشید یا سرویس‌های پرمصرف را بهینه‌سازی کنید.']]; } return null; },
        'hardware_error' => function($line) { $pattern = '/^(?<timestamp>\w{3}\s+\d+\s+[\d:]+) .*? kernel: .*?(I\/O error|Hardware Error|MCE|ata error|SCSI error).*? on device (?<device>\S+)/i'; if (preg_match($pattern, $line, $matches)) { return ['type' => 'system_critical', 'timestamp' => $matches['timestamp'], 'timestamp_unix' => strtotime($matches['timestamp']), 'ip' => 'HARDWARE', 'message' => 'Hardware Error Detected', 'full_log_message' => $line, 'attack_details' => ['type' => 'System Failure', 'subtype' => 'Hardware Error', 'description' => 'یک خطای سخت‌افزاری روی دستگاه "'.htmlspecialchars($matches['device']).'" شناسایی شد. این می‌تواند نشانه خرابی دیسک، RAM یا CPU باشد.', 'mitigation' => 'فوراً وضعیت سلامت سخت‌افزار سرور را بررسی کنید. برای دیسک از ابزار S.M.A.R.T (دستور `smartctl -a /dev/sda`) و برای حافظه از ابزار memtest86 استفاده کنید.']]; } return null; },
        'system_boot' => function($line) { $pattern = '/^(?<timestamp>\w{3}\s+\d+\s+[\d:]+) .*? kernel: Linux version .*?$/'; if (preg_match($pattern, $line, $matches)) { return ['type' => 'system_event', 'timestamp' => $matches['timestamp'], 'timestamp_unix' => strtotime($matches['timestamp']), 'ip' => 'SYSTEM', 'message' => 'System startup detected', 'full_log_message' => $line, 'attack_details' => ['type' => 'System Event', 'subtype' => 'System Boot', 'description' => 'سیستم در این زمان راه‌اندازی شده است. اگر این یک ری‌استارت برنامه‌ریزی نشده بوده، لاگ‌های قبل از این زمان را برای یافتن علت بررسی کنید.', 'mitigation' => 'برای تحلیل علت ری‌استارت، از دستور `journalctl -b -1` یا `last -x` در ترمینال برای مشاهده لاگ‌های بوت و خاموش شدن قبلی استفاده کنید.']]; } return null; },
        'sudo_usage' => function($line) { $pattern = '/^(?<timestamp>\w{3}\s+\d+\s+[\d:]+) .*? (?:sudo|su)\[\d+\]: \s*(?<user>\S+) : (?<result>.*? session opened|COMMAND=.*)$/'; if (preg_match($pattern, $line, $matches)) { return ['type' => 'system_security', 'timestamp' => $matches['timestamp'], 'timestamp_unix' => strtotime($matches['timestamp']), 'ip' => 'LOCAL', 'message' => 'Root access by user '.$matches['user'], 'full_log_message' => $line, 'attack_details' => ['type' => 'Security Event', 'subtype' => 'Root Access', 'description' => 'کاربر "'.htmlspecialchars($matches['user']).'" به سطح دسترسی ریشه (root) دسترسی پیدا کرده است. این یک رویداد امنیتی مهم است.', 'mitigation' => 'اطمینان حاصل کنید که این فعالیت مجاز بوده است. دسترسی به sudo را فقط به کاربران معتمد محدود کنید.']]; } return null; },
        'phpfpm_warning' => function($line) { $pattern = '/^(?<timestamp>\w{3}\s+\d+\s+[\d:]+) .*? php-fpm: .*? WARNING: \[pool .*?\] server reached max_children setting \((?<limit>\d+)\)/'; if (preg_match($pattern, $line, $matches)) { return ['type' => 'service_warning', 'timestamp' => $matches['timestamp'], 'timestamp_unix' => strtotime($matches['timestamp']), 'ip' => 'SERVICE', 'message' => 'PHP-FPM reached process limit', 'full_log_message' => $line, 'attack_details' => ['type' => 'Service Health', 'subtype' => 'PHP-FPM Limit', 'description' => 'سرویس PHP-FPM به حداکثر تعداد پردازش‌های مجاز ('.htmlspecialchars($matches['limit']).') رسیده است. این موضوع باعث کندی شدید یا از دسترس خارج شدن سایت می‌شود.', 'mitigation' => 'مقدار `pm.max_children` را در فایل پیکربندی PHP-FPM pool خود افزایش دهید. همچنین کدهای PHP را برای پیدا کردن اسکریپت‌های کند و زمان‌بر بهینه‌سازی کنید.']]; } return null; },
        'json_audit' => function($line) { if (strpos($line, '{"transaction":') === 0) { $data = json_decode($line, true); if (json_last_error() === JSON_ERROR_NONE && isset($data['audit_data']['messages'][0])) { $attack_message = $data['audit_data']['messages'][0]; $attack_details = detect_attack_from_waf_log($attack_message); if ($attack_details) { return ['type' => 'json_audit', 'timestamp' => $data['transaction']['time'], 'timestamp_unix' => strtotime(preg_replace('/:[0-9]{6}\s/', ' ', $data['transaction']['time'])), 'ip' => $data['transaction']['remote_address'], 'message' => $data['request']['request_line'] ?? 'N/A', 'user_agent' => $data['request']['headers']['User-Agent'] ?? 'N/A', 'full_log_message' => $attack_message, 'attack_details' => $attack_details]; } } } return null; },
        'ssh_log' => function($line) { $pattern = '/^(?<timestamp>\w{3}\s+\d+\s+[\d:]+) .*? sshd\[\d+\]: Failed password for (?<invalid>invalid user )?(?<user>\S+) from (?<ip>[\d\.]+) port \d+ ssh2$/'; if (preg_match($pattern, $line, $matches)) { $user_type = empty($matches['invalid']) ? 'کاربر معتبر' : 'کاربر نامعتبر'; $details = ['type' => 'Brute-Force', 'subtype' => 'SSH Auth Failure', 'description' => 'تلاش ناموفق برای ورود به سرور از طریق SSH با نام کاربری '.htmlspecialchars($matches['user']).' ('.$user_type.') ثبت شده است.', 'mitigation' => 'این IP را فوراً در فایروال مسدود کنید. پورت SSH را به یک عدد غیر استاندارد تغییر دهید و ورود با رمز عبور را برای کاربر root غیرفعال کرده و از کلیدهای SSH استفاده کنید.', 'matched_pattern' => $matches['user']]; return ['type' => 'ssh_log', 'timestamp' => $matches['timestamp'], 'timestamp_unix' => strtotime($matches['timestamp']), 'ip' => $matches['ip'], 'message' => "Failed SSH login for {$user_type} '{$matches['user']}'", 'full_log_message' => $line, 'attack_details' => $details]; } return null; },
        'mail_log' => function($line) { $exim_pattern = '/^(?<timestamp>\S+ \S+) login authenticator failed for .*? \[(?<ip>[\d\.:a-fA-F]+)\]: .*?\(set_id=(?<user>.*?)\)$/'; if (preg_match($exim_pattern, $line, $matches)) { return ['type' => 'mail_log', 'timestamp' => $matches['timestamp'], 'timestamp_unix' => strtotime($matches['timestamp']), 'ip' => $matches['ip'], 'message' => "Failed mail login for user: " . $matches['user'], 'full_log_message' => $line, 'attack_details' => ['type' => 'Brute-Force', 'subtype' => 'SMTP/IMAP Auth Failure', 'description' => 'تلاش ناموفق برای ورود به ایمیل با نام کاربری '.htmlspecialchars($matches['user']).'. تکرار این خطا نشانه حمله Brute-Force است.', 'mitigation' => 'این IP را در فایروال مسدود کنید. از رمزهای عبور قوی برای ایمیل‌ها استفاده کنید.']]; } $dovecot_pattern = '/^(?<timestamp>\w{3}\s+\d+\s+[\d:]+) .*? dovecot\[\d+\]: .*?-login: Disconnected: .*?(?:no auth attempts|Too many invalid commands).*?rip=(?<ip>[\d\.]+),/'; if (preg_match($dovecot_pattern, $line, $matches)) { return ['type' => 'mail_log', 'timestamp' => $matches['timestamp'], 'timestamp_unix' => strtotime($matches['timestamp']), 'ip' => $matches['ip'], 'message' => 'Suspicious disconnect from mail server', 'full_log_message' => $line, 'attack_details' => ['type' => 'Connection Scan', 'subtype' => 'POP3/IMAP Scan', 'description' => 'یک اتصال به سرور ایمیل برقرار و بدون تلاش برای احراز هویت یا با دستورات نامعتبر قطع شده است. این رفتار معمولاً مربوط به اسکنرهای امنیتی است.', 'mitigation' => 'فایروال شما باید این IPها را در صورت تکرار خطا به صورت خودکار مسدود کند (مانند کاری که Fail2Ban انجام می‌دهد).']]; } return null; },
        'firewall_log' => function($line) { $pattern = '/^(?<timestamp>\w{3}\s+\d+\s+[\d:]+) .*? kernel: .*?(?:Firewall: \*)?(?<action>\S+)\s+Blocked\*?.*?SRC=(?<ip>[\d\.]+) .*?PROTO=(?<protocol>\S+)(?: DPT=(?<dpt>\d+))?/'; if (preg_match($pattern, $line, $matches)) { $protocol = $matches['protocol']; $dpt = $matches['dpt'] ?? 'N/A'; $description = "ترافیک {$protocol} به پورت {$dpt} از IP ".htmlspecialchars($matches['ip'])." توسط فایروال مسدود شده است."; $subtype = ($protocol === 'ICMP') ? 'ICMP Scan (Ping)' : 'Port Scan'; return ['type' => 'firewall_log', 'timestamp' => $matches['timestamp'], 'timestamp_unix' => strtotime($matches['timestamp']), 'ip' => $matches['ip'], 'message' => "Firewall blocked {$protocol} packet to port {$dpt}", 'full_log_message' => $line, 'attack_details' => ['type' => 'Firewall Block', 'subtype' => $subtype, 'description' => $description, 'mitigation' => 'فایروال شما به درستی کار کرده است. این بسته‌ها معمولاً توسط اسکنرهای خودکار ارسال می‌شوند. نیازی به اقدام فوری نیست مگر اینکه تعداد آن‌ها بسیار زیاد باشد.']]; } return null; },
        'access_log' => function($line) { $pattern = '/^(?<ip>[\d\.]+) \S+ \S+ \[(?<timestamp>.*?)\].*?"(?<method>GET|POST|PUT|DELETE|HEAD) (?<url>.*?) HTTP.*?" (?<code>\d{3}) (?<size>\d+) "(?<referrer>.*?)" "(?<agent>.*?)"$/'; if (preg_match($pattern, $line, $matches)) { $attack_details = detect_attack_from_access_log($matches['url']); if ($attack_details) { return ['type' => 'access_log', 'timestamp' => $matches['timestamp'], 'timestamp_unix' => strtotime($matches['timestamp']), 'ip' => $matches['ip'], 'message' => $matches['method'] . ' ' . $matches['url'], 'user_agent' => $matches['agent'], 'full_log_message' => $line, 'attack_details' => $attack_details]; } } return null; },
    ];
    foreach ($patterns as $parser_function) { $parsed = $parser_function($line); if ($parsed) return $parsed; } return null;
}

/**
 * [بهبود یافته] توابع تشخیص حمله با توضیحات و هایلایت
 */
function detect_attack_from_waf_log($message) {
    $definitions = [
        ['type' => 'WAF Block', 'subtype' => 'Sensitive File Access', 'pattern' => '/Matched phrase "(\/\.env|\/\.git|\/wp-config\.php|sftp-config\.json|\/app\/etc\/local\.xml|\.bak)"/i', 'description' => 'فایروال دسترسی به یک فایل حساس را مسدود کرده است.', 'mitigation' => 'فایروال به درستی کار کرده است. اطمینان حاصل کنید که این فایل‌ها خارج از پوشه public_html قرار دارند.', 'explanation' => 'حمله "دسترسی به فایل حساس" زمانی رخ می‌دهد که مهاجم تلاش می‌کند فایل‌های پیکربندی یا حیاتی سرور را مستقیماً دانلود کند تا به اطلاعاتی مانند رمز عبور دیتابیس دست یابد.'],
        ['type' => 'WAF Block', 'subtype' => 'PHP Injection', 'pattern' => '/(COMODO WAF: PHP Injection Attack|php:\/\/input)/i', 'description' => 'فایروال یک تلاش بسیار خطرناک برای تزریق کد PHP را مسدود کرده است.', 'mitigation' => 'فایروال به درستی عمل کرده است. کد خود را برای هرگونه آسیب‌پذیری RCE (اجرای کد از راه دور) بازبینی کنید.', 'explanation' => 'در این حمله، مهاجم تلاش می‌کند کدهای PHP مخرب را مستقیماً در ورودی‌های برنامه شما تزریق و اجرا کند تا کنترل سرور را به دست بگیرد. این یکی از خطرناک‌ترین حملات است.'],
    ];
    foreach ($definitions as $def) {
        if (preg_match($def['pattern'], $message, $matches)) {
            if (isset($matches[1])) {
                $def['description'] = str_replace('یک فایل حساس', 'فایل حساس "'.htmlspecialchars($matches[1]).'"', $def['description']);
                $def['matched_pattern'] = $matches[1]; // بخش قابل هایلایت
            }
            return $def;
        }
    }
    return null;
}
function detect_attack_from_access_log($url) {
    $decoded_url = urldecode($url);
    $definitions = [
        ['type' => 'Potential Attack', 'subtype' => 'Path Traversal', 'pattern' => '/(\.\.\/|%2e%2e%2f)/i', 'description' => 'تلاش برای پیمایش مسیر (Path Traversal) شناسایی شد.', 'mitigation' => 'تمام ورودی‌های کاربر که برای دسترسی به فایل‌ها استفاده می‌شود را به دقت اعتبارسنجی کنید.', 'explanation' => 'در حمله "پیمایش مسیر"، مهاجم با استفاده از الگوی `../` تلاش می‌کند از دایرکتوری وب‌سایت شما خارج شده و به فایل‌های حساس سیستم‌عامل (مانند `/etc/passwd`) دسترسی پیدا کند.'],
        ['type' => 'Potential Attack', 'subtype' => 'SQL Injection', 'pattern' => '/\b(union|select|insert|concat|from|where|--|;)\b/i', 'description' => 'تلاش برای تزریق SQL شناسایی شد.', 'mitigation' => 'همیشه از Prepared Statements (با PDO یا MySQLi) برای کار با دیتابیس استفاده کنید.', 'explanation' => 'در حمله "تزریق SQL"، مهاجم تلاش می‌کند با وارد کردن دستورات SQL در ورودی‌های برنامه (مانند فرم‌ها یا URL)، کوئری‌های دیتابیس شما را دستکاری کرده و به اطلاعات جداول دسترسی پیدا کند یا آن‌ها را تخریب کند.'],
        ['type' => 'Potential Attack', 'subtype' => 'XSS Attempt', 'pattern' => '/(<script>|alert\(|onerror=)/i', 'description' => 'تلاش برای حمله XSS شناسایی شد.', 'mitigation' => 'تمام خروجی‌هایی که در صفحه HTML نمایش می‌دهید را با تابع `htmlspecialchars` پاکسازی کنید.', 'explanation' => 'در حمله "Cross-Site Scripting" یا XSS، مهاجم تلاش می‌کند کدهای جاوا اسکریپت مخرب را در وب‌سایت شما تزریق کند تا این کدها در مرورگر کاربران دیگر اجرا شده و اطلاعات آن‌ها (مانند کوکی‌ها) به سرقت برود.'],
    ];
    foreach ($definitions as $def) {
        if (preg_match($def['pattern'], $decoded_url, $matches)) {
            $def['matched_pattern'] = $matches[0]; // بخش قابل هایلایت
            return $def;
        }
    }
    return null;
}

// ... توابع get_country_from_ip و country_code_to_emoji بدون تغییر ...
function get_country_from_ip($ip) { static $cache = []; if (isset($cache[$ip])) { return $cache[$ip]; } if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) { return 'N/A'; } if (!function_exists('curl_init')) { return 'cURL needed'; } $url = "http://ip-api.com/json/{$ip}?fields=status,country,countryCode"; $ch = curl_init(); curl_setopt($ch, CURLOPT_URL, $url); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); curl_setopt($ch, CURLOPT_TIMEOUT, 3); curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2); $response = curl_exec($ch); if (curl_errno($ch)) { $response = false; } curl_close($ch); if ($response !== false) { $data = json_decode($response, true); if (json_last_error() === JSON_ERROR_NONE && isset($data['status']) && $data['status'] === 'success' && isset($data['countryCode'])) { $country_code = htmlspecialchars($data['countryCode']); $country_name = htmlspecialchars($data['country']); $cache[$ip] = country_code_to_emoji($country_code) . ' ' . $country_name; return $cache[$ip]; } } return $cache[$ip] = 'Unknown'; }
function country_code_to_emoji($code) { if (empty($code) || strlen($code) !== 2) { return '🌍'; } $code = strtoupper($code); $regional_indicator_a = 0x1F1E6; $offset = ord('A'); $emoji = mb_convert_encoding('&#'.($regional_indicator_a + (ord($code[0]) - $offset)).';', 'UTF-8', 'HTML-ENTITIES'); $emoji .= mb_convert_encoding('&#'.($regional_indicator_a + (ord($code[1]) - $offset)).';', 'UTF-8', 'HTML-ENTITIES'); return $emoji; }

// ... پردازش اصلی بدون تغییر ...
$stats = ['total_lines' => 0, 'total_attacks' => 0, 'attack_counts' => []]; $all_logs = []; $ip_counts = [];
foreach ($logFiles as $logFile) { if (file_exists($logFile) && is_readable($logFile)) { $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES); $stats['total_lines'] += count($lines); foreach ($lines as $line) { $parsed = parse_line($line); if ($parsed && !empty($parsed['attack_details'])) { $stats['total_attacks']++; $type = $parsed['attack_details']['type']; $stats['attack_counts'][$type] = ($stats['attack_counts'][$type] ?? 0) + 1; if(!empty($parsed['ip'])) { $ip_counts[$parsed['ip']] = ($ip_counts[$parsed['ip']] ?? 0) + 1; } $all_logs[] = $parsed; } } } }
usort($all_logs, function($a, $b) { return ($b['timestamp_unix'] ?? 0) <=> ($a['timestamp_unix'] ?? 0); });
arsort($ip_counts);

?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تحلیلگر جامع لاگ سرور</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root { 
            --color-bg: #f4f7f9; --color-card: #ffffff; --color-text: #333333; --color-primary: #007bff; 
            --color-border: #e0e5eb; --color-danger: #dc3545; --color-warning: #fd7e14; 
            --color-system-critical: #721c24; --color-system-warning: #856404; --color-system-event: #495057;   
        } 
        body { font-family: 'Vazirmatn', sans-serif; background-color: var(--color-bg); color: var(--color-text); margin: 0; padding: 20px; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background-color: var(--color-card); padding: 25px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); margin-bottom: 25px; }
        h1, h2 { color: var(--color-primary); border-bottom: 2px solid var(--color-border); padding-bottom: 10px; margin-top: 0; font-weight: 700; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; }
        .stat-card { background-color: var(--color-bg); padding: 20px; border-radius: 8px; text-align: center; border: 1px solid var(--color-border); }
        .stat-card .number { font-size: 2.2em; font-weight: 700; color: var(--color-primary); }
        .stat-card .label { font-size: 1em; color: #666; margin-top: 5px; }
        details { border-left: 5px solid #ccc; border-radius: 8px; margin-bottom: 15px; overflow: hidden; border: 1px solid var(--color-border); }
        
        details[data-type="system_critical"] { border-left-color: var(--color-system-critical); background-color: #f8d7da; }
        details[data-type="system_warning"], details[data-type="service_warning"] { border-left-color: var(--color-system-warning); background-color: #fff3cd; }
        details[data-type="system_event"], details[data-type="system_security"] { border-left-color: var(--color-system-event); }
        
        summary { padding: 15px; cursor: pointer; display: grid; grid-template-columns: 140px auto 180px; gap: 15px; align-items: center; font-size: 0.9em; background-color: #f8f9fa; }
        summary:hover { background-color: #f1f3f5; }
        .summary-ip { font-weight: 700; color: var(--color-danger); font-family: monospace; }
        .summary-ip[data-ip-type="CRITICAL"] { color: var(--color-system-critical); }
        .summary-ip[data-ip-type="SYSTEM"] { color: var(--color-system-event); }
        .summary-msg { color: #444; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .summary-type { padding: 4px 10px; border-radius: 12px; font-size: 0.8em; text-align: center; font-weight: 700; }
        .attack-content { padding: 15px; background-color: #fff; }
        .attack-content code { background-color: #e9ecef; padding: 10px; border-radius: 4px; direction: ltr; display: block; text-align: left; white-space: pre-wrap; word-wrap: break-word; font-size: 0.85em; margin-top: 5px; }
        .mitigation { background-color: #e3f2fd; border-right: 4px solid var(--color-primary); padding: 10px; margin-top: 10px; border-radius: 4px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: right; padding: 12px; border-bottom: 1px solid var(--color-border); }
        th { background-color: #f2f2f2; }
        .htaccess-code { background-color: #e9ecef; color: #495057; padding: 5px 10px; border-radius: 4px; font-family: 'Courier New', Courier, monospace; direction: ltr; text-align: left; }
        .charts-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 30px; align-items: center; }
        
        /* [جدید] استایل برای هایلایت و توضیحات */
        .highlight {
            background-color: #f8d7da;
            color: #721c24;
            padding: 2px 4px;
            border-radius: 3px;
            font-weight: bold;
        }
        .explanation-box {
            background-color: #f0f7ff;
            border-left: 4px solid #007bff;
            padding: 10px;
            margin-top: 15px;
            border-radius: 4px;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- بخش‌های آمار کلی، نمودارها و جدول مهاجمان برتر بدون تغییر -->
        <h1>تحلیلگر جامع لاگ سرور</h1>
        <div class="card">
            <h2>آمار کلی</h2>
            <div class="stats-grid">
                <div class="stat-card"><div class="number"><?php echo number_format($stats['total_lines']); ?></div><div class="label">کل خطوط خوانده شده</div></div>
                <div class="stat-card"><div class="number" style="color:var(--color-danger)"><?php echo number_format($stats['total_attacks']); ?></div><div class="label">رویدادهای امنیتی</div></div>
                <?php foreach($stats['attack_counts'] as $type => $count): ?>
                    <div class="stat-card"><div class="number"><?php echo number_format($count); ?></div><div class="label"><?php echo htmlspecialchars($type); ?></div></div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php if (!empty($stats['attack_counts']) && !empty($ip_counts)): ?>
        <div class="card">
            <h2>گزارش‌های نموداری</h2>
            <div class="charts-grid">
                <div><canvas id="attackTypesChart"></canvas></div>
                <div><canvas id="topAttackersChart"></canvas></div>
            </div>
        </div>
        <?php endif; ?>
        <div class="card">
            <h2>مهاجمان برتر (Top 10 IPs)</h2>
            <?php if (empty($ip_counts)): ?>
                <p>هیچ مهاجمی با IP شناسایی نشد.</p>
            <?php else: ?>
            <table>
                <thead><tr><th>IP آدرس</th><th>کشور</th><th>تعداد رویداد</th><th>دستور مسدودسازی</th></tr></thead>
                <tbody>
                    <?php foreach(array_slice($ip_counts, 0, 10) as $ip => $count): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($ip); ?></td>
                        <td><?php echo get_country_from_ip($ip); ?></td>
                        <td><?php echo number_format($count); ?></td>
                        <td><code class="htaccess-code">deny from <?php echo htmlspecialchars($ip); ?></code></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>

        <!-- [بهبود یافته] بخش جزئیات رویدادها -->
        <div class="card">
            <h2>جزئیات رویدادهای امنیتی (مرتب شده بر اساس زمان)</h2>
            <?php if (empty($all_logs)): ?>
                <p>هیچ رویداد امنیتی در لاگ‌ها یافت نشد.</p>
            <?php else: ?>
                <?php foreach ($all_logs as $log): ?>
                    <details data-type="<?php echo $log['type']; ?>">
                        <summary>
                            <span class="summary-ip" data-ip-type="<?php echo htmlspecialchars($log['ip'] ?? 'SYSTEM'); ?>"><?php echo htmlspecialchars($log['ip'] ?? 'SYSTEM'); ?></span>
                            <span class="summary-msg" title="<?php echo htmlspecialchars($log['full_log_message']); ?>"><?php echo htmlspecialchars($log['attack_details']['description']); ?></span>
                            <span class="summary-type"><?php echo htmlspecialchars($log['attack_details']['subtype']); ?></span>
                        </summary>
                        <div class="attack-content">
                            <p><strong>نوع رویداد:</strong> <?php echo htmlspecialchars($log['attack_details']['type']); ?><br><strong>زمان:</strong> <?php echo htmlspecialchars($log['timestamp']); ?><br></p>
                            
                            <p><strong>پیام کامل لاگ (بخش خطرناک هایلایت شده است):</strong><br>
                                <code><?php
                                    $full_log = htmlspecialchars($log['full_log_message']);
                                    if (!empty($log['attack_details']['matched_pattern'])) {
                                        $pattern = htmlspecialchars($log['attack_details']['matched_pattern']);
                                        $highlighted = '<span class="highlight">' . $pattern . '</span>';
                                        // برای جلوگیری از هایلایت شدن موارد مشابه در بخش‌های دیگر لاگ، از preg_quote استفاده می‌کنیم
                                        echo preg_replace('/' . preg_quote($pattern, '/') . '/', $highlighted, $full_log, 1);
                                    } else {
                                        echo $full_log;
                                    }
                                ?></code>
                            </p>

                            <?php if (!empty($log['attack_details']['explanation'])): ?>
                                <div class="explanation-box">
                                    <strong>این حمله چیست؟</strong><br>
                                    <?php echo htmlspecialchars($log['attack_details']['explanation']); ?>
                                </div>
                            <?php endif; ?>

                            <div class="mitigation">
                                <strong>راهکار پیشنهادی:</strong><br>
                                <?php echo htmlspecialchars($log['attack_details']['mitigation']); ?>
                            </div>
                        </div>
                    </details>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>

    <!-- اسکریپت نمودارها بدون تغییر -->
    <?php if (!empty($stats['attack_counts']) && !empty($ip_counts)): ?>
    <script>
        document.addEventListener('DOMContentLoaded', function () {
            const attackCountsData = <?php echo json_encode(array_values($stats['attack_counts'])); ?>;
            const attackCountsLabels = <?php echo json_encode(array_keys($stats['attack_counts'])); ?>;
            const topIpsData = <?php echo json_encode(array_values(array_slice($ip_counts, 0, 10))); ?>;
            const topIpsLabels = <?php echo json_encode(array_keys(array_slice($ip_counts, 0, 10))); ?>;

            const ctxTypes = document.getElementById('attackTypesChart').getContext('2d');
            new Chart(ctxTypes, { type: 'doughnut', data: { labels: attackCountsLabels, datasets: [{ label: 'تعداد رویداد', data: attackCountsData, backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#20c997', '#0dcaf0', '#6f42c1', '#d63384', '#721c24', '#495057'], borderColor: '#fff', borderWidth: 2, hoverOffset: 8 }] }, options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { fontFamily: 'Vazirmatn' } }, title: { display: true, text: 'توزیع انواع رویدادهای امنیتی', font: { size: 16, family: 'Vazirmatn' } } } } });
            
            const ctxAttackers = document.getElementById('topAttackersChart').getContext('2d');
            new Chart(ctxAttackers, { type: 'bar', data: { labels: topIpsLabels, datasets: [{ label: 'تعداد حملات', data: topIpsData, backgroundColor: 'rgba(0, 123, 255, 0.7)', borderColor: 'rgba(0, 123, 255, 1)', borderWidth: 1, borderRadius: 4 }] }, options: { responsive: true, indexAxis: 'y', scales: { y: { ticks: { font: { family: 'monospace' } } }, x: { beginAtZero: true } }, plugins: { legend: { display: false }, title: { display: true, text: '۱۰ مهاجم برتر بر اساس IP', font: { size: 16, family: 'Vazirmatn' } } } } });
        });
    </script>
    <?php endif; ?>
</body>
</html>
