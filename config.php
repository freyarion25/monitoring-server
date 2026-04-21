<?php
// Konfigurasi Telegram
define('TELEGRAM_BOT_TOKEN', '8403464105:AAHqlFSQuI_x-ZUBtX2h88bzDnWiZsCE4U8');  // GANTI DENGAN TOKEN BOT KAMU
define('TELEGRAM_CHAT_ID', '1640896393');      // GANTI DENGAN CHAT ID KAMU

// Path direktori monitoring (ABSOLUTE)
define('MONITORING_PATH', '/home/atmlink.id/monitor');

// Log file
define('LOG_FILE', MONITORING_PATH . '/activity_log.txt');
define('BF_CACHE', MONITORING_PATH . '/bruteforce_cache.txt');

// Blacklist IP
$BLACKLIST_IP = [
    // '1.2.3.4',
    // '5.6.7.8'
];

// User Agent mencurigakan (hacker tools)
$SUSPICIOUS_UA = [
    'sqlmap', 'nikto', 'nmap', 'wpscan', 'burp', 'masscan', 
    'zgrab', 'dirbuster', 'gobuster', 'wfuzz', 'hydra',
    'openvas', 'nessus', 'acunetix', 'netsparker', 'awvs'
];

// Ekstensi file berbahaya
$DANGEROUS_EXTENSIONS = [
    'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar',
    'asp', 'aspx', 'jsp', 'jspx', 'cfm', 'cfml', 'do',
    'pl', 'py', 'rb', 'sh', 'bash', 'zsh',
    'exe', 'bat', 'cmd', 'com', 'scr', 'vbs', 'ps1'
];

// Ambil informasi request
function getRequestInfo() {
    // Mendeteksi IP asli (support Cloudflare & proxy)
    $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? 
          $_SERVER['HTTP_X_FORWARDED_FOR'] ?? 
          $_SERVER['HTTP_X_REAL_IP'] ?? 
          $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    
    if (strpos($ip, ',') !== false) {
        $ip = explode(',', $ip)[0];
    }
    $ip = trim($ip);
    
    // Deteksi request path lengkap
    $fullPath = $_SERVER['SCRIPT_FILENAME'] ?? 'unknown';
    $requestUri = $_SERVER['REQUEST_URI'] ?? '/';
    
    return [
        'ip' => $ip,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
        'referer' => $_SERVER['HTTP_REFERER'] ?? 'Direct',
        'request_uri' => $requestUri,
        'full_path' => $fullPath,
        'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
        'timestamp' => date('Y-m-d H:i:s'),
        'query_string' => $_SERVER['QUERY_STRING'] ?? ''
    ];
}

// Kirim notifikasi ke Telegram
function sendTelegramAlert($message) {
    $url = "https://api.telegram.org/bot" . TELEGRAM_BOT_TOKEN . "/sendMessage";
    
    $data = [
        'chat_id' => TELEGRAM_CHAT_ID,
        'text' => $message,
        'parse_mode' => 'HTML',
        'disable_web_page_preview' => true
    ];
    
    $options = [
        'http' => [
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data),
            'timeout' => 5,
            'ignore_errors' => true
        ]
    ];
    
    $context = stream_context_create($options);
    @file_get_contents($url, false, $context);
}

// Simpan ke file log
function saveToLog($type, $message, $details = []) {
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'type' => $type,
        'message' => $message,
        'script' => $_SERVER['SCRIPT_FILENAME'] ?? 'unknown',
        'request_uri' => $_SERVER['REQUEST_URI'] ?? '/',
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'details' => $details
    ];
    
    file_put_contents(LOG_FILE, json_encode($logEntry) . PHP_EOL, FILE_APPEND | LOCK_EX);
}

// Deteksi brute force
function detectBruteForce($ip) {
    $timeWindow = 300; // 5 menit
    $maxAttempts = 20; // Maks 20 request mencurigakan dalam 5 menit
    
    $data = [];
    if (file_exists(BF_CACHE)) {
        $content = file_get_contents(BF_CACHE);
        $data = json_decode($content, true) ?: [];
    }
    
    $now = time();
    if (!isset($data[$ip])) {
        $data[$ip] = [];
    }
    
    // Hapus data lama
    $data[$ip] = array_filter($data[$ip], function($t) use ($now, $timeWindow) {
        return ($now - $t) < $timeWindow;
    });
    
    // Tambah request baru
    $data[$ip][] = $now;
    
    // Simpan
    file_put_contents(BF_CACHE, json_encode($data), LOCK_EX);
    
    return count($data[$ip]) > $maxAttempts;
}

// Format pesan alert
function formatAlertMessage($type, $info, $extra = '') {
    $msg = "🚨 <b>SECURITY ALERT</b> 🚨\n";
    $msg .= "━━━━━━━━━━━━━━━━━━━━━\n";
    $msg .= "⚠️ <b>Jenis:</b> {$type}\n";
    $msg .= "🕐 <b>Waktu:</b> {$info['timestamp']}\n";
    $msg .= "🌐 <b>IP Address:</b> <code>{$info['ip']}</code>\n";
    $msg .= "📍 <b>Target:</b> " . basename($info['full_path']) . "\n";
    $msg .= "🔗 <b>URL:</b> {$info['method']} {$info['request_uri']}\n";
    $msg .= "📱 <b>User Agent:</b>\n<code>" . substr($info['user_agent'], 0, 60) . "</code>\n";
    
    if ($info['referer'] != 'Direct' && $info['referer'] != '') {
        $msg .= "🔁 <b>Referer:</b> {$info['referer']}\n";
    }
    
    if ($extra) {
        $msg .= "📎 <b>Detail:</b> {$extra}\n";
    }
    
    if ($info['query_string']) {
        $msg .= "🔍 <b>Query:</b> " . substr($info['query_string'], 0, 100) . "\n";
    }
    
    $msg .= "━━━━━━━━━━━━━━━━━━━━━";
    return $msg;
}

// Cek apakah IP lokal (untuk testing, tidak usah alert)
function isLocalIp($ip) {
    $localRanges = [
        '127.0.0.1', '::1',
        '192.168.', '10.', '172.16.', '172.17.', '172.18.', 
        '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
        '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
        '172.29.', '172.30.', '172.31.'
    ];
    
    foreach ($localRanges as $range) {
        if (strpos($ip, $range) === 0) {
            return true;
        }
    }
    return false;
}
?>
