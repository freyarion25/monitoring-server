<?php
// Auto loader untuk monitoring - Include file ini di SETIAP halaman PHP
// Cara include: require_once '/home/chiacundippal/monitoring/autoload.php';

// Path absolut ke direktori monitoring
define('MONITORING_PATH', '/home/atmlink.id/monitor');

// Load konfigurasi
require_once MONITORING_PATH . '/config.php';

// Fungsi utama monitoring
function runSecurityMonitor($enableTelegram = true) {
    static $alreadyRun = false;
    
    // Hindari eksekusi ganda dalam 1 request
    if ($alreadyRun) return true;
    $alreadyRun = true;
    
    $info = getRequestInfo();
    
    // JANGAN alert untuk IP lokal (testing sendiri)
    if (isLocalIp($info['ip'])) {
        saveToLog('LOCAL_ACCESS', "Akses lokal dari {$info['ip']}", $info);
        return true;
    }
    
    // ========== 1. DETEKSI BRUTE FORCE ==========
    if (detectBruteForce($info['ip'])) {
        $alertType = "🔐 BRUTE FORCE DETECTED";
        $message = formatAlertMessage($alertType, $info, "Banyak request dalam 5 menit");
        if ($enableTelegram) sendTelegramAlert($message);
        saveToLog('BRUTE_FORCE', "Brute force attack dari {$info['ip']}", $info);
        
        // Optional: Delay response untuk memperlambat attacker
        usleep(500000); // 0.5 detik
    }
    
    // ========== 2. DETEKSI IP BLACKLIST ==========
    global $BLACKLIST_IP;
    if (in_array($info['ip'], $BLACKLIST_IP)) {
        $alertType = "⛔ BLACKLISTED IP";
        $message = formatAlertMessage($alertType, $info, "IP dalam daftar hitam");
        if ($enableTelegram) sendTelegramAlert($message);
        saveToLog('BLACKLIST', "IP terblokir: {$info['ip']}", $info);
        
        header('HTTP/1.0 403 Forbidden');
        die("<h1>Access Denied</h1><p>Your IP has been blocked.</p>");
    }
    
    // ========== 3. DETEKSI USER AGENT HACKER ==========
    global $SUSPICIOUS_UA;
    foreach ($SUSPICIOUS_UA as $suspect) {
        if (stripos($info['user_agent'], $suspect) !== false) {
            $alertType = "🛠️ HACKING TOOL DETECTED";
            $message = formatAlertMessage($alertType, $info, "Tool: {$suspect}");
            if ($enableTelegram) sendTelegramAlert($message);
            saveToLog('HACKING_TOOL', "Hacking tool terdeteksi: {$suspect}", $info);
            break;
        }
    }
    
    // ========== 4. DETEKSI PATH TRAVERSAL ==========
    $dangerousPatterns = ['../', '..\\', '%2e%2e%2f', '%2e%2e%5c', '..%252f'];
    foreach ($dangerousPatterns as $pattern) {
        if (strpos($_SERVER['REQUEST_URI'], $pattern) !== false) {
            $alertType = "🗂️ PATH TRAVERSAL ATTEMPT";
            $message = formatAlertMessage($alertType, $info, "Mencoba akses: {$pattern}");
            if ($enableTelegram) sendTelegramAlert($message);
            saveToLog('PATH_TRAVERSAL', "Path traversal: {$_SERVER['REQUEST_URI']}", $info);
            break;
        }
    }
    
    // ========== 5. DETEKSI XSS ==========
    foreach ([$_GET, $_POST, $_COOKIE] as $source) {
        foreach ($source as $key => $value) {
            if (is_string($value)) {
                // XSS Patterns
                if (preg_match('/<script|javascript:|onload=|onerror=|alert\(|prompt\(|confirm\(|onclick=/i', $value)) {
                    $alertType = "💉 XSS ATTACK";
                    $message = formatAlertMessage($alertType, $info, "Parameter: {$key}");
                    if ($enableTelegram) sendTelegramAlert($message);
                    saveToLog('XSS', "XSS attempt pada {$key}", $info);
                    break 2;
                }
                
                // SQL Injection Patterns
                if (preg_match("/(union.*select|select.*from|insert.*into|delete.*from|drop.*table|'or'1'='1|'or 1=1|--|#|\\/\\*|\\*\\/)/i", $value)) {
                    $alertType = "🗄️ SQL INJECTION ATTACK";
                    $message = formatAlertMessage($alertType, $info, "Parameter: {$key}");
                    if ($enableTelegram) sendTelegramAlert($message);
                    saveToLog('SQLI', "SQL injection attempt pada {$key}", $info);
                    break 2;
                }
            }
        }
    }
    
    // ========== 6. LOG AKSES NORMAL ==========
    // Sampling 2% akses untuk menghindari spam Telegram
    if (rand(1, 50) == 1) {
        $alertType = "👀 ACCESS DETECTED";
        $message = formatAlertMessage($alertType, $info, "Normal access");
        if ($enableTelegram) sendTelegramAlert($message);
    }
    
    // Selalu simpan ke log file
    saveToLog('ACCESS', "Akses ke {$_SERVER['REQUEST_URI']}", $info);
    
    return true;
}

// ========== FUNGSI KHUSUS UPLOAD ==========
function checkMaliciousUpload($fileInput, $fieldName = 'file') {
    if (!isset($_FILES[$fieldName]) || $_FILES[$fieldName]['error'] != 0) {
        return true; // Tidak ada file atau error upload
    }
    
    $file = $_FILES[$fieldName];
    $info = getRequestInfo();
    global $DANGEROUS_EXTENSIONS;
    
    $filename = $file['name'];
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $alerts = [];
    
    // Cek ekstensi
    if (in_array($extension, $DANGEROUS_EXTENSIONS)) {
        $alerts[] = "Ekstensi berbahaya: .{$extension}";
    }
    
    // Cek MIME type
    if (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        $dangerousMime = [
            'application/x-httpd-php', 'text/x-php', 'application/php',
            'application/x-asp', 'text/html', 'application/x-javascript',
            'application/x-msdownload', 'application/x-executable'
        ];
        
        if (in_array($mimeType, $dangerousMime)) {
            $alerts[] = "MIME type mencurigakan: {$mimeType}";
        }
    }
    
    // Cek konten file
    $content = file_get_contents($file['tmp_name']);
    $dangerousFunctions = [
        'eval(', 'base64_decode', 'system(', 'exec(', 'passthru(',
        'shell_exec', 'assert(', 'gzinflate', 'str_rot13', 'phpinfo',
        'popen(', 'proc_open(', 'pcntl_exec('
    ];
    
    foreach ($dangerousFunctions as $func) {
        if (stripos($content, $func) !== false) {
            $alerts[] = "Konten mengandung: {$func}";
            break;
        }
    }
    
    // Jika terdeteksi berbahaya
    if (count($alerts) > 0) {
        $alertDetail = implode(", ", $alerts);
        $alertType = "☠️ MALICIOUS FILE UPLOAD";
        $message = formatAlertMessage($alertType, $info, "File: {$filename} - {$alertDetail}");
        sendTelegramAlert($message);
        saveToLog('MALICIOUS_UPLOAD', "File berbahaya: {$filename}", $info);
        
        // Hapus file sementara
        @unlink($file['tmp_name']);
        
        return false; // Upload tidak aman
    }
    
    // Upload aman
    $alertType = "📁 FILE UPLOAD";
    $message = formatAlertMessage($alertType, $info, "File: {$filename} ({$file['size']} bytes)");
    sendTelegramAlert($message);
    saveToLog('UPLOAD', "Upload file: {$filename}", $info);
    
    return true; // Upload aman
}

// JALANKAN MONITORING!
runSecurityMonitor();

// Catatan: File ini akan otomatis berjalan saat di-include
?>
