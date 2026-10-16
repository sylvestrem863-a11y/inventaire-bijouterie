<?php
// functions.php — utilitaires partagés (auth, DB, permissions, images, API tokens, notifications)
session_start();

function get_pdo() {
    static $pdo = null;
    if ($pdo) return $pdo;
    $dbPath = __DIR__ . '/data/inventory.db';
    if (!file_exists($dbPath)) {
        throw new Exception("Base introuvable. Lance install.php d'abord.");
    }
    $pdo = new PDO('sqlite:' . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $pdo;
}

function h($s){ return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }

function current_user() { return $_SESSION['user'] ?? null; }
function require_login() { if (empty($_SESSION['user'])) { header('Location: auth.php?action=login'); exit; } }

function setting_get($key) {
    $pdo = get_pdo();
    $stmt = $pdo->prepare("SELECT value FROM settings WHERE key = :k");
    $stmt->execute([':k'=>$key]);
    $r = $stmt->fetch(PDO::FETCH_ASSOC);
    return $r ? $r['value'] : null;
}
function setting_set($key, $value) {
    $pdo = get_pdo();
    $stmt = $pdo->prepare("INSERT OR REPLACE INTO settings (key,value) VALUES (:k,:v)");
    $stmt->execute([':k'=>$key, ':v'=>$value]);
}

// permissions (viewer < seller < admin)
function check_permission($required) {
    $user = current_user();
    if (!$user) return false;
    $role = $user['role'] ?? 'viewer';
    if (is_array($required)) return in_array($role, $required);
    $levels = ['viewer'=>1,'seller'=>2,'admin'=>3];
    $user_level = $levels[$role] ?? 1;
    $req_level = $levels[$required] ?? 1;
    return $user_level >= $req_level;
}

// API tokens
function create_api_token($user_id, $name = null) {
    $pdo = get_pdo();
    $token = bin2hex(random_bytes(32));
    $stmt = $pdo->prepare("INSERT INTO api_tokens (user_id, token, name) VALUES (:uid,:t,:n)");
    $stmt->execute([':uid'=>$user_id, ':t'=>$token, ':n'=>$name]);
    return $token;
}
function revoke_api_token($token) {
    $pdo = get_pdo();
    $stmt = $pdo->prepare("DELETE FROM api_tokens WHERE token = :t");
    $stmt->execute([':t'=>$token]);
}
function list_api_tokens() {
    $pdo = get_pdo();
    return $pdo->query("SELECT at.id, at.name, at.token, at.user_id, at.created_at, u.username FROM api_tokens at LEFT JOIN users u ON u.id = at.user_id ORDER BY at.created_at DESC")->fetchAll(PDO::FETCH_ASSOC);
}
function verify_api_token($token) {
    $pdo = get_pdo();
    $stmt = $pdo->prepare("SELECT u.id, u.username, u.role FROM api_tokens at JOIN users u ON u.id = at.user_id WHERE at.token = :t LIMIT 1");
    $stmt->execute([':t'=>$token]);
    $u = $stmt->fetch(PDO::FETCH_ASSOC);
    return $u ?: null;
}

// Image handling: upload, resize original if too wide, create thumbnail
function handle_image_upload($fileField, $maxW = 1200, $thumbW = 300) {
    if (empty($_FILES[$fileField]['tmp_name']) || !is_uploaded_file($_FILES[$fileField]['tmp_name'])) return null;
    $tmp = $_FILES[$fileField]['tmp_name'];
    $origName = $_FILES[$fileField]['name'];
    $ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
    $allowed = ['jpg','jpeg','png','gif','webp'];
    if (!in_array($ext, $allowed)) return null;
    $fname = uniqid('img_') . '.' . $ext;
    $dir = __DIR__ . '/data/images/';
    if (!is_dir($dir)) mkdir($dir, 0755, true);
    $target = $dir . $fname;

    if (!move_uploaded_file($tmp, $target)) return null;

    $mime = mime_content_type($target);
    $img = null;
    switch ($mime) {
        case 'image/jpeg': $img = imagecreatefromjpeg($target); break;
        case 'image/png': $img = imagecreatefrompng($target); break;
        case 'image/gif': $img = imagecreatefromgif($target); break;
        case 'image/webp': $img = imagecreatefromwebp($target); break;
        default: $img = null;
    }
    if ($img) {
        $w = imagesx($img); $h = imagesy($img);
        if ($w > $maxW) {
            $newW = $maxW; $newH = (int)($h * ($newW / $w));
            $res = imagecreatetruecolor($newW, $newH);
            imagecopyresampled($res, $img, 0,0,0,0, $newW, $newH, $w, $h);
            switch ($mime) {
                case 'image/jpeg': imagejpeg($res, $target, 85); break;
                case 'image/png': imagepng($res, $target); break;
                case 'image/gif': imagegif($res, $target); break;
                case 'image/webp': imagewebp($res, $target, 85); break;
            }
            imagedestroy($res);
        }
        $thumbH = (int)($h * ($thumbW / $w));
        $thumb = imagecreatetruecolor($thumbW, $thumbH);
        imagecopyresampled($thumb, $img, 0,0,0,0, $thumbW, $thumbH, $w, $h);
        $thumbName = 'thumb_' . $fname;
        $thumbPath = $dir . $thumbName;
        switch ($mime) {
            case 'image/jpeg': imagejpeg($thumb, $thumbPath, 85); break;
            case 'image/png': imagepng($thumb, $thumbPath); break;
            case 'image/gif': imagegif($thumb, $thumbPath); break;
            case 'image/webp': imagewebp($thumb, $thumbPath, 85); break;
        }
        imagedestroy($thumb);
        imagedestroy($img);
    }
    return $fname;
}

// Cleanup orphan images: deletes files not referenced in DB; dryRun=true to only list
function cleanup_orphan_images($dryRun = true) {
    $pdo = get_pdo();
    $files = glob(__DIR__ . '/data/images/*');
    $used = [];
    $stmt = $pdo->query("SELECT image_filename FROM items WHERE image_filename IS NOT NULL");
    while ($r = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $used[$r['image_filename']] = true;
        $used['thumb_' . $r['image_filename']] = true;
    }
    $deleted = [];
    foreach ($files as $f) {
        $basename = basename($f);
        if (!isset($used[$basename])) {
            if (!$dryRun) unlink($f);
            $deleted[] = $basename;
        }
    }
    return $deleted;
}

// Notifications: webhook and email (PHPMailer if available)
function send_webhook($url, $payload) {
    if (!$url) return null;
    $json = json_encode($payload);
    if (function_exists('curl_version')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return ['code'=>$code,'response'=>$resp];
    } else {
        $opts = ['http' => ['method' => 'POST', 'header' => "Content-Type: application/json\r\n", 'content' => $json]];
        $context = stream_context_create($opts);
        $resp = @file_get_contents($url, false, $context);
        return ['code'=>200,'response'=>$resp];
    }
}

// ---------- SMTP / email (PHPMailer if available) ----------
function send_notification_email($to, $subject, $bodyHtml, $bodyText = '') {
    $composerAutoload = __DIR__ . '/vendor/autoload.php';
    if (file_exists($composerAutoload)) {
        require_once $composerAutoload;
        if (class_exists('PHPMailer\PHPMailer\PHPMailer')) {
            $mail = new PHPMailer\PHPMailer\PHPMailer(true);
            try {
                $smtpHost = setting_get('smtp_host') ?: '';
                $smtpPort = setting_get('smtp_port') ?: 587;
                $smtpUser = setting_get('smtp_user') ?: '';
                $smtpPass = setting_get('smtp_pass') ?: '';
                $smtpSecure = setting_get('smtp_secure') ?: 'tls';
                $from = setting_get('smtp_from') ?: 'noreply@example.com';
                $fromName = setting_get('smtp_from_name') ?: 'Inventory';

                $mail->isSMTP();
                if ($smtpHost) $mail->Host = $smtpHost;
                $mail->SMTPAuth = !empty($smtpUser);
                if ($smtpUser) $mail->Username = $smtpUser;
                if ($smtpPass) $mail->Password = $smtpPass;
                $mail->SMTPSecure = ($smtpSecure === 'ssl' ? 'ssl' : 'tls');
                $mail->Port = (int)$smtpPort;

                $mail->setFrom($from, $fromName);
                $mail->addAddress($to);

                $mail->isHTML(true);
                $mail->Subject = $subject;
                $mail->Body = $bodyHtml;
                $mail->AltBody = $bodyText ?: strip_tags($bodyHtml);

                $mail->send();
                return ['ok'=>true, 'msg'=>'sent'];
            } catch (Exception $e) {
                return ['ok'=>false, 'msg'=>'Mailer Error: ' . $mail->ErrorInfo];
            }
        }
    }

    $from = setting_get('smtp_from') ?: 'noreply@example.com';
    $headers = "MIME-Version: 1.0\r\nContent-type: text/html; charset=UTF-8\r\nFrom: $from\r\n";
    $success = mail($to, $subject, $bodyHtml, $headers);
    return ['ok'=>$success, 'msg'=>$success ? 'sent' : 'mail_failed'];
}

function test_smtp_send($to) {
    $subject = 'Test SMTP — Inventaire';
    $body = '<p>Test SMTP envoyé depuis votre application Inventaire.</p>';
    return send_notification_email($to, $subject, $body, 'Test SMTP');
}

// Metals-API fetch (returns €/g)
function fetch_gold_price_api($date = null) {
    $api_key = setting_get('metals_api_key');
    if (!$api_key) return null;
    $endpointDate = $date ? $date : 'latest';
    $url = "https://metals-api.com/api/{$endpointDate}?access_key=" . urlencode($api_key) . "&base=EUR&symbols=XAU";
    $resp = null;
    if (function_exists('curl_version')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($code < 200 || $code >= 300) return null;
    } else {
        $resp = @file_get_contents($url);
        if ($resp === false) return null;
    }
    $data = json_decode($resp, true);
    if (!$data) return null;
    if (isset($data['rates']['XAU']) && $data['rates']['XAU'] > 0) {
        $per_ounce = 1.0 / $data['rates']['XAU'];
        $per_gram = $per_ounce / 31.1034768;
        return floatval($per_gram);
    }
    if (isset($data['price'])) {
        $per_gram = floatval($data['price']) / 31.1034768;
        return $per_gram;
    }
    return null;
}
