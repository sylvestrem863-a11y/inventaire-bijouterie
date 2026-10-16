<?php
// functions.php — shared utilities: auth, DB, permissions, image handling, API tokens, notifications, backups, audit log
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

function audit_log($action, $details = null) {
    try {
        $pdo = get_pdo();
        $user = current_user();
        $stmt = $pdo->prepare("INSERT INTO audit_logs (user_id, username, action, details, ip) VALUES (:uid,:uname,:action,:details,:ip)");
        $stmt->execute([
            ':uid'=>$user['id'] ?? null,
            ':uname'=>$user['username'] ?? null,
            ':action'=>$action,
            ':details'=>is_string($details) ? $details : json_encode($details, JSON_UNESCAPED_UNICODE),
            ':ip'=>$_SERVER['REMOTE_ADDR'] ?? null
        ]);
    } catch (Exception $e) {
        // do not break app on logging failure
    }
}

function create_api_token($user_id, $name = null, $scopes = []) {
    $pdo = get_pdo();
    $token = bin2hex(random_bytes(32));
    $scopesStr = is_array($scopes) ? implode(',', $scopes) : trim((string)$scopes);
    $stmt = $pdo->prepare("INSERT INTO api_tokens (user_id, token, name, scopes) VALUES (:uid,:t,:n,:s)");
    $stmt->execute([':uid'=>$user_id, ':t'=>$token, ':n'=>$name, ':s'=>$scopesStr]);
    audit_log('create_token', ['user_id'=>$user_id,'name'=>$name,'scopes'=>$scopesStr]);
    return $token;
}

function revoke_api_token($token) {
    $pdo = get_pdo();
    $stmt = $pdo->prepare("DELETE FROM api_tokens WHERE token = :t");
    $stmt->execute([':t'=>$token]);
    audit_log('revoke_token', $token);
}

function list_api_tokens() {
    $pdo = get_pdo();
    return $pdo->query("SELECT at.id, at.name, at.token, at.user_id, at.scopes, at.created_at, u.username FROM api_tokens at LEFT JOIN users u ON u.id = at.user_id ORDER BY at.created_at DESC")->fetchAll(PDO::FETCH_ASSOC);
}

function verify_api_token($token) {
    $pdo = get_pdo();
    $stmt = $pdo->prepare("SELECT u.id, u.username, u.role, at.scopes FROM api_tokens at JOIN users u ON u.id = at.user_id WHERE at.token = :t LIMIT 1");
    $stmt->execute([':t'=>$token]);
    $u = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($u) {
        $u['scopes'] = array_values(array_filter(array_map('trim', explode(',', $u['scopes'] ?? ''))));
        return $u;
    }
    return null;
}

function list_audit_logs($limit = 50) {
    $pdo = get_pdo();
    $stmt = $pdo->prepare("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT :limit");
    $stmt->bindValue(':limit', (int)$limit, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

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

function convert_currency($amount, $from, $to) {
    $from = strtoupper($from);
    $to = strtoupper($to);
    if ($from === $to) return $amount;
    $pdo = get_pdo();
    $rateFrom = 1.0; $rateTo = 1.0;
    if ($from !== 'EUR') {
        $stmt = $pdo->prepare("SELECT rate_to_eur FROM exchange_rates WHERE currency = :c LIMIT 1");
        $stmt->execute([':c'=>$from]);
        $r = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$r) return null;
        $rateFrom = floatval($r['rate_to_eur']);
    }
    if ($to !== 'EUR') {
        $stmt = $pdo->prepare("SELECT rate_to_eur FROM exchange_rates WHERE currency = :c LIMIT 1");
        $stmt->execute([':c'=>$to]);
        $r = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$r) return null;
        $rateTo = floatval($r['rate_to_eur']);
    }
    $amount_eur = ($from === 'EUR') ? $amount : ($amount / $rateFrom);
    return ($to === 'EUR') ? $amount_eur : ($amount_eur * $rateTo);
}

function render_template($template, $data) {
    $out = $template;
    foreach ($data as $k => $v) {
        $out = str_replace('{{' . $k . '}}', (string)$v, $out);
    }
    $out = str_replace('{{type}}', $data['type'] ?? '', $out);
    $out = str_replace('{{details}}', json_encode($data, JSON_UNESCAPED_UNICODE), $out);
    return $out;
}

function list_notification_rules() {
    $pdo = get_pdo();
    return $pdo->query("SELECT * FROM notification_rules ORDER BY created_at DESC")->fetchAll(PDO::FETCH_ASSOC);
}

function create_notification_rule($name, $type, $conditionJson, $emails, $webhookUrl, $template, $enabled = 1) {
    $pdo = get_pdo();
    $stmt = $pdo->prepare("INSERT INTO notification_rules (name, type, enabled, condition_json, emails, webhook_url, template) VALUES (:name,:type,:enabled,:cond,:emails,:webhook,:template)");
    $stmt->execute([
        ':name'=>$name,
        ':type'=>$type,
        ':enabled'=>$enabled ? 1 : 0,
        ':cond'=>$conditionJson,
        ':emails'=>$emails,
        ':webhook'=>$webhookUrl,
        ':template'=>$template
    ]);
    audit_log('create_notification_rule', ['name'=>$name,'type'=>$type]);
}

function evaluate_notification_rules($eventType, $payload) {
    $pdo = get_pdo();
    $stmt = $pdo->prepare("SELECT * FROM notification_rules WHERE enabled = 1 AND type = :t");
    $stmt->execute([':t'=>$eventType]);
    $rules = $stmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rules as $r) {
        $cond = json_decode($r['condition_json'] ?? '{}', true);
        $trigger = false;
        if ($eventType === 'price_update' && isset($cond['above'])) {
            if (isset($payload['price_per_gram']) && floatval($payload['price_per_gram']) > floatval($cond['above'])) $trigger = true;
        }
        if ($eventType === 'sale' && isset($cond['min_price'])) {
            if (isset($payload['sale_price']) && floatval($payload['sale_price']) >= floatval($cond['min_price'])) $trigger = true;
        }
        if ($eventType === 'old_stock' && isset($cond['days'])) {
            if (isset($payload['days_in_stock']) && floatval($payload['days_in_stock']) >= floatval($cond['days'])) $trigger = true;
        }
        if ($trigger) {
            $emails = array_filter(array_map('trim', explode(',', $r['emails'] ?? '')));
            $template = $r['template'] ?: "Alert: {{type}}";
            $body = render_template($template, $payload);
            foreach ($emails as $to) {
                send_notification_email($to, "Alert: {$r['name']}", nl2br(h($body)), $body);
            }
            if (!empty($r['webhook_url'])) send_webhook($r['webhook_url'], $payload);
            $pdo->prepare("UPDATE notification_rules SET last_triggered = datetime('now') WHERE id = :id")->execute([':id'=>$r['id']]);
        }
    }
}

function create_backup($keep = 14) {
    $dir = __DIR__ . '/data/backups';
    if (!is_dir($dir)) mkdir($dir, 0755, true);
    $src = __DIR__ . '/data/inventory.db';
    if (!file_exists($src)) return ['ok'=>false, 'msg'=>'Database not found'];
    $ts = date('Ymd_His');
    $dest = "$dir/inventory_{$ts}.db";
    if (!copy($src, $dest)) return ['ok'=>false, 'msg'=>'Copy failed'];
    $zip = "$dest.zip";
    if (class_exists('ZipArchive')) {
        $za = new ZipArchive();
        if ($za->open($zip, ZipArchive::CREATE) === true) {
            $za->addFile($dest, basename($dest));
            $za->close();
            unlink($dest);
        }
    }
    $files = glob($dir . '/inventory_*.db.zip');
    usort($files, function($a,$b){ return filemtime($b) - filemtime($a); });
    $keep = max(1, intval($keep));
    $i = 0; foreach ($files as $f) { if ($i++ >= $keep) @unlink($f); }
    return ['ok'=>true, 'file'=>basename($zip)];
}

function list_backups() {
    $dir = __DIR__ . '/data/backups';
    if (!is_dir($dir)) return [];
    $files = glob($dir . '/inventory_*.db.zip');
    usort($files, function($a,$b){ return filemtime($b) - filemtime($a); });
    $out = [];
    foreach ($files as $f) { $out[] = ['path'=>$f,'name'=>basename($f),'mtime'=>date('c', filemtime($f)),'size'=>filesize($f)]; }
    return $out;
}

function restore_backup($name) {
    $dir = __DIR__ . '/data/backups';
    $file = $dir . '/' . basename($name);
    if (!file_exists($file)) return ['ok'=>false,'msg'=>'backup not found'];
    if (class_exists('ZipArchive')) {
        $za = new ZipArchive();
        if ($za->open($file) === true) {
            $za->extractTo($dir);
            $za->close();
            $dbfile = $dir . '/' . str_replace('.zip','', basename($file));
            if (file_exists($dbfile)) {
                copy($dbfile, __DIR__ . '/data/inventory.db');
                unlink($dbfile);
                return ['ok'=>true];
            }
        }
    }
    return ['ok'=>false,'msg'=>'unzip failed'];
}
