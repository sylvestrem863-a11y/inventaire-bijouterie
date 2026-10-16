<?php
// fetch_fx.php — fetch FX rates from exchangerate.host and store in exchange_rates
require_once __DIR__ . '/functions.php';
$pdo = get_pdo();
try {
    // fetch common currencies
    $symbols = ['USD','CHF'];
    $url = 'https://api.exchangerate.host/latest?base=EUR&symbols=' . implode(',', $symbols);
    if (function_exists('curl_version')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        $resp = curl_exec($ch);
        curl_close($ch);
    } else {
        $resp = @file_get_contents($url);
    }
    $data = $resp ? json_decode($resp, true) : null;
    if (!$data || empty($data['rates'])) { echo "Fetch failed\n"; exit; }
    foreach ($data['rates'] as $c=>$r) {
        $stmt = $pdo->prepare("INSERT OR REPLACE INTO exchange_rates (currency, rate_to_eur, updated_at) VALUES (:c,:r,datetime('now'))");
        $stmt->execute([':c'=>$c, ':r'=>floatval($r)]);
    }
    echo "Updated rates\n";
} catch (Exception $e) { echo 'Error: '.$e->getMessage(); }
