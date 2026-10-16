<?php
// api.php — REST endpoints with token auth and write capabilities (scoped tokens)
require_once __DIR__ . '/functions.php';
header('Content-Type: application/json; charset=utf-8');

// Authenticate token: Authorization: Bearer <token> OR ?api_token=...
$token = null;
$h = $_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null);
if ($h && preg_match('/Bearer\s+(\S+)/', $h, $m)) $token = $m[1];
if (!$token && !empty($_GET['api_token'])) $token = $_GET['api_token'];

$user = $token ? verify_api_token($token) : null;
if (!$user) {
    http_response_code(401);
    echo json_encode(['error'=>'Unauthorized']);
    exit;
}

$action = $_GET['action'] ?? 'items';
$pdo = get_pdo();

function has_scope($user, $scope) {
    if (empty($user['scopes'])) return false;
    return in_array($scope, $user['scopes']);
}

if ($action === 'items') {
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $page = max(1, intval($_GET['page'] ?? 1));
        $per = min(200, max(1, intval($_GET['per_page'] ?? 20)));
        $offset = ($page - 1) * $per;

        $where = [];
        $params = [];
        if (!empty($_GET['q'])) {
            $q = trim($_GET['q']);
            $where[] = "id IN (SELECT rowid FROM items_fts WHERE items_fts MATCH :match)";
            $params[':match'] = str_replace('"', '', $q) . '*';
        }
        if (isset($_GET['sold']) && $_GET['sold'] !== '') {
            $where[] = 'sold = :sold';
            $params[':sold'] = intval($_GET['sold']);
        }
        if (!empty($_GET['from'])) { $where[] = 'purchase_date >= :from'; $params[':from'] = $_GET['from']; }
        if (!empty($_GET['to'])) { $where[] = 'purchase_date <= :to'; $params[':to'] = $_GET['to']; }

        $where_sql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM items $where_sql");
        $stmt->execute($params);
        $total = intval($stmt->fetchColumn());

        $sql = "SELECT id,name,description,purchase_date,purchase_price,weight_g,purity_percent,purchase_gold_price,image_filename,sold,sale_date,sale_price FROM items $where_sql ORDER BY created_at DESC LIMIT :limit OFFSET :offset";
        $pstmt = $pdo->prepare($sql);
        foreach ($params as $k=>$v) $pstmt->bindValue($k, $v);
        $pstmt->bindValue(':limit', $per, PDO::PARAM_INT);
        $pstmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $pstmt->execute();
        $rows = $pstmt->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode([
            'page'=>$page,
            'per_page'=>$per,
            'total'=>$total,
            'total_pages'=>($per?ceil($total/$per):1),
            'data'=>$rows
        ], JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE);
        exit;
    }

    // Create item (requires write scope)
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!has_scope($user, 'write')) {
            http_response_code(403); echo json_encode(['error'=>'forbidden','reason'=>'missing_scope']); exit;
        }
        $input = json_decode(file_get_contents('php://input'), true) ?: $_POST;
        $stmt = $pdo->prepare("INSERT INTO items (name,description,purchase_date,purchase_price,weight_g,purity_percent,purchase_gold_price,image_filename) VALUES (:name,:desc,:pd,:pp,:wg,:pu,:pg,:img)");
        $stmt->execute([
            ':name'=>$input['name'] ?? null,
            ':desc'=>$input['description'] ?? null,
            ':pd'=>$input['purchase_date'] ?? null,
            ':pp'=>$input['purchase_price'] ?? null,
            ':wg'=>$input['weight_g'] ?? null,
            ':pu'=>$input['purity_percent'] ?? null,
            ':pg'=>$input['purchase_gold_price'] ?? null,
            ':img'=>$input['image_filename'] ?? null
        ]);
        $id = $pdo->lastInsertId();
        audit_log('api_create_item', ['id'=>$id,'by'=>$user['username']]);
        http_response_code(201);
        echo json_encode(['ok'=>true,'id'=>$id]);
        exit;
    }
}

if ($action === 'item' && isset($_GET['id'])) {
    $id = intval($_GET['id']);
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $stmt = $pdo->prepare("SELECT * FROM items WHERE id = :id");
        $stmt->execute([':id'=>$id]);
        $r = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$r) { http_response_code(404); echo json_encode(['error'=>'not_found']); exit; }
        echo json_encode($r, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE); exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'PATCH' || $_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!has_scope($user, 'write')) { http_response_code(403); echo json_encode(['error'=>'forbidden']); exit; }
        $input = json_decode(file_get_contents('php://input'), true) ?: $_POST;
        $fields = [];
        $params = [':id'=>$id];
        $allowed = ['name','description','purchase_date','purchase_price','weight_g','purity_percent','purchase_gold_price','image_filename','sold','sale_date','sale_price'];
        foreach ($allowed as $a) {
            if (array_key_exists($a, $input)) { $fields[] = "$a = :$a"; $params[":$a"] = $input[$a]; }
        }
        if ($fields) {
            $sql = "UPDATE items SET " . implode(',', $fields) . " WHERE id = :id";
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            audit_log('api_update_item', ['id'=>$id,'by'=>$user['username'],'fields'=>array_keys($input)]);
            echo json_encode(['ok'=>true]); exit;
        }
        echo json_encode(['ok'=>false,'reason'=>'no_fields']); exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
        if (!has_scope($user, 'delete')) { http_response_code(403); echo json_encode(['error'=>'forbidden']); exit; }
        $stmt = $pdo->prepare("DELETE FROM items WHERE id = :id");
        $stmt->execute([':id'=>$id]);
        audit_log('api_delete_item', ['id'=>$id,'by'=>$user['username']]);
        echo json_encode(['ok'=>true]); exit;
    }
}

// sell endpoint
if ($action === 'sell' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    // data: id, sale_date, sale_price
    if (!has_scope($user, 'sell') && !has_scope($user,'write')) { http_response_code(403); echo json_encode(['error'=>'forbidden']); exit; }
    $input = json_decode(file_get_contents('php://input'), true) ?: $_POST;
    $id = intval($input['id'] ?? 0);
    $sd = $input['sale_date'] ?? date('Y-m-d');
    $sp = $input['sale_price'] ?? null;
    if (!$id || !$sp) { http_response_code(400); echo json_encode(['error'=>'invalid']); exit; }
    $stmt = $pdo->prepare("UPDATE items SET sold=1, sale_date=:sd, sale_price=:sp WHERE id=:id");
    $stmt->execute([':sd'=>$sd, ':sp'=>$sp, ':id'=>$id]);
    // notify
    $stmt2 = $pdo->prepare("SELECT id,name FROM items WHERE id=:id"); $stmt2->execute([':id'=>$id]); $it = $stmt2->fetch(PDO::FETCH_ASSOC);
    evaluate_notification_rules('sale', ['type'=>'sale','item'=>$it,'sale_price'=>$sp,'sale_date'=>$sd]);
    audit_log('api_sell_item', ['id'=>$id,'by'=>$user['username'],'price'=>$sp]);
    echo json_encode(['ok'=>true]); exit;
}

// fallback
http_response_code(404); echo json_encode(['error'=>'unknown action']);
