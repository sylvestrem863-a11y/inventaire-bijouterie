<?php
// backup.php — create a backup (callable via CLI or browser) and list backups
require_once __DIR__ . '/functions.php';
require_login();
if (!check_permission('admin')) { echo 'Access denied.'; exit; }

$action = $_GET['action'] ?? ($_POST['action'] ?? 'list');
if ($action === 'create') {
    $res = create_backup(14);
    echo json_encode($res, JSON_PRETTY_PRINT);
    exit;
}
if ($action === 'list') {
    $list = list_backups();
    echo json_encode($list, JSON_PRETTY_PRINT);
    exit;
}
if ($action === 'restore' && !empty($_POST['name'])) {
    $name = $_POST['name'];
    $res = restore_backup($name);
    if ($res['ok']) {
        audit_log('backup_restore', $name);
        echo json_encode(['ok'=>true]);
    } else echo json_encode($res);
    exit;
}
http_response_code(400); echo json_encode(['error'=>'invalid']);
