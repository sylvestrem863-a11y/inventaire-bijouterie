<?php
// backups_ui.php — Admin UI to create/list/download/restore backups
require_once __DIR__ . '/functions.php';
require_login();
if (!check_permission('admin')) { echo 'Accès refusé.'; exit; }
$action = $_POST['action'] ?? ($_GET['action'] ?? null);
$message = null;
if ($action === 'create') {
    $res = create_backup((int)($_POST['keep'] ?? 14));
    $message = json_encode($res);
}
if ($action === 'restore' && !empty($_POST['name'])) {
    // create safety backup before restore
    create_backup(14);
    $res = restore_backup($_POST['name']);
    if ($res['ok']) {
        audit_log('backup_restore', $_POST['name']);
        $message = 'Restore OK';
    } else $message = 'Restore failed: ' . ($res['msg'] ?? '');
}
$backups = list_backups();
?>
<!doctype html>
<html lang="fr">
<head><meta charset="utf-8"><title>Admin — Backups</title>
<link rel="stylesheet" href="styles.css"></head>
<body>
<header><h1>Backups</h1><nav><a href="index.php">Retour</a></nav></header>
<main>
  <?php if ($message): ?><div style="padding:8px;border:1px solid #ccc;margin-bottom:10px"><?=h($message)?></div><?php endif; ?>
  <section>
    <h2>Créer une sauvegarde</h2>
    <form method="post" action="backups_ui.php">
      <input type="hidden" name="action" value="create">
      <label>Conserver (jours)<br><input name="keep" value="14"></label>
      <button>Créer</button>
    </form>
  </section>

  <section>
    <h2>Sauvegardes disponibles</h2>
    <?php if (empty($backups)): ?>
      <p>Aucune sauvegarde trouvée.</p>
    <?php else: ?>
      <table>
        <thead><tr><th>Fichier</th><th>Modifié</th><th>Taille</th><th>Actions</th></tr></thead>
        <tbody>
          <?php foreach ($backups as $b): ?>
            <tr>
              <td><?=h($b['name'])?></td>
              <td><?=h($b['mtime'])?></td>
              <td><?=h(number_format($b['size']/1024,2))?> KB</td>
              <td>
                <a href="data/backups/<?=rawurlencode($b['name'])?>" download>Download</a>
                <form method="post" style="display:inline" onsubmit="return confirm('Restaurer la sauvegarde ? Cela écrasera la base actuelle.');">
                  <input type="hidden" name="action" value="restore">
                  <input type="hidden" name="name" value="<?=h($b['name'])?>">
                  <button>Restore</button>
                </form>
              </td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  </section>
</main>
</body>
</html>
