<?php
// tokens.php — Admin UI to create and revoke API tokens (show raw token only once)
require_once __DIR__ . '/functions.php';
require_login();
if (!check_permission('admin')) { echo 'Accès refusé.'; exit; }
$pdo = get_pdo();
$created_token = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!empty($_POST['action']) && $_POST['action'] === 'create') {
        $user_id = intval($_POST['user_id']);
        $name = trim($_POST['name'] ?? '');
        $scopes = $_POST['scopes'] ?? [];
        $days = intval($_POST['days'] ?? 90);
        $raw = create_api_token($user_id, $name, $scopes, $days);
        $created_token = $raw;
    }
    if (!empty($_POST['action']) && $_POST['action'] === 'revoke' && !empty($_POST['id'])) {
        revoke_api_token_by_id(intval($_POST['id']));
        header('Location: tokens.php'); exit;
    }
}
$users = $pdo->query("SELECT id,username FROM users ORDER BY username")->fetchAll(PDO::FETCH_ASSOC);
$tokens = list_api_tokens();
?>
<!doctype html>
<html lang="fr">
<head><meta charset="utf-8"><title>Admin — API Tokens</title>
<link rel="stylesheet" href="styles.css"></head>
<body>
<header><h1>API Tokens</h1><nav><a href="index.php">Retour</a></nav></header>
<main>
  <section>
    <h2>Créer un token</h2>
    <form method="post" action="tokens.php">
      <input type="hidden" name="action" value="create">
      <label>Utilisateur
        <select name="user_id">
          <?php foreach ($users as $u): ?>
            <option value="<?=h($u['id'])?>"><?=h($u['username'])?></option>
          <?php endforeach; ?>
        </select>
      </label>
      <label>Nom (usage interne)<br><input name="name"></label>
      <label>Scopes<br>
        <label><input type="checkbox" name="scopes[]" value="read"> read</label>
        <label><input type="checkbox" name="scopes[]" value="write"> write</label>
        <label><input type="checkbox" name="scopes[]" value="sell"> sell</label>
        <label><input type="checkbox" name="scopes[]" value="delete"> delete</label>
      </label>
      <label>Validité (jours)<br><input name="days" value="90"></label>
      <button>Créer token</button>
    </form>
    <?php if ($created_token): ?>
      <div style="border:1px solid #4caf50;padding:10px;margin-top:10px;background:#f6fffa">
        <strong>Token créé — copie le maintenant (ne sera plus affiché)</strong>
        <pre id="tokenBox"><?=h($created_token)?></pre>
        <button onclick="navigator.clipboard.writeText('<?=h($created_token)?>')">Copier</button>
      </div>
    <?php endif; ?>
  </section>

  <section>
    <h2>Tokens existants</h2>
    <table>
      <thead><tr><th>id</th><th>nom</th><th>utilisateur</th><th>scopes</th><th>créé</th><th>expire</th><th>action</th></tr></thead>
      <tbody>
        <?php foreach ($tokens as $t): ?>
          <tr>
            <td><?=h($t['id'])?></td>
            <td><?=h($t['name'])?></td>
            <td><?=h($t['username'] ?? $t['user_id'])?></td>
            <td><?=h($t['scopes'])?></td>
            <td><?=h($t['created_at'])?></td>
            <td><?=h($t['expires_at'] ?? '-')?></td>
            <td>
              <form method="post" style="display:inline" onsubmit="return confirm('Révoquer le token ?');">
                <input type="hidden" name="action" value="revoke">
                <input type="hidden" name="id" value="<?=h($t['id'])?>">
                <button>Révoquer</button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </section>
</main>
</body>
</html>
