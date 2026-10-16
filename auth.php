<?php
// auth.php — login / logout / change password
require_once __DIR__ . '/functions.php';
$pdo = get_pdo();

$action = $_GET['action'] ?? ($_POST['action'] ?? 'login');

if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = $_POST['username'] ?? '';
    $p = $_POST['password'] ?? '';
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :u LIMIT 1");
    $stmt->execute([':u'=>$u]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($user && password_verify($p, $user['password_hash'])) {
        $_SESSION['user'] = ['id'=>$user['id'], 'username'=>$user['username'], 'role'=>$user['role']];
        header('Location: index.php');
        exit;
    } else {
        $error = "Identifiants invalides.";
    }
}

if ($action === 'logout') {
    session_destroy();
    header('Location: auth.php?action=login');
    exit;
}

if ($action === 'change_password') {
    require_login();
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $old = $_POST['old'] ?? '';
        $new = $_POST['new'] ?? '';
        $uid = $_SESSION['user']['id'];
        $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id = :id LIMIT 1");
        $stmt->execute([':id'=>$uid]);
        $r = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$r || !password_verify($old, $r['password_hash'])) {
            $error = "Mot de passe actuel incorrect.";
        } elseif (strlen($new) < 6) {
            $error = "Nouveau mot de passe trop court (>=6).";
        } else {
            $h = password_hash($new, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("UPDATE users SET password_hash = :h WHERE id = :id");
            $stmt->execute([':h'=>$h, ':id'=>$uid]);
            $msg = "Mot de passe changé.";
        }
    }
}

?>
<!doctype html>
<html lang="fr">
<head><meta charset="utf-8"><title>Auth</title><link rel="stylesheet" href="styles.css"></head>
<body>
<main>
<?php if ($action === 'login'): ?>
  <h2>Connexion</h2>
  <?php if (!empty($error)) echo "<p style='color:red'>".h($error)."</p>"; ?>
  <form method="post" action="auth.php?action=login">
    <label>Nom d'utilisateur<br><input name="username" required></label>
    <label>Mot de passe<br><input name="password" type="password" required></label>
    <button>Se connecter</button>
  </form>
<?php elseif ($action === 'change_password'): require_login(); ?>
  <h2>Changer mot de passe</h2>
  <?php if (!empty($error)) echo "<p style='color:red'>".h($error)."</p>"; ?>
  <?php if (!empty($msg)) echo "<p style='color:green'>".h($msg)."</p>"; ?>
  <form method="post" action="auth.php?action=change_password">
    <label>Mot de passe actuel<br><input name="old" type="password" required></label>
    <label>Nouveau mot de passe<br><input name="new" type="password" required></label>
    <button>Changer</button>
  </form>
  <p><a href="index.php">Retour</a></p>
<?php endif; ?>
</main>
</body>
</html>
