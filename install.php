<?php
// install.php — installation complète (exécute une seule fois)
$dbDir = __DIR__ . '/data';
$dbPath = $dbDir . '/inventory.db';
if (!is_dir($dbDir)) {
    if (!mkdir($dbDir, 0755, true)) {
        echo "Impossible de créer le dossier data/. Vérifie les permissions.";
        exit;
    }
}
if (!is_dir($dbDir . '/images')) {
    mkdir($dbDir . '/images', 0755, true);
}

if (file_exists($dbPath)) {
    echo "<p>La base existe déjà : <code>data/inventory.db</code></p>";
    echo '<p><a href="index.php">Aller à l\'application</a></p>';
    echo '<p>Si tu veux réinitialiser, supprime <code>data/inventory.db</code> puis relance ce script.</p>';
    exit;
}

try {
    $pdo = new PDO('sqlite:' . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Core tables
    $pdo->exec("
    CREATE TABLE items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      purchase_date TEXT,
      purchase_price REAL,
      weight_g REAL,
      purity_percent REAL,
      purchase_gold_price REAL,
      image_filename TEXT,
      sold INTEGER DEFAULT 0,
      sale_date TEXT,
      sale_price REAL,
      created_at TEXT DEFAULT (datetime('now'))
    );
    ");

    $pdo->exec("
    CREATE TABLE gold_prices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      date TEXT NOT NULL UNIQUE,
      price_per_gram REAL NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );
    ");

    $pdo->exec("
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'admin',
      created_at TEXT DEFAULT (datetime('now'))
    );
    ");

    $pdo->exec("
    CREATE TABLE settings (
      key TEXT PRIMARY KEY,
      value TEXT
    );
    ");

    // Additional / migration tables
    $pdo->exec("
    CREATE TABLE IF NOT EXISTS api_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL UNIQUE,
      name TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    ");

    $pdo->exec("
    CREATE TABLE IF NOT EXISTS roles_permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      role TEXT NOT NULL,
      permission TEXT NOT NULL
    );
    ");

    // FTS5 virtual table and triggers (if SQLite compiled with FTS5)
    // create virtual table only if supported; attempt and ignore if fails
    try {
        $pdo->exec("CREATE VIRTUAL TABLE IF NOT EXISTS items_fts USING fts5(name, description, content='items', content_rowid='id');");

        $pdo->exec("
        CREATE TRIGGER IF NOT EXISTS items_ai AFTER INSERT ON items BEGIN
          INSERT INTO items_fts(rowid, name, description) VALUES (new.id, new.name, new.description);
        END;
        ");
        $pdo->exec("
        CREATE TRIGGER IF NOT EXISTS items_ad AFTER DELETE ON items BEGIN
          INSERT INTO items_fts(items_fts, rowid, name, description) VALUES('delete', old.id, old.name, old.description);
        END;
        ");
        $pdo->exec("
        CREATE TRIGGER IF NOT EXISTS items_au AFTER UPDATE ON items BEGIN
          INSERT INTO items_fts(items_fts, rowid, name, description) VALUES('delete', old.id, old.name, old.description);
          INSERT INTO items_fts(rowid, name, description) VALUES (new.id, new.name, new.description);
        END;
        ");
    } catch (Exception $e) {
        // FTS5 not available; continue without it
    }

    $pdo->exec("
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT,
      payload TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      sent INTEGER DEFAULT 0
    );
    ");

    $pdo->exec("
    CREATE TABLE IF NOT EXISTS exchange_rates (
      currency TEXT PRIMARY KEY,
      rate_to_eur REAL,
      updated_at TEXT DEFAULT (datetime('now'))
    );
    ");

    // Indexes
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_gold_date ON gold_prices(date);");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_items_purchase_date ON items(purchase_date);");

    // Create default admin user if no users exist
    $count = $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
    if (intval($count) === 0) {
        $username = 'admin';
        $password = 'changeme';
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, role) VALUES (:u,:p,'admin')");
        $stmt->execute([':u'=>$username, ':p'=>$hash]);
        $created_msg = "<p>Utilisateur par défaut créé : <strong>admin</strong> / mot de passe <strong>changeme</strong></p>
        <p>Change le mot de passe dès la première connexion (Auth → Changer mot de passe).</p>";
    } else {
        $created_msg = "<p>Des utilisateurs existent déjà (pas de création automatique).</p>";
    }

    echo "<h2>Installation terminée</h2>";
    echo "<p>Base créée : <code>data/inventory.db</code></p>";
    echo $created_msg;
    echo '<p><a href="index.php">Aller à l\'application</a></p>';
    echo '<p>Conseil : installe PHPMailer (composer require phpmailer/phpmailer) pour activer SMTP authentifié et utiliser smtp_helper.php pour configurer Gmail/Mailjet/Sendinblue.</p>';

} catch (Exception $e) {
    echo "<h2>Erreur d'installation</h2>";
    echo "<pre>" . htmlspecialchars($e->getMessage()) . "</pre>";
    exit;
}
PHP