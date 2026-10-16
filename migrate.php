<?php
// migrate.php — adds audit_logs, notification_rules, api_tokens scopes, token_hash and expires_at
try {
    $dbPath = __DIR__ . '/data/inventory.db';
    if (!file_exists($dbPath)) throw new Exception("Database not found. Run install.php first.");
    $pdo = new PDO('sqlite:' . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Ensure api_tokens has a scopes column
    $cols = $pdo->query("PRAGMA table_info(api_tokens)")->fetchAll(PDO::FETCH_ASSOC);
    $hasScopes = false; $hasTokenHash = false; $hasExpires = false;
    foreach ($cols as $c) {
        if ($c['name'] === 'scopes') $hasScopes = true;
        if ($c['name'] === 'token_hash') $hasTokenHash = true;
        if ($c['name'] === 'expires_at') $hasExpires = true;
    }
    if (!$hasScopes) {
        try { $pdo->exec("ALTER TABLE api_tokens ADD COLUMN scopes TEXT"); } catch (Exception $e) { }
    }
    if (!$hasTokenHash) {
        try { $pdo->exec("ALTER TABLE api_tokens ADD COLUMN token_hash TEXT"); } catch (Exception $e) { }
    }
    if (!$hasExpires) {
        try { $pdo->exec("ALTER TABLE api_tokens ADD COLUMN expires_at TEXT"); } catch (Exception $e) { }
    }

    // Audit logs
    $pdo->exec("CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      action TEXT NOT NULL,
      details TEXT,
      ip TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );");

    // Notification rules
    $pdo->exec("CREATE TABLE IF NOT EXISTS notification_rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      type TEXT,
      enabled INTEGER DEFAULT 1,
      condition_json TEXT,
      emails TEXT,
      webhook_url TEXT,
      template TEXT,
      last_triggered TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );");

    // Ensure exchange_rates table exists
    $pdo->exec("CREATE TABLE IF NOT EXISTS exchange_rates (
      currency TEXT PRIMARY KEY,
      rate_to_eur REAL,
      updated_at TEXT DEFAULT (datetime('now'))
    );");

    echo "Migration completed: audit_logs, notification_rules ensured; api_tokens columns updated if missing.\n";
} catch (Exception $e) {
    echo 'Migration error: ' . htmlspecialchars($e->getMessage());
}
