<?php
// migrate.php — adds audit_logs, notification_rules, api_tokens scopes, and other migration items
try {
    $dbPath = __DIR__ . '/data/inventory.db';
    if (!file_exists($dbPath)) throw new Exception("Database not found. Run install.php first.");
    $pdo = new PDO('sqlite:' . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Ensure api_tokens has a scopes column
    $cols = $pdo->query("PRAGMA table_info(api_tokens)")->fetchAll(PDO::FETCH_ASSOC);
    $hasScopes = false;
    foreach ($cols as $c) { if ($c['name'] === 'scopes') { $hasScopes = true; break; } }
    if (!$hasScopes) {
        try {
            $pdo->exec("ALTER TABLE api_tokens ADD COLUMN scopes TEXT");
        } catch (Exception $e) { /* ignore if cannot alter */ }
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
      type TEXT, -- e.g. 'price_threshold','old_stock','sale'
      enabled INTEGER DEFAULT 1,
      condition_json TEXT, -- rule definition as JSON
      emails TEXT, -- comma separated
      webhook_url TEXT,
      template TEXT,
      last_triggered TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );");

    // Ensure exchange_rates table exists (install may have created it)
    $pdo->exec("CREATE TABLE IF NOT EXISTS exchange_rates (
      currency TEXT PRIMARY KEY,
      rate_to_eur REAL,
      updated_at TEXT DEFAULT (datetime('now'))
    );");

    echo "Migration completed: audit_logs, notification_rules ensured; api_tokens.scopes added if missing.\n";
} catch (Exception $e) {
    echo 'Migration error: ' . htmlspecialchars($e->getMessage());
}
