<?php
// ============================================================
// Ensemble - Auth Helpers
// ============================================================
// Session wrapper plus password verification helpers.
//
// Login flow:
//   1. User submits access_uuid + password via login form
//   2. auth_verify_password() checks the hash in the DB
//   3. If pw_set=0, session flag 'force_pw_change' is set
//   4. index.php redirects to the force-change form
//   5. After the user sets a real password, auth_set_password()
//      stores the bcrypt hash, clears force_pw_change, and
//      POSTs "passwordset" back to the HUD via notify_hud_password_set()
// ============================================================

// Derive a site-specific suffix from the hostname so that multiple
// Ensemble installations on different domains never share session or
// remember-me cookies. Characters outside [a-zA-Z0-9] become underscores.
$_ensemble_host_slug = preg_replace('/[^a-zA-Z0-9]/', '_', $_SERVER['HTTP_HOST'] ?? 'default');
session_name('ensemble_' . $_ensemble_host_slug);

function auth_start(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        session_start([
            'cookie_httponly' => true,
            'cookie_samesite' => 'Lax',
        ]);
    }
}

// Log the wearer in — stores access_uuid and username in session
function auth_login(string $accessUUID, string $username): void
{
    auth_start();
    session_regenerate_id(true);
    $_SESSION['access_uuid'] = $accessUUID;
    $_SESSION['username']    = $username;
}

function auth_logout(): void
{
    auth_start();
    $_SESSION = [];
    session_destroy();
}

// Returns the logged-in access UUID, or null if not logged in
function auth_uuid(): ?string
{
    auth_start();
    return $_SESSION['access_uuid'] ?? null;
}

function auth_username(): string
{
    auth_start();
    return $_SESSION['username'] ?? '';
}

// Redirect to login if not authenticated
function auth_require(): void
{
    if (auth_uuid() === null) {
        header('Location: index.php');
        exit;
    }
}

// ── CSRF protection ──────────────────────────────────────────
// Generates (or returns the existing) session CSRF token.
// Call auth_csrf_token() to get the value for embedding in forms
// and JS, and auth_check_csrf() at the top of any mutating action.
function auth_csrf_token(): string
{
    auth_start();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// Verifies that $_POST['csrf_token'] matches the session token.
// Exits with 403 if the token is absent or wrong.
// Call this at the top of every mutating API action and form handler.
function auth_check_csrf(): void
{
    auth_start();
    $submitted = $_POST['csrf_token'] ?? '';
    $expected  = $_SESSION['csrf_token'] ?? '';
    if ($expected === '' || !hash_equals($expected, $submitted)) {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'invalid_csrf_token']);
        exit;
    }
}

// Returns true if the logged-in user must change their password
// before accessing the dashboard (temp password still active)
function auth_needs_pw_change(): bool
{
    auth_start();
    return !empty($_SESSION['force_pw_change']);
}

// ── Password verification ────────────────────────────────────
// Verifies the submitted password against the stored hash.
// Handles both temp passwords (MD5 hash from HUD) and real
// passwords (bcrypt hash set by user).
//
// Returns:
//   'ok'           — password correct, pw_set=1
//   'force_change' — password correct, pw_set=0 (temp password)
//   'wrong'        — password incorrect
//   'no_password'  — no password set yet (HUD hasn't checked in)
function auth_verify_password(PDO $pdo, string $accessUUID, string $password): string
{
    $stmt = $pdo->prepare('SELECT pw_hash, pw_set FROM users WHERE access_uuid = ?');
    $stmt->execute([$accessUUID]);
    $row = $stmt->fetch();

    if (!$row || $row['pw_hash'] === null) {
        return 'no_password';
    }

    $storedHash = $row['pw_hash'];
    $pwSet      = (int)$row['pw_set'];

    // Determine which verification method to use.
    // Temp passwords are stored as MD5(plaintext + access_uuid) — 32 hex chars.
    // Real passwords are stored as bcrypt via password_hash() — starts with $2y$.
    if (str_starts_with($storedHash, '$2y$')) {
        // bcrypt — user-set real password
        $valid = password_verify($password, $storedHash);
    } else {
        // MD5 temp hash from HUD — replicate the HUD's hashing:
        // llMD5String(plaintext + access_uuid, 0) → lowercase hex
        // LSL's llMD5String(str, nonce) computes md5(str + ":" + nonce)
        // so llMD5String(password, 0) = md5(password + ":0")
        $valid = (md5($password . ':0') === $storedHash);
    }

    if (!$valid) return 'wrong';
    if ($pwSet === 0) return 'force_change';
    return 'ok';
}

// ── Password strength validation ─────────────────────────────
// Returns '' if strong enough, or a human-readable error string.
// Rules: 10+ chars, upper, lower, digit, symbol.
function auth_check_password_strength(string $password): string
{
    if (strlen($password) < 10)
        return 'Password must be at least 10 characters long.';
    if (!preg_match('/[A-Z]/', $password))
        return 'Password must contain at least one uppercase letter.';
    if (!preg_match('/[a-z]/', $password))
        return 'Password must contain at least one lowercase letter.';
    if (!preg_match('/[0-9]/', $password))
        return 'Password must contain at least one number.';
    if (!preg_match('/[^A-Za-z0-9]/', $password))
        return 'Password must contain at least one symbol (e.g. !@#$%).';
    return '';
}

// ── Set a real user password ─────────────────────────────────
// Stores a bcrypt hash and sets pw_set=1 in the database.
// Called after successful force-change or voluntary reset.
function auth_set_password(PDO $pdo, string $accessUUID, string $newPassword): void
{
    $hash = password_hash($newPassword, PASSWORD_BCRYPT);
    $stmt = $pdo->prepare('UPDATE users SET pw_hash = ?, pw_set = 1 WHERE access_uuid = ?');
    $stmt->execute([$hash, $accessUUID]);
}

// ── Remember-me cookie ───────────────────────────────────────
// Generates a random token, stores its SHA-256 hash in the DB,
// and sets a persistent cookie containing accessUUID:plaintext_token.
// The cookie lasts until the user signs out or clears their cookies.
// The UUID prefix lets us look up the right user without a
// full-table scan on every page load.
// Cookie lasts 10 years — effectively permanent until the user signs out
// or clears their cookies. No forced re-authentication; the system is
// not sensitive enough to warrant it.
define('REMEMBER_DAYS', 3650);
// Cookie name is also host-specific to prevent cross-installation collisions.
define('REMEMBER_COOKIE', 'ensemble_remember_' . preg_replace('/[^a-zA-Z0-9]/', '_', $_SERVER['HTTP_HOST'] ?? 'default'));

function auth_set_remember(PDO $pdo, string $accessUUID): void
{
    $token     = bin2hex(random_bytes(32)); // 64-char hex, cryptographically random
    $tokenHash = hash('sha256', $token);
    $expires   = time() + (REMEMBER_DAYS * 24 * 60 * 60);

    $stmt = $pdo->prepare('
        INSERT INTO remember_tokens (user_uuid, token_hash, expires_at)
        VALUES (?, ?, ?)
    ');
    $stmt->execute([$accessUUID, $tokenHash, $expires]);

    setcookie(REMEMBER_COOKIE, $accessUUID . ':' . $token, [
        'expires'  => $expires,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

// Check for a valid remember-me cookie and auto-login if found.
// Rotates the token on each use so a stolen cookie can only be
// used once before it changes. Returns true if login succeeded.
// Expired tokens (beyond REMEMBER_DAYS) are cleaned up on login.
function auth_check_remember(PDO $pdo): bool
{
    $cookie = $_COOKIE[REMEMBER_COOKIE] ?? '';
    if ($cookie === '') return false;

    $sep = strpos($cookie, ':');
    if ($sep === false) return false;

    $accessUUID = substr($cookie, 0, $sep);
    $token      = substr($cookie, $sep + 1);

    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $accessUUID)) return false;
    if ($token === '') return false;

    $tokenHash = hash('sha256', $token);
    $now       = time();

    $stmt = $pdo->prepare('
        SELECT t.id, u.access_uuid, u.username
        FROM remember_tokens t
        JOIN users u ON u.access_uuid = t.user_uuid
        WHERE t.user_uuid = ? AND t.token_hash = ? AND t.expires_at > ?
    ');
    $stmt->execute([$accessUUID, $tokenHash, $now]);
    $row = $stmt->fetch();

    if (!$row) {
        auth_clear_remember();
        return false;
    }

    // Valid — log in, delete the old token, issue a fresh one (rotation)
    auth_login($row['access_uuid'], $row['username']);
    $stmt = $pdo->prepare('DELETE FROM remember_tokens WHERE id = ?');
    $stmt->execute([$row['id']]);
    auth_set_remember($pdo, $row['access_uuid']);

    // Clean up any other expired tokens for this user
    $stmt = $pdo->prepare('DELETE FROM remember_tokens WHERE user_uuid = ? AND expires_at <= ?');
    $stmt->execute([$accessUUID, $now]);

    return true;
}

// Clear the remember-me cookie and delete the token from the DB.
// $pdo is optional so this can be called even if DB is unavailable.
function auth_clear_remember(?PDO $pdo = null): void
{
    $cookie = $_COOKIE[REMEMBER_COOKIE] ?? '';
    if ($cookie !== '' && $pdo !== null) {
        $sep = strpos($cookie, ':');
        if ($sep !== false) {
            $tokenHash = hash('sha256', substr($cookie, $sep + 1));
            $stmt = $pdo->prepare('DELETE FROM remember_tokens WHERE token_hash = ?');
            $stmt->execute([$tokenHash]);
        }
    }

    setcookie(REMEMBER_COOKIE, '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

// ── Notify HUD that password has been set ────────────────────
// POSTs command=passwordset to the HUD's current sim_url.
// WebRelay routes this to Core via LM_PASSWORD_SET so it can
// persist pws=1 and stop regenerating temp passwords on init.
// Failure is non-fatal — the user is already logged in.
function auth_notify_hud_password_set(PDO $pdo, string $accessUUID): void
{
    $stmt = $pdo->prepare('SELECT sim_url, last_seen FROM users WHERE access_uuid = ?');
    $stmt->execute([$accessUUID]);
    $row = $stmt->fetch();

    if (!$row || $row['sim_url'] === '') return;

    // Only attempt if HUD was seen within the last 10 minutes
    $age = time() - (int)$row['last_seen'];
    if ($age > 600) return;

    $postBody = http_build_query([
        'access_uuid' => $accessUUID,
        'command'     => 'passwordset',
    ]);

    $context = stream_context_create([
        'http' => [
            'method'        => 'POST',
            'header'        => "Content-Type: application/x-www-form-urlencoded\r\n"
                             . "Content-Length: " . strlen($postBody) . "\r\n",
            'content'       => $postBody,
            'timeout'       => 5,
            'ignore_errors' => true,
        ]
    ]);

    // Fire-and-forget — we don't care about the response
    @file_get_contents($row['sim_url'], false, $context);
}
