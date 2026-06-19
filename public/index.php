<?php
// ============================================================
// Ensemble - Web Panel
// ============================================================
// Handles login and the wearer dashboard.
// ============================================================

define('ENSEMBLE_VERSION', 'Release Candidate 1');

// SVG icons for the password reveal toggle
define('EYE_ICON',     '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>');
define('EYE_OFF_ICON', '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>');

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';

auth_start();

// ── Handle logout ─────────────────────────────────────────────
if (isset($_GET['logout'])) {
    try {
        $pdo = db_connect();
        auth_clear_remember($pdo);
    } catch (Exception $e) {
        auth_clear_remember(); // clear cookie even if DB fails
    }
    auth_logout();
    header('Location: index.php');
    exit;
}

$error   = '';
$page    = 'login'; // 'login', 'force_change', or 'dashboard'

// ── Cookie auto-login ─────────────────────────────────────────
// If no active session but a valid remember-me cookie exists,
// log the user in automatically before handling any POST.
if (auth_uuid() === null) {
    try {
        $pdo = db_connect();
        auth_check_remember($pdo);
    } catch (Exception $e) {
        // Cookie check failure is silent — fall through to login page
    }
}

// ── Handle login form submission ──────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['access_uuid'])) {
    auth_check_csrf();
    $inputUUID = trim($_POST['access_uuid']);
    $inputPw   = $_POST['password'] ?? '';

    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $inputUUID)) {
        $error = 'That doesn\'t look like a valid Avatar UUID. It should be in the format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.';
    } elseif ($inputPw === '') {
        $error = 'Please enter your password.';
    } else {
        try {
            $pdo  = db_connect();
            $stmt = $pdo->prepare('SELECT access_uuid, username FROM users WHERE access_uuid = ?');
            $stmt->execute([$inputUUID]);
            $user = $stmt->fetch();

            if (!$user) {
                $error = 'Avatar UUID not found. Make sure your HUD has checked in at least once.';
            } else {
                $result = auth_verify_password($pdo, $inputUUID, $inputPw);

                if ($result === 'no_password') {
                    $error = 'No password has been set yet. Make sure your HUD is online — it will send a temporary password automatically.';
                } elseif ($result === 'wrong') {
                    $error = 'Incorrect password. If you have forgotten it, use the Reset Password option on your HUD.';
                } elseif ($result === 'force_change') {
                    // Temp password correct — log in but flag force-change required
                    auth_login($user['access_uuid'], $user['username']);
                    auth_start();
                    $_SESSION['force_pw_change'] = true;
                    header('Location: index.php');
                    exit;
                } else {
                    // Real password correct — normal login
                    auth_login($user['access_uuid'], $user['username']);
                    if (!empty($_POST['remember_me'])) {
                        auth_set_remember($pdo, $user['access_uuid']);
                    }
                    header('Location: index.php');
                    exit;
                }
            }
        } catch (Exception $e) {
            $error = 'A database error occurred. Please try again.';
            error_log('Ensemble login error: ' . $e->getMessage());
        }
    }
}

// ── Handle force-change form submission ───────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['new_password'])) {
    auth_check_csrf();
    $uuid    = auth_uuid();
    $newPw   = $_POST['new_password']     ?? '';
    $confirm = $_POST['confirm_password'] ?? '';

    if ($uuid === null) {
        // Session lost — send back to login
        header('Location: index.php');
        exit;
    }

    if ($newPw !== $confirm) {
        $error = 'Passwords do not match.';
    } else {
        $strengthError = auth_check_password_strength($newPw);
        if ($strengthError !== '') {
            $error = $strengthError;
        } else {
            try {
                $pdo = db_connect();
                auth_set_password($pdo, $uuid, $newPw);
                auth_notify_hud_password_set($pdo, $uuid);
                // Clear force-change flag — user is now fully logged in
                auth_start();
                unset($_SESSION['force_pw_change']);
                header('Location: index.php');
                exit;
            } catch (Exception $e) {
                $error = 'A database error occurred. Please try again.';
                error_log('Ensemble password change error: ' . $e->getMessage());
            }
        }
    }
}

// ── Determine which page to show ──────────────────────────────
$loggedInUUID = auth_uuid();

if ($loggedInUUID !== null && auth_needs_pw_change()) {
    $page = 'force_change';
} elseif ($loggedInUUID !== null) {
    $page = 'dashboard';

    $allTags = [];
    try {
        $pdo  = db_connect();
        $stmt = $pdo->prepare('SELECT * FROM users WHERE access_uuid = ?');
        $stmt->execute([$loggedInUUID]);
        $userData = $stmt->fetch();

        // Session valid but user deleted — log out
        if (!$userData) {
            auth_logout();
            header('Location: index.php');
            exit;
        }

        // Fetch outfits for this user, newest first
        $stmtOutfits = $pdo->prepare('
            SELECT id, outfit_name, folder_path, attachments,
                   has_space_warning, image_filename, created_at,
                   tags, comments, access_level,
                   wear_mode, base_outfits, additional_items, wear_after_remove, locked,
                   remove_before_wear, removal_points
            FROM outfits
            WHERE user_uuid = ?
            ORDER BY created_at DESC
        ');
        $stmtOutfits->execute([$loggedInUUID]);
        $outfits = $stmtOutfits->fetchAll();

        // Collect all unique tags across outfits (for the filter bar)
        $allTagsRaw = [];
        foreach ($outfits as $o) {
            $t = trim($o['tags'] ?? '');
            if ($t !== '') {
                foreach (array_map('trim', explode(',', $t)) as $tag) {
                    if ($tag !== '') $allTagsRaw[] = $tag;
                }
            }
        }
        // Case-insensitive dedup, sorted alphabetically
        $allTagsMap = [];
        foreach ($allTagsRaw as $tag) {
            $allTagsMap[strtolower($tag)] = $tag;
        }
        ksort($allTagsMap);
        $allTags = array_values($allTagsMap);

    } catch (Exception $e) {
        $error = 'Could not load your data. Please try again.';
        $userData = null;
        $outfits  = [];
        $allTags  = [];
    }
}

// ── Theme resolution ──────────────────────────────────────────
// Discovers available themes by scanning the themes/ directory.
// A valid theme is any subdirectory that contains a style.css file.
// The user's saved preference is loaded from their DB row.
// Falls back to 'default' if the saved theme no longer exists.

function ensemble_available_themes(): array
{
    $themes = [];
    $dir = __DIR__ . '/themes/';
    if (!is_dir($dir)) return ['default'];
    foreach (scandir($dir) as $entry) {
        if ($entry === '.' || $entry === '..') continue;
        if (is_dir($dir . $entry) && file_exists($dir . $entry . '/style.css')) {
            $themes[] = $entry;
        }
    }
    sort($themes);
    return $themes ?: ['default'];
}

function ensemble_active_theme(?array $userData): string
{
    $saved = trim($userData['theme'] ?? '');
    if ($saved === '') $saved = 'default';
    // Validate that the saved theme folder still exists
    $themeDir = __DIR__ . '/themes/' . $saved;
    if (!is_dir($themeDir) || !file_exists($themeDir . '/style.css')) {
        return 'default';
    }
    return $saved;
}

// Resolve the active theme now so it's available to the HTML head
$activeTheme    = ensemble_active_theme($userData ?? null);
$availableThemes = ensemble_available_themes();

// ── Connection status helper ───────────────────────────────────
function ensemble_connection_status(int $lastSeen): array
{
    if ($lastSeen === 0) {
        return ['label' => 'Never connected', 'class' => 'status-offline'];
    }
    $age = time() - $lastSeen;
    if ($age < 180) {   // < 3 min
        return ['label' => 'Online', 'class' => 'status-online'];
    }
    if ($age < 600) {   // < 10 min
        return ['label' => 'Stale', 'class' => 'status-stale'];
    }
    return ['label' => 'Offline', 'class' => 'status-offline'];
}

function ensemble_time_ago(int $ts): string
{
    if ($ts === 0) return 'Never';
    $age = time() - $ts;
    if ($age < 60)   return 'Just now';
    if ($age < 3600) return floor($age / 60) . ' min ago';
    if ($age < 86400) return floor($age / 3600) . ' hr ago';
    return date('d M Y, H:i', $ts);
}

?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ensemble<?= $page === 'dashboard' ? ' — ' . htmlspecialchars(auth_username()) : '' ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,600;1,400&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="themes/<?= htmlspecialchars($activeTheme) ?>/style.css">
</head>
<body>

<div class="page-wrap">

    <!-- ── Header ──────────────────────────────────────────── -->
    <header class="site-header">
        <div class="header-inner">

            <?php if ($page === 'dashboard'): ?>
            <!-- Hamburger button — dashboard only -->
            <button class="hamburger-btn" id="hamburgerBtn" aria-label="Open menu" aria-expanded="false" aria-controls="sideMenu">
                <span class="hamburger-bar"></span>
                <span class="hamburger-bar"></span>
                <span class="hamburger-bar"></span>
            </button>
            <?php endif; ?>

            <div class="logo-wrap">
                <img src="themes/<?= htmlspecialchars($activeTheme) ?>/ensemblelogo.png"
                     alt="Ensemble"
                     class="logo-img">
            </div>
            <?php if ($page === 'dashboard'): ?>
            <?php
                $headerStatus = isset($userData) ? ensemble_connection_status((int)$userData['last_seen']) : ['label' => 'Offline', 'class' => 'status-offline'];
            ?>
            <nav class="header-nav">
                <span class="status-badge <?= $headerStatus['class'] ?>">
                    <span class="status-dot"></span>
                    <?= $headerStatus['label'] ?>
                </span>
                <span class="nav-username"><?= htmlspecialchars(auth_username()) ?></span>
                <a href="index.php?logout=1" class="btn btn-ghost btn-sm">Log out</a>
            </nav>
            <?php endif; ?>
        </div>
    </header>

    <?php if ($page === 'dashboard'): ?>
    <!-- ── Side menu overlay ───────────────────────────────── -->
    <div class="side-menu-overlay" id="sideMenuOverlay"></div>

    <!-- ── Side menu panel ─────────────────────────────────── -->
    <nav class="side-menu" id="sideMenu" aria-label="Main navigation">
        <div class="side-menu-header">
            <span class="side-menu-title">Menu</span>
            <button class="side-menu-close" id="sideMenuClose" aria-label="Close menu">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="20" height="20">
                    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        </div>

        <ul class="side-menu-list">

            <!-- Outfits -->
            <li class="side-menu-item">
                <button class="side-menu-trigger" data-submenu="outfits">
                    <svg class="side-menu-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20.38 3.46 16 2a4 4 0 0 1-8 0L3.62 3.46a2 2 0 0 0-1.34 2.23l.58 3.57a1 1 0 0 0 .99.84H6v10c0 1.1.9 2 2 2h8a2 2 0 0 0 2-2V10h2.15a1 1 0 0 0 .99-.84l.58-3.57a2 2 0 0 0-1.34-2.23z"/></svg>
                    Outfits
                    <svg class="side-menu-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
                </button>
                <ul class="side-submenu" id="submenu-outfits">
                    <li><button class="side-submenu-item" onclick="openAddOutfitModal()">Add New</button></li>
                </ul>
            </li>

            <!-- Tools -->
            <li class="side-menu-item">
                <button class="side-menu-trigger" data-submenu="tools">
                    <svg class="side-menu-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
                    Tools
                    <svg class="side-menu-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
                </button>
                <ul class="side-submenu" id="submenu-tools">
                    <li>
                        <button class="side-submenu-item side-submenu-parent" data-submenu="rlv">
                            RLV
                            <svg class="side-menu-chevron side-menu-chevron--sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
                        </button>
                        <ul class="side-submenu side-submenu--nested" id="submenu-rlv">
                            <li><button class="side-submenu-item" onclick="menuStub('Tools › RLV › Check RLV')">Check RLV</button></li>
                            <li><button class="side-submenu-item" onclick="menuStub('Tools › RLV › Send RLV Command')">Send RLV Command</button></li>
                        </ul>
                    </li>
                    <li><button class="side-submenu-item" onclick="openLinksModal('create')">Create Link</button></li>
                    <li><button class="side-submenu-item" onclick="openLinksModal()">Manage Links</button></li>
                </ul>
            </li>

            <!-- Backup -->
            <li class="side-menu-item">
                <button class="side-menu-trigger" data-submenu="backup">
                    <svg class="side-menu-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    Backup
                    <svg class="side-menu-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
                </button>
                <ul class="side-submenu" id="submenu-backup">
                    <li><button class="side-submenu-item" onclick="menuStub('Backup › Download Backup')">Download Backup</button></li>
                    <li><button class="side-submenu-item" onclick="menuStub('Backup › Restore Backup')">Restore Backup</button></li>
                </ul>
            </li>

            <!-- Settings -->
            <li class="side-menu-item">
                <button class="side-menu-trigger" data-submenu="settings">
                    <svg class="side-menu-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                    Settings
                    <svg class="side-menu-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
                </button>
                <ul class="side-submenu" id="submenu-settings">
                    <li><button class="side-submenu-item" onclick="menuStub('Settings › Account')">Account</button></li>
                    <li><button class="side-submenu-item" onclick="menuStub('Settings › Default Removal Points')">Default Removal Points</button></li>
                    <li><button class="side-submenu-item" onclick="openThemeModal()">Theme Selection</button></li>
                    <li><button class="side-submenu-item" onclick="openChangePasswordModal()">Change Password</button></li>
                </ul>
            </li>

        </ul>
    </nav>

    <script>
    // ── Active theme (PHP-injected, used for placeholder fallbacks) ──
    var ENSEMBLE_ACTIVE_THEME  = <?= json_encode($activeTheme) ?>;
    var ENSEMBLE_AVAIL_THEMES  = <?= json_encode($availableThemes) ?>;

    // ── Hamburger / side menu ────────────────────────────────
    (function() {
        var btn     = document.getElementById('hamburgerBtn');
        var menu    = document.getElementById('sideMenu');
        var overlay = document.getElementById('sideMenuOverlay');
        var close   = document.getElementById('sideMenuClose');

        function openMenu() {
            menu.classList.add('side-menu--open');
            overlay.classList.add('side-menu-overlay--visible');
            btn.setAttribute('aria-expanded', 'true');
            document.body.style.overflow = 'hidden';
        }
        function closeMenu() {
            menu.classList.remove('side-menu--open');
            overlay.classList.remove('side-menu-overlay--visible');
            btn.setAttribute('aria-expanded', 'false');
            document.body.style.overflow = '';
        }

        btn.addEventListener('click', openMenu);
        close.addEventListener('click', closeMenu);
        overlay.addEventListener('click', closeMenu);

        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') closeMenu();
        });

        // ── Submenu toggles ───────────────────────────────────
        document.querySelectorAll('.side-menu-trigger, .side-submenu-parent').forEach(function(trigger) {
            trigger.addEventListener('click', function() {
                var id  = this.getAttribute('data-submenu');
                var sub = document.getElementById('submenu-' + id);
                if (!sub) return;
                var isOpen = sub.classList.contains('side-submenu--open');
                // Close all siblings at this level
                var parent = this.closest('li');
                var list   = parent.parentElement;
                list.querySelectorAll('.side-submenu--open').forEach(function(el) {
                    if (el !== sub) {
                        el.classList.remove('side-submenu--open');
                        el.previousElementSibling && el.previousElementSibling.querySelector('.side-menu-chevron, .side-menu-chevron--sm') && el.previousElementSibling.querySelector('[class*="chevron"]').classList.remove('rotated');
                    }
                });
                sub.classList.toggle('side-submenu--open', !isOpen);
                var chevron = this.querySelector('[class*="chevron"]');
                if (chevron) chevron.classList.toggle('rotated', !isOpen);
            });
        });
    })();

    // ── Stub handler for unimplemented menu items ─────────────
    function menuStub(label) {
        // Close the side menu first
        document.getElementById('sideMenu').classList.remove('side-menu--open');
        document.getElementById('sideMenuOverlay').classList.remove('side-menu-overlay--visible');
        document.getElementById('hamburgerBtn').setAttribute('aria-expanded', 'false');
        document.body.style.overflow = '';

        if (label === 'Settings › Account') {
            openAccountModal();
            return;
        }
        if (label === 'Settings › Default Removal Points') {
            openRemovalDefaultsModal();
            return;
        }
        if (label === 'Tools › RLV › Check RLV') {
            openRLVModal('check');
            return;
        }
        if (label === 'Tools › RLV › Send RLV Command') {
            openRLVModal('send');
            return;
        }
        if (label === 'Backup › Download Backup') {
            downloadBackup();
            return;
        }
        if (label === 'Backup › Restore Backup') {
            openRestoreModal();
            return;
        }
        showToast('\u2139\ufe0f ' + label + ' — coming soon', 'info');
    }
    </script>
    <?php endif; ?>

    <!-- ── Main content ────────────────────────────────────── -->
    <main class="main-content">

    <?php if ($page === 'login'): ?>
    <!-- ════════════════════════════════════════════════════════
         LOGIN PAGE
         ════════════════════════════════════════════════════════ -->
    <div class="login-wrap">
        <div class="login-card">
            <h1 class="login-heading">Welcome back</h1>
            <p class="login-subtext">Enter your Avatar UUID and password to sign in.</p>

            <?php if ($error !== ''): ?>
            <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>

            <form method="post" action="index.php" class="login-form">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(auth_csrf_token()) ?>">
                <div class="field">
                    <label for="access_uuid" class="field-label">Avatar UUID</label>
                    <input
                        type="text"
                        id="access_uuid"
                        name="access_uuid"
                        class="field-input monospace"
                        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        maxlength="36"
                        autocomplete="off"
                        autocorrect="off"
                        autocapitalize="off"
                        spellcheck="false"
                        required
                    >
                    <span class="field-hint">Found in your HUD: touch it, choose Settings, and your Avatar UUID is shown at the top.</span>
                </div>
                <div class="field">
                    <label for="password" class="field-label">Password</label>
                    <div class="pw-wrap">
                        <input
                            type="password"
                            id="password"
                            name="password"
                            class="field-input"
                            autocomplete="current-password"
                            required
                        >
                        <button type="button" class="pw-reveal" onclick="toggleReveal('password', this)" aria-label="Show password">
                            <?= EYE_ICON ?>
                        </button>
                    </div>
                    <span class="field-hint">Your temporary password was sent to you by IM when you first wore the HUD.</span>
                </div>
                <button type="submit" class="btn btn-primary btn-full">Sign in</button>
                <div class="field-remember">
                    <label class="remember-label">
                        <input type="checkbox" name="remember_me" value="1">
                        Remember me
                    </label>
                </div>
            </form>

            <div class="login-help">
                <p>Don't have an account yet? Wear the Ensemble HUD in-world — it will create your account automatically on first use.</p>
                <p>Forgotten your password? Use the <strong>Reset Password</strong> option in the HUD's Settings menu.</p>
            </div>
        </div>
    </div>

    <?php elseif ($page === 'force_change'): ?>
    <!-- ════════════════════════════════════════════════════════
         FORCE PASSWORD CHANGE
         ════════════════════════════════════════════════════════ -->
    <div class="login-wrap">
        <div class="login-card">
            <h1 class="login-heading">Set your password</h1>
            <p class="login-subtext">You logged in with a temporary password. Please choose a permanent password before continuing.</p>

            <?php if ($error !== ''): ?>
            <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>

            <form method="post" action="index.php" class="login-form">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(auth_csrf_token()) ?>">
                <div class="field">
                    <label for="new_password" class="field-label">New password</label>
                    <div class="pw-wrap">
                        <input
                            type="password"
                            id="new_password"
                            name="new_password"
                            class="field-input"
                            autocomplete="new-password"
                            required
                        >
                        <button type="button" class="pw-reveal" onclick="toggleReveal('new_password', this)" aria-label="Show password">
                            <?= EYE_ICON ?>
                        </button>
                    </div>
                    <span class="field-hint">At least 10 characters, with uppercase, lowercase, a number, and a symbol.</span>
                </div>
                <div class="field">
                    <label for="confirm_password" class="field-label">Confirm password</label>
                    <div class="pw-wrap">
                        <input
                            type="password"
                            id="confirm_password"
                            name="confirm_password"
                            class="field-input"
                            autocomplete="new-password"
                            required
                        >
                        <button type="button" class="pw-reveal" onclick="toggleReveal('confirm_password', this)" aria-label="Show password">
                            <?= EYE_ICON ?>
                        </button>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary btn-full">Set password</button>
            </form>
        </div>
    </div>

    <?php elseif ($page === 'dashboard' && $userData): ?>
    <!-- ════════════════════════════════════════════════════════
         DASHBOARD
         ════════════════════════════════════════════════════════ -->

    <?php
        $status    = ensemble_connection_status((int)$userData['last_seen']);
    ?>

    <div class="dashboard-wrap">

        <!-- Outfits section — full width -->
        <section class="card card-outfits">
            <div class="card-body">
                <div class="outfits-header">
                    <h2 class="card-title">Outfits</h2>
                    <span class="outfit-count" id="outfitCount"><?= count($outfits) ?> saved</span>
                </div>

                <?php if (empty($outfits)): ?>
                <div class="outfits-empty">
                    <div class="placeholder-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                            <path d="M20.38 3.46L16 2a4 4 0 01-8 0L3.62 3.46a2 2 0 00-1.34 2.23l.58 3.57a1 1 0 00.99.84H6v10c0 1.1.9 2 2 2h8a2 2 0 002-2V10h2.15a1 1 0 00.99-.84l.58-3.57a2 2 0 00-1.34-2.23z"/>
                        </svg>
                    </div>
                    <p class="placeholder-text">No outfits saved yet. Use the <strong>Create Outfit</strong> button on your in-world HUD to save your first outfit.</p>
                </div>

                <?php else: ?>

                <!-- ── Filter bar ──────────────────────────────────── -->
                <div class="filter-bar" id="filterBar">
                    <div class="filter-bar-row">

                        <!-- Hide private checkbox -->
                        <label class="filter-private-label" title="Hide outfits marked as Private">
                            <input type="checkbox" id="filterHidePrivate" onchange="applyFilters()">
                            <span>Hide Private</span>
                        </label>

                        <div class="filter-bar-divider"></div>

                        <!-- Tag pills (collapsed, read-only) -->
                        <div class="filter-tags-collapsed" id="filterTagsCollapsed">
                            <?php foreach ($allTags as $tag): ?>
                            <span class="filter-tag-pill"><?= htmlspecialchars($tag) ?></span>
                            <?php endforeach; ?>
                            <?php if (empty($allTags)): ?>
                            <span class="filter-no-tags">No tags yet</span>
                            <?php endif; ?>
                        </div>

                        <!-- Clear button (collapsed state, only shown when tags active) -->
                        <button class="filter-clear-btn" id="filterClearCollapsed" onclick="clearAllTagFilters()" hidden>Clear</button>

                        <!-- Expand toggle -->
                        <?php if (!empty($allTags)): ?>
                        <button class="filter-expand-btn" id="filterExpandBtn" onclick="toggleFilterExpand()" title="Filter by tags">
                            <svg class="filter-chevron" id="filterChevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" width="15" height="15"><polyline points="6 9 12 15 18 9"/></svg>
                            <span id="filterExpandLabel">Filter</span>
                        </button>
                        <?php endif; ?>

                    </div><!-- /.filter-bar-row -->

                    <!-- Expanded tag checklist (hidden by default) -->
                    <?php if (!empty($allTags)): ?>
                    <div class="filter-bar-expanded" id="filterBarExpanded" hidden>
                        <div class="filter-expanded-header">
                            <span class="filter-expanded-title">Filter by tag</span>
                            <button class="filter-clear-btn filter-clear-btn--expanded" id="filterClearExpanded" onclick="clearAllTagFilters()">Clear all</button>
                        </div>
                        <div class="filter-tag-checklist" id="filterTagChecklist">
                            <?php foreach ($allTags as $tag): ?>
                            <label class="filter-tag-check">
                                <input type="checkbox"
                                       class="filter-tag-cb"
                                       value="<?= htmlspecialchars(strtolower($tag)) ?>"
                                       onchange="applyFilters()">
                                <span><?= htmlspecialchars($tag) ?></span>
                            </label>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <?php endif; ?>

                </div><!-- /.filter-bar -->

                <div class="outfit-grid" id="outfitGrid">
                    <?php foreach ($outfits as $outfit):
                        $imageSrc    = $outfit['image_filename']
                                       ? 'image.php?file=' . urlencode($outfit['image_filename'])
                                       : 'themes/' . $activeTheme . '/placeholder.png';
                        $attachments = json_decode($outfit['attachments'], true) ?? [];
                        $savedDate   = date('d M Y', (int)$outfit['created_at']);
                        $isOnline    = ($status['class'] === 'status-online');
                        $isLocked    = !empty($outfit['locked']);

                        // Normalise legacy wear_mode values to new format
                        $rawMode  = $outfit['wear_mode'] ?? '';
                        $wearMode = in_array($rawMode, ['folder_add','folder_replace','subfolders_add','subfolders_replace'], true)
                                    ? $rawMode : 'subfolders_replace';
                    ?>
                    <?php
                        $isPrivate = ($outfit['access_level'] === 'private');
                        $cardClasses = 'outfit-card';
                        if ($outfit['has_space_warning']) $cardClasses .= ' outfit-card--warning';
                        if ($isLocked)   $cardClasses .= ' outfit-card--locked';
                        if ($isPrivate)  $cardClasses .= ' outfit-card--private';
                        // Normalise tags for data attribute: lowercase, pipe-separated
                        $cardTagList = '';
                        if (trim($outfit['tags'] ?? '') !== '') {
                            $cardTagList = implode('|', array_map('strtolower', array_map('trim', explode(',', $outfit['tags']))));
                        }
                    ?>
                    <div class="<?= $cardClasses ?>"
                         data-access="<?= htmlspecialchars($outfit['access_level'] ?? 'public') ?>"
                         data-tags="<?= htmlspecialchars($cardTagList) ?>">

                        <!-- Outfit image — click to open properties -->
                        <div class="outfit-image-wrap"
                             onclick="openOutfitPropertiesById(<?= (int)$outfit['id'] ?>)"
                             title="Click to edit outfit properties"
                             style="cursor:pointer"
                        >
                            <img
                                src="<?= $imageSrc ?>"
                                alt="<?= htmlspecialchars($outfit['outfit_name']) ?>"
                                class="outfit-image outfit-image--clickable"
                                onerror="this.src='themes/<?= $activeTheme ?>/placeholder.png'; this.onerror=null;"
                            >
                            <?php if ($outfit['has_space_warning']): ?>
                            <span class="outfit-warning-badge" title="Folder name contains spaces — RLV may match the wrong folder">⚠</span>
                            <?php endif; ?>
                            <?php if ($isLocked): ?>
                            <span class="outfit-lock-badge" title="Outfit is locked">🔒</span>
                            <?php endif; ?>
                            <?php if ($isPrivate): ?>
                            <span class="outfit-private-badge" title="Private outfit">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
                                    <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/>
                                    <path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/>
                                    <line x1="1" y1="1" x2="23" y2="23"/>
                                </svg>
                            </span>
                            <?php endif; ?>
                            <!-- Delete button floats over the top-right corner of the image -->
                            <button
                                class="btn btn-delete"
                                data-outfit-id="<?= (int)$outfit['id'] ?>"
                                data-outfit-name="<?= htmlspecialchars($outfit['outfit_name'], ENT_QUOTES) ?>"
                                onclick="confirmDeleteOutfit(this); event.stopPropagation();"
                                title="Delete outfit"
                                aria-label="Delete outfit"
                            >
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <polyline points="3 6 5 6 21 6"/>
                                    <path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/>
                                    <path d="M10 11v6"/>
                                    <path d="M14 11v6"/>
                                    <path d="M9 6V4a1 1 0 011-1h4a1 1 0 011 1v2"/>
                                </svg>
                            </button>
                        </div>

                        <!-- Outfit details -->
                        <div class="outfit-details">
                            <h3 class="outfit-name"><?= htmlspecialchars($outfit['outfit_name']) ?></h3>
                            <?php
                                // Show tag list on card if tags exist; otherwise fall back to folder path
                                $cardTags = trim($outfit['tags'] ?? '');
                                if ($cardTags !== ''):
                            ?>
                            <p class="outfit-tags"><?= htmlspecialchars($cardTags) ?></p>
                            <?php else: ?>
                            <p class="outfit-path"><?= htmlspecialchars($outfit['folder_path']) ?></p>
                            <?php endif; ?>

                            <?php if (!empty($attachments)): ?>
                            <p class="outfit-attachments">
                                <?= count($attachments) ?> attachment<?= count($attachments) !== 1 ? 's' : '' ?>
                            </p>
                            <?php endif; ?>

                            <p class="outfit-date">Saved <?= $savedDate ?></p>

                            <?php if ($outfit['has_space_warning']): ?>
                            <p class="outfit-warning-text">⚠ Folder name contains spaces — rename in your viewer to avoid RLV matching the wrong folder.</p>
                            <?php endif; ?>
                        </div>

                        <!-- Outfit actions — Wear and Remove only; delete is on the image -->
                        <div class="outfit-actions">
                            <button
                                class="btn btn-wear<?= (!$isOnline || $isLocked) ? ' btn-wear--offline' : '' ?>"
                                data-outfit-id="<?= (int)$outfit['id'] ?>"
                                data-outfit-name="<?= htmlspecialchars($outfit['outfit_name'], ENT_QUOTES) ?>"
                                data-wear-mode="<?= htmlspecialchars($wearMode, ENT_QUOTES) ?>"
                                <?= $isLocked ? 'title="Outfit is locked — unlock in properties to wear"' : (!$isOnline ? 'title="HUD is offline — cannot send wear command"' : '') ?>
                                onclick="wearOutfit(this)"
                            >
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M20.38 3.46L16 2a4 4 0 01-8 0L3.62 3.46a2 2 0 00-1.34 2.23l.58 3.57a1 1 0 00.99.84H6v10c0 1.1.9 2 2 2h8a2 2 0 002-2V10h2.15a1 1 0 00.99-.84l.58-3.57a2 2 0 00-1.34-2.23z"/>
                                </svg>
                                Wear
                            </button>
                            <button
                                class="btn btn-remove<?= (!$isOnline || $isLocked) ? ' btn-remove--offline' : '' ?>"
                                data-outfit-id="<?= (int)$outfit['id'] ?>"
                                data-outfit-name="<?= htmlspecialchars($outfit['outfit_name'], ENT_QUOTES) ?>"
                                <?= $isLocked ? 'title="Outfit is locked — unlock in properties to remove"' : (!$isOnline ? 'title="HUD is offline — cannot send remove command"' : '') ?>
                                onclick="removeOutfit(this)"
                            >Remove</button>
                        </div>

                    </div><!-- /.outfit-card -->
                    <?php endforeach; ?>
                </div><!-- /.outfit-grid -->
                <p class="filter-no-results" id="filterNoResults" style="display:none">No outfits match the current filters.</p>
                <?php endif; ?>

            </div>
        </section>

    </div><!-- /.dashboard-wrap -->

    <!-- Wear feedback toast -->
    <div id="wear-toast" class="wear-toast" aria-live="polite"></div>

    <!-- ════════════════════════════════════════════════════════
         DELETE CONFIRMATION MODAL
         ════════════════════════════════════════════════════════ -->
    <div id="delete-modal" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="delete-modal-title" hidden>
        <div class="modal-box modal-box--sm">
            <div class="modal-header">
                <h2 class="modal-title" id="delete-modal-title">Delete Outfit</h2>
            </div>
            <div class="modal-body">
                <p class="delete-confirm-text">
                    Are you sure you want to delete <strong id="delete-outfit-name"></strong>?
                    This cannot be undone.
                </p>
            </div>
            <div class="modal-footer modal-footer--right">
                <button class="btn btn-ghost" onclick="closeDeleteModal()">Cancel</button>
                <button class="btn btn-danger" id="delete-confirm-btn" onclick="executeDelete()">Delete</button>
            </div>
        </div>
    </div>

    <!-- ════════════════════════════════════════════════════════
         OUTFIT PROPERTIES MODAL
         ════════════════════════════════════════════════════════ -->
    <div id="props-modal" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="props-modal-title" hidden>
        <div class="modal-box modal-box--lg">

            <!-- Modal header -->
            <div class="modal-header">
                <h2 class="modal-title" id="props-modal-title">Outfit Properties</h2>
                <button class="modal-close-btn" onclick="closePropsModal()" aria-label="Close">&times;</button>
            </div>

            <!-- ── Wear options bar ─────────────────────────────── -->
            <div class="props-wear-bar">
                <div class="wear-mode-groups">
                    <div class="wear-mode-group">
                        <span class="wear-mode-label">Scope:</span>
                        <label class="wear-radio">
                            <input type="radio" name="prop_wear_scope" value="folder">
                            <span>This folder only</span>
                        </label>
                        <label class="wear-radio">
                            <input type="radio" name="prop_wear_scope" value="subfolders" checked>
                            <span>Folder &amp; subfolders</span>
                        </label>
                    </div>
                    <div class="wear-mode-group wear-mode-group--sep">
                        <span class="wear-mode-label">Method:</span>
                        <label class="wear-radio">
                            <input type="radio" name="prop_wear_method" value="add">
                            <span>Add</span>
                        </label>
                        <label class="wear-radio">
                            <input type="radio" name="prop_wear_method" value="replace" checked>
                            <span>Replace</span>
                        </label>
                    </div>
                </div>
                <div class="props-wear-actions">
                    <button
                        class="btn btn-wear btn-wear--modal"
                        id="props-wear-btn"
                        onclick="wearFromProps()"
                    >
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M20.38 3.46L16 2a4 4 0 01-8 0L3.62 3.46a2 2 0 00-1.34 2.23l.58 3.57a1 1 0 00.99.84H6v10c0 1.1.9 2 2 2h8a2 2 0 002-2V10h2.15a1 1 0 00.99-.84l.58-3.57a2 2 0 00-1.34-2.23z"/>
                        </svg>
                        Wear
                    </button>
                    <button
                        class="btn btn-remove btn-remove--modal"
                        id="props-remove-btn"
                        onclick="removeFromProps()"
                    >Remove</button>
                </div>
            </div>

            <!-- ── Lock bar ────────────────────────────────────── -->
            <div id="props-lock-bar" class="props-lock-bar">
                <div class="props-lock-info">
                    <span id="props-lock-status-icon" class="props-lock-icon">🔓</span>
                    <span id="props-lock-status-text" class="props-lock-text">This outfit is not locked.</span>
                </div>
                <div class="props-lock-actions">
                    <button id="props-lock-btn" class="btn btn-lock" onclick="toggleOutfitLock()">Lock outfit</button>
                    <button id="props-force-unlock-btn" class="btn btn-force-unlock" onclick="forceUnlockOutfit()" title="Emergency: clear lock in database and release RLV restriction" style="display:none">Force unlock</button>
                </div>
            </div>

            <!-- Modal body — scrollable -->
            <div class="modal-body modal-body--scroll">

                <!-- Title -->
                <div class="props-row">
                    <label class="props-label" for="prop-title">Title</label>
                    <div class="props-control">
                        <input type="text" id="prop-title" class="field-input" placeholder="Outfit name">
                    </div>
                </div>

                <!-- Path -->
                <div class="props-row">
                    <label class="props-label" for="prop-folder-path">Path</label>
                    <div class="props-control">
                        <div class="props-path-row">
                            <input type="text" id="prop-folder-path" class="field-input props-path-input" placeholder="e.g. .ensemble/MyOutfit" readonly>
                            <button type="button" class="btn btn-ghost btn-sm props-path-edit-btn" id="props-path-edit-btn" onclick="togglePathEdit()" title="Edit path">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14">
                                    <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/>
                                    <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>
                                </svg>
                                Edit
                            </button>
                        </div>
                        <span class="field-hint props-path-hint-text" id="props-path-hint">The RLV folder path for this outfit. Edit only if it was saved incorrectly.</span>
                    </div>
                </div>

                <!-- Image -->
                <div class="props-row props-row--image">
                    <label class="props-label">Image</label>
                    <div class="props-control props-image-wrap">
                        <div class="props-image-preview-wrap">
                            <img id="prop-image-preview" src="" alt="Outfit image"
                                 class="props-image-preview props-image-preview--clickable"
                                 onclick="openLightbox(this.src, this.alt)"
                                 title="Click to view full size">
                        </div>
                        <div class="props-image-controls">
                            <button class="btn btn-ghost btn-sm" onclick="browseOutfitImage()">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14">
                                    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                                    <polyline points="17 8 12 3 7 8"/>
                                    <line x1="12" y1="3" x2="12" y2="15"/>
                                </svg>
                                Browse…
                            </button>
                            <div id="prop-image-status" class="image-upload-status"></div>
                            <span class="field-hint">JPEG, PNG or WebP. Max 2 MB.<br>Resized to 800×800 on upload.</span>
                            <input type="file" id="prop-image-file" accept="image/jpeg,image/png,image/webp" style="display:none" onchange="uploadOutfitImage(this)">
                        </div>
                    </div>
                </div>

                <!-- Tags -->
                <div class="props-row">
                    <label class="props-label" for="prop-tags">Tags</label>
                    <div class="props-control">
                        <textarea id="prop-tags" class="field-input props-tags-area" rows="2" placeholder="e.g. Casual, Summer, Mesh"></textarea>
                        <span class="field-hint">Comma-separated list of tags.</span>
                    </div>
                </div>

                <!-- Comments -->
                <div class="props-row">
                    <label class="props-label" for="prop-comments">Comments</label>
                    <div class="props-control">
                        <textarea id="prop-comments" class="field-input props-textarea" rows="3" placeholder="Notes about this outfit…"></textarea>
                    </div>
                </div>

                <!-- Access -->
                <div class="props-row">
                    <label class="props-label">Access</label>
                    <div class="props-control">
                        <div class="access-radio-group">
                            <label class="access-radio">
                                <input type="radio" name="prop_access" value="public" checked>
                                <span class="access-radio-label">
                                    <strong>Public</strong>
                                    <span class="access-radio-hint">Visible in all shared wardrobe views</span>
                                </span>
                            </label>
                            <label class="access-radio">
                                <input type="radio" name="prop_access" value="private">
                                <span class="access-radio-label">
                                    <strong>Private</strong>
                                    <span class="access-radio-hint">Only visible in views that permit private items</span>
                                </span>
                            </label>
                        </div>
                    </div>
                </div>

                <!-- Base Outfits -->
                <div class="props-row">
                    <label class="props-label">Base Outfits</label>
                    <div class="props-control">
                        <div class="outfit-picker" id="picker-base-outfits">
                            <div class="outfit-picker__chips" id="picker-base-outfits__chips">
                                <span class="outfit-picker__placeholder">No base outfits selected…</span>
                            </div>
                            <button type="button" class="outfit-picker__add-btn" id="picker-base-outfits__btn"
                                    onclick="opToggle('base-outfits')">+ Add</button>
                            <div class="outfit-picker__dropdown" id="picker-base-outfits__dropdown" style="display:none">
                                <input type="text" class="outfit-picker__search" placeholder="Search outfits…"
                                       oninput="opFilter('base-outfits', this.value)">
                                <ul class="outfit-picker__list" id="picker-base-outfits__list"></ul>
                            </div>
                        </div>
                        <span class="field-hint">These will be worn <em>before</em> this outfit, in order.</span>
                    </div>
                </div>

                <!-- Additional Items -->
                <div class="props-row">
                    <label class="props-label">Additional Items</label>
                    <div class="props-control">
                        <div class="outfit-picker" id="picker-additional-items">
                            <div class="outfit-picker__chips" id="picker-additional-items__chips">
                                <span class="outfit-picker__placeholder">No additional items selected…</span>
                            </div>
                            <button type="button" class="outfit-picker__add-btn" id="picker-additional-items__btn"
                                    onclick="opToggle('additional-items')">+ Add</button>
                            <div class="outfit-picker__dropdown" id="picker-additional-items__dropdown" style="display:none">
                                <input type="text" class="outfit-picker__search" placeholder="Search outfits…"
                                       oninput="opFilter('additional-items', this.value)">
                                <ul class="outfit-picker__list" id="picker-additional-items__list"></ul>
                            </div>
                        </div>
                        <span class="field-hint">These will be worn <em>after</em> this outfit, in order.</span>
                    </div>
                </div>

                <!-- Wear After Remove -->
                <div class="props-row">
                    <label class="props-label">Wear After Remove</label>
                    <div class="props-control">
                        <div class="outfit-picker" id="picker-wear-after-remove">
                            <div class="outfit-picker__chips" id="picker-wear-after-remove__chips">
                                <span class="outfit-picker__placeholder">No outfits selected…</span>
                            </div>
                            <button type="button" class="outfit-picker__add-btn" id="picker-wear-after-remove__btn"
                                    onclick="opToggle('wear-after-remove')">+ Add</button>
                            <div class="outfit-picker__dropdown" id="picker-wear-after-remove__dropdown" style="display:none">
                                <input type="text" class="outfit-picker__search" placeholder="Search outfits…"
                                       oninput="opFilter('wear-after-remove', this.value)">
                                <ul class="outfit-picker__list" id="picker-wear-after-remove__list"></ul>
                            </div>
                        </div>
                        <span class="field-hint">These will be worn when this outfit is <em>removed</em> via the Remove button. Only fires on explicit removal — not in-world or sequence-based.</span>
                    </div>
                </div>

                <!-- Remove Before Wearing -->
                <div class="props-row">
                    <label class="props-label">Before Wearing</label>
                    <div class="props-control">
                        <label class="toggle-label">
                            <input type="checkbox" id="prop-remove-before-wear" class="toggle-checkbox">
                            <span class="toggle-text">Remove attachment points before wearing</span>
                        </label>
                        <div id="prop-removal-scope" class="removal-scope" style="display:none">
                            <div class="removal-scope-radios">
                                <label class="wear-radio">
                                    <input type="radio" name="prop_removal_scope" value="default" checked>
                                    <span>Use my defaults</span>
                                </label>
                                <label class="wear-radio">
                                    <input type="radio" name="prop_removal_scope" value="custom">
                                    <span>Custom for this outfit</span>
                                </label>
                            </div>
                            <div id="prop-removal-points-wrap" style="display:none">
                                <!-- Point checklist injected by JS -->
                            </div>
                        </div>
                        <span class="field-hint">Clears selected attachment points before attaching this outfit.</span>
                    </div>
                </div>

            </div><!-- /.modal-body -->

            <!-- Modal footer -->
            <div class="modal-footer">
                <button class="btn btn-ghost" onclick="discardPropsChanges()">Discard changes</button>
                <button class="btn btn-primary" onclick="saveOutfitProps()">Save</button>
            </div>

        </div><!-- /.modal-box -->
    </div><!-- /#props-modal -->

    <!-- ════════════════════════════════════════════════════════
         LIGHTBOX — full-size outfit image viewer
         Layers on top of the properties modal (higher z-index).
         ════════════════════════════════════════════════════════ -->
    <div id="lightbox" class="lightbox-backdrop" role="dialog" aria-modal="true" aria-label="Full size image" hidden onclick="closeLightbox()">
        <div class="lightbox-inner" onclick="event.stopPropagation()">
            <img id="lightbox-img" src="" alt="" class="lightbox-img">
            <button class="lightbox-close btn btn-ghost" onclick="closeLightbox()">Close</button>
        </div>
    </div>

    <!-- ════════════════════════════════════════════════════════
         ACCOUNT MODAL
         Settings › Account — shows user info and worn items.
         ════════════════════════════════════════════════════════ -->
    <div id="account-modal" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="account-modal-title" hidden>
        <div class="modal-box modal-box--md">

            <div class="modal-header">
                <h2 class="modal-title" id="account-modal-title">Account</h2>
                <button class="modal-close-btn" onclick="closeAccountModal()" aria-label="Close">&times;</button>
            </div>

            <div class="modal-body modal-body--scroll">

                <!-- ── Part 1: Account info ─────────────────── -->
                <section class="acct-section">
                    <h3 class="acct-section-title">Account Details</h3>
                    <dl class="acct-dl">
                        <div class="acct-row">
                            <dt>Username</dt>
                            <dd><?= htmlspecialchars($userData['username'] ?? '—') ?></dd>
                        </div>
                        <div class="acct-row">
                            <dt>Avatar UUID</dt>
                            <dd class="acct-mono"><?= htmlspecialchars($userData['owner_uuid'] ?? '—') ?></dd>
                        </div>
                        <div class="acct-row">
                            <dt>Region</dt>
                            <dd><?= htmlspecialchars($userData['region_name'] ?? '—') ?></dd>
                        </div>
                        <div class="acct-row">
                            <dt>Simulator URL</dt>
                            <dd class="acct-mono acct-muted acct-truncate" title="<?= htmlspecialchars($userData['sim_url'] ?? '') ?>"><?= htmlspecialchars($userData['sim_url'] ?? '—') ?></dd>
                        </div>
                        <div class="acct-row">
                            <dt>Last seen</dt>
                            <dd id="acct-last-seen-dd"><?= ensemble_time_ago((int)($userData['last_seen'] ?? 0)) ?></dd>
                        </div>
                        <div class="acct-row">
                            <dt>HUD status</dt>
                            <?php
                                $hudLocked = !empty($userData['hud_locked']);
                                $hudStatusLabel = $hudLocked ? '🔒 Locked' : '🔓 Unlocked';
                                $hudStatusClass = $hudLocked ? 'acct-hud-locked' : 'acct-hud-unlocked';
                            ?>
                            <dd id="acct-hud-status-dd" class="<?= $hudStatusClass ?>"><?= $hudStatusLabel ?></dd>
                        </div>
                        <div class="acct-row">
                            <dt>Member since</dt>
                            <dd><?= ($userData['created_at'] ?? 0) ? date('d M Y', (int)$userData['created_at']) : '—' ?></dd>
                        </div>
                        <div class="acct-row">
                            <dt>HUD scripts</dt>
                            <dd class="acct-version-pills">
                                <?php
                                    $cv = htmlspecialchars($userData['core_version'] ?? '');
                                    $rv = htmlspecialchars($userData['relay_version'] ?? '');
                                ?>
                                <span class="version-pill" title="Core script version">
                                    Core <?= $cv !== '' ? 'Version ' . $cv : '(unknown)' ?>
                                </span>
                                <span class="version-pill" title="WebRelay script version">
                                    Relay <?= $rv !== '' ? 'Version ' . $rv : '(unknown)' ?>
                                </span>
                            </dd>
                        </div>
                    </dl>
                </section>

                <!-- ── Part 2: Worn items ───────────────────── -->
                <section class="acct-section acct-section--worn">
                    <div class="acct-worn-header">
                        <h3 class="acct-section-title">Currently Worn</h3>
                        <button class="btn btn-ghost btn-sm" id="refresh-worn-btn" onclick="loadWornItems()">
                            <svg id="refresh-worn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14" style="margin-right:.3rem">
                                <polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>
                                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
                            </svg>
                            Refresh
                        </button>
                    </div>
                    <p class="acct-worn-notice">🔒 Locked outfit items will not be removed.</p>
                    <div id="worn-items-area">
                        <p class="acct-worn-hint">Click Refresh to load currently worn items from your HUD.</p>
                    </div>
                </section>

            </div><!-- /.modal-body -->

            <div class="modal-footer modal-footer--right">
                <button class="btn btn-ghost" onclick="closeAccountModal()">Close</button>
            </div>

        </div><!-- /.modal-box -->
    </div><!-- /#account-modal -->

    <!-- ════════════════════════════════════════════════════════
         DEFAULT REMOVAL POINTS MODAL
         Settings › Default Removal Points
         ════════════════════════════════════════════════════════ -->
    <div id="removal-modal" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="removal-modal-title" hidden>
        <div class="modal-box modal-box--md">

            <div class="modal-header">
                <h2 class="modal-title" id="removal-modal-title">Default Removal Points</h2>
                <button class="modal-close-btn" onclick="closeRemovalModal()" aria-label="Close">&times;</button>
            </div>

            <div class="modal-body modal-body--scroll">
                <p class="removal-modal-intro">When an outfit has <strong>Remove before wearing</strong> enabled and set to <em>Use my defaults</em>, these attachment points will be cleared before the outfit is worn.</p>
                <div id="removal-checklist-wrap">
                    <p class="acct-worn-hint"><span class="acct-spinner"></span> Loading…</p>
                </div>
            </div>

            <div class="modal-footer">
                <button class="btn btn-ghost" onclick="closeRemovalModal()">Cancel</button>
                <button class="btn btn-primary" id="removal-save-btn" onclick="saveRemovalDefaults()">Save defaults</button>
            </div>

        </div>
    </div>

    <?php endif; ?>
    </main>

    <!-- ── Footer ───────────────────────────────────────────── -->
    <footer class="site-footer">
        <p>Ensemble: <?= ENSEMBLE_VERSION ?> &mdash; Open source outfit management for OpenSim</p>
    </footer>

</div><!-- /.page-wrap -->

<?php if ($page === 'dashboard'): ?>
<script>
// ── Outfit data map — keyed by outfit ID ─────────────────────
// All outfit data is stored here rather than in HTML attributes
// to avoid any HTML-escaping issues with JSON in attributes.
var OUTFIT_DATA = <?php
    $map = [];
    foreach ($outfits as $o) {
        $raw      = $o['wear_mode'] ?? '';
        $wm       = in_array($raw, ['folder_add','folder_replace','subfolders_add','subfolders_replace'], true)
                    ? $raw : 'subfolders_replace';
        $imgSrc   = $o['image_filename']
                    ? 'image.php?file=' . urlencode($o['image_filename'])
                    : 'themes/' . $activeTheme . '/placeholder.png';
        $map[(int)$o['id']] = [
            'id'               => (int)$o['id'],
            'outfit_name'      => $o['outfit_name'],
            'folder_path'      => $o['folder_path'],
            'image_filename'   => (string)($o['image_filename'] ?? ''),
            'tags'             => (string)($o['tags'] ?? ''),
            'comments'         => (string)($o['comments'] ?? ''),
            'access_level'     => (string)($o['access_level'] ?? 'public'),
            'wear_mode'          => $wm,
            'base_outfits'       => (string)($o['base_outfits'] ?? ''),
            'additional_items'   => (string)($o['additional_items'] ?? ''),
            'wear_after_remove'  => (string)($o['wear_after_remove'] ?? ''),
            'image_src'          => $imgSrc,
            'locked'             => !empty($o['locked']),
            'remove_before_wear' => !empty($o['remove_before_wear']),
            'removal_points'     => (string)($o['removal_points'] ?? ''),
        ];
    }
    echo json_encode($map, JSON_HEX_TAG | JSON_HEX_AMP);
?>;

// ══════════════════════════════════════════════════════════════
// FILTER BAR
// ══════════════════════════════════════════════════════════════
var _filterExpanded = false;
var _totalOutfits   = document.querySelectorAll('#outfitGrid .outfit-card').length;

function applyFilters() {
    var _hidePrivateCb = document.getElementById('filterHidePrivate');
    var hidePrivate = _hidePrivateCb ? _hidePrivateCb.checked : false;
    sessionStorage.setItem('ensemble_hidePrivate', hidePrivate ? '1' : '0');
    var activeTags  = [];
    document.querySelectorAll('.filter-tag-cb:checked').forEach(function(cb) {
        activeTags.push(cb.value); // already lowercase
    });

    var cards   = document.querySelectorAll('#outfitGrid .outfit-card');
    var visible = 0;

    cards.forEach(function(card) {
        var isPrivate = card.getAttribute('data-access') === 'private';
        var cardTags  = card.getAttribute('data-tags') || ''; // pipe-separated lowercase
        var show = true;

        // Hide private check
        if (hidePrivate && isPrivate) show = false;

        // Tag filter — card must match ANY active tag (OR logic)
        if (show && activeTags.length > 0) {
            var cardTagArr = cardTags ? cardTags.split('|') : [];
            var matches = activeTags.some(function(t) { return cardTagArr.indexOf(t) !== -1; });
            if (!matches) show = false;
        }

        // Use display:none — card.hidden doesn't suppress grid items reliably
        card.style.display = show ? '' : 'none';
        if (show) visible++;
    });

    // Update count badge
    var countEl = document.getElementById('outfitCount');
    if (countEl) {
        countEl.textContent = (visible === _totalOutfits)
            ? _totalOutfits + ' saved'
            : visible + ' of ' + _totalOutfits + ' showing';
    }

    // No-results message
    var noRes = document.getElementById('filterNoResults');
    if (noRes) noRes.style.display = (visible === 0) ? '' : 'none';

    // Update the collapsed tag pills to show only active tags
    updateCollapsedPills(activeTags);
}

function updateCollapsedPills(activeTags) {
    var container = document.getElementById('filterTagsCollapsed');
    if (!container) return;
    container.innerHTML = '';

    if (activeTags.length === 0) {
        // No active tags — show "Not filtered" hint
        var hint = document.createElement('span');
        hint.className = 'filter-not-filtered';
        hint.textContent = 'Not filtered';
        container.appendChild(hint);
    } else {
        // Show one pill per active tag (display label, not lowercase key)
        activeTags.forEach(function(tagKey) {
            // Find the display label from the checklist checkbox's sibling span
            var cb = document.querySelector('.filter-tag-cb[value="' + tagKey + '"]');
            var label = cb ? cb.parentElement.querySelector('span').textContent : tagKey;
            var pill = document.createElement('span');
            pill.className = 'filter-tag-pill filter-tag-pill--active';
            pill.textContent = label;
            container.appendChild(pill);
        });
    }

    // Show/hide the collapsed Clear button
    var clearBtn = document.getElementById('filterClearCollapsed');
    if (clearBtn) clearBtn.hidden = (activeTags.length === 0);
}

function clearAllTagFilters() {
    document.querySelectorAll('.filter-tag-cb').forEach(function(cb) { cb.checked = false; });
    applyFilters();
}

function toggleFilterExpand() {
    _filterExpanded = !_filterExpanded;
    var panel   = document.getElementById('filterBarExpanded');
    var chevron = document.getElementById('filterChevron');
    var label   = document.getElementById('filterExpandLabel');
    if (!panel) return;

    panel.hidden = !_filterExpanded;
    if (chevron) chevron.style.transform = _filterExpanded ? 'rotate(180deg)' : '';
    if (label)   label.textContent = _filterExpanded ? 'Done' : 'Filter';
}

// Initialise filters on page load.
// Restores "Hide Private" from sessionStorage (persists across refreshes within
// the same browser session; cleared automatically when the session ends).
(function() {
    var cb = document.getElementById('filterHidePrivate');
    if (cb && sessionStorage.getItem('ensemble_hidePrivate') === '1') {
        cb.checked = true;
    }
    applyFilters();
})();

function openOutfitPropertiesById(id) {
    var outfit = OUTFIT_DATA[id];
    if (outfit) openOutfitProperties(outfit);
}

// ── CSRF helper ───────────────────────────────────────────────
// Appends the CSRF token to any FormData before it is sent.
// Every mutating fetch() call passes its FormData through csrfFd().
var CSRF_TOKEN = <?= json_encode(auth_csrf_token()) ?>;
function csrfFd(fd) {
    fd.append('csrf_token', CSRF_TOKEN);
    return fd;
}

// ── Auto-refresh status badge every 60 seconds ──────────────────
// Previously did a full page reload to keep the connection badge
// current. Replaced with a lightweight fetch so client-side state
// (filters, expanded panels) is never disrupted.
//
// The header badge is updated in-place. The outfit count badge and
// Wear/Remove button states also reflect the latest HUD status.
(function() {
    function refreshBadge() {
        fetch('api.php?action=get_account_status', { method: 'POST', body: csrfFd(new FormData()) })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.status !== 'ok') return;

            var age = Math.floor(Date.now() / 1000) - (data.last_seen || 0);
            var isOnline = (data.last_seen && age < 180);
            var isStale  = (!isOnline && data.last_seen && age < 600);

            var label = isOnline ? 'Online' : (isStale ? 'Stale' : 'Offline');
            var cls   = isOnline ? 'status-online' : (isStale ? 'status-stale' : 'status-offline');

            // Update header status badge
            var badge = document.querySelector('.status-badge');
            if (badge) {
                badge.className = 'status-badge ' + cls;
                var textNode = badge.querySelector('.status-dot');
                if (textNode && textNode.nextSibling) {
                    textNode.nextSibling.textContent = ' ' + label;
                } else {
                    // Fallback: set full text content preserving the dot span
                    var dot = badge.querySelector('.status-dot');
                    badge.textContent = label;
                    if (dot) badge.insertBefore(dot, badge.firstChild);
                }
            }

            // Update Wear/Remove button states across all cards
            var wearBtns = document.querySelectorAll('.btn-wear:not(.btn-wear--modal)');
            var remBtns  = document.querySelectorAll('.btn-remove:not(.btn-remove--modal)');
            wearBtns.forEach(function(btn) {
                // Don't touch locked outfits — their offline state is intentional
                var card = btn.closest('.outfit-card');
                if (card && card.classList.contains('outfit-card--locked')) return;
                btn.classList.toggle('btn-wear--offline', !isOnline);
                if (!isOnline) {
                    btn.title = 'HUD is offline — cannot send wear command';
                } else {
                    btn.title = '';
                }
            });
            remBtns.forEach(function(btn) {
                var card = btn.closest('.outfit-card');
                if (card && card.classList.contains('outfit-card--locked')) return;
                btn.classList.toggle('btn-remove--offline', !isOnline);
                if (!isOnline) {
                    btn.title = 'HUD is offline — cannot send remove command';
                } else {
                    btn.title = '';
                }
            });
        })
        .catch(function() { /* silent — stale badge is harmless */ });
    }

    // Poll every 60 seconds
    setInterval(refreshBadge, 60000);
})();

// ══════════════════════════════════════════════════════════════
// WEAR OUTFIT
// POSTs to api.php?action=wear
// ══════════════════════════════════════════════════════════════
function wearOutfit(btn) {
    var outfitId   = btn.getAttribute('data-outfit-id');
    var outfitName = btn.getAttribute('data-outfit-name');
    var wearMode   = btn.getAttribute('data-wear-mode') || 'subfolders_replace';

    if (btn.classList.contains('btn-wear--offline')) {
        showToast('HUD is offline — cannot send wear command.', 'error');
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Sending…';

    var formData = new FormData();
    formData.append('outfit_id', outfitId);
    formData.append('wear_mode', wearMode);

    fetch('api.php?action=wear', {
        method: 'POST',
        body: csrfFd(formData)
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'ok') {
            showToast('Wearing: ' + outfitName, 'success');
        } else if (data.error === 'hud_offline') {
            showToast('HUD is offline — wear command not delivered.', 'error');
        } else {
            showToast('Error: ' + (data.error || 'unknown error'), 'error');
        }
    })
    .catch(function() {
        showToast('Could not reach the web panel. Please try again.', 'error');
    })
    .finally(function() {
        setTimeout(function() {
            btn.disabled = false;
            btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.38 3.46L16 2a4 4 0 01-8 0L3.62 3.46a2 2 0 00-1.34 2.23l.58 3.57a1 1 0 00.99.84H6v10c0 1.1.9 2 2 2h8a2 2 0 002-2V10h2.15a1 1 0 00.99-.84l.58-3.57a2 2 0 00-1.34-2.23z"/></svg> Wear';
        }, 2000);
    });
}

// ══════════════════════════════════════════════════════════════
// REMOVE OUTFIT
// POSTs to api.php?action=remove
// ══════════════════════════════════════════════════════════════
function removeOutfit(btn) {
    var outfitId   = btn.getAttribute('data-outfit-id');
    var outfitName = btn.getAttribute('data-outfit-name');

    if (btn.classList.contains('btn-remove--offline')) {
        showToast('HUD is offline — cannot send remove command.', 'error');
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Sending…';

    var formData = new FormData();
    formData.append('outfit_id', outfitId);

    fetch('api.php?action=remove', {
        method: 'POST',
        body: csrfFd(formData)
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'ok') {
            showToast('Removed: ' + outfitName, 'success');
        } else if (data.error === 'hud_offline') {
            showToast('HUD is offline — remove command not delivered.', 'error');
        } else {
            showToast('Error: ' + (data.error || 'unknown error'), 'error');
        }
    })
    .catch(function() {
        showToast('Could not reach the web panel. Please try again.', 'error');
    })
    .finally(function() {
        setTimeout(function() {
            btn.disabled = false;
            btn.textContent = 'Remove';
        }, 2000);
    });
}

// ══════════════════════════════════════════════════════════════
// DELETE OUTFIT — confirmation modal
// ══════════════════════════════════════════════════════════════
var _deleteTargetId   = null;
var _deleteTargetName = null;

function confirmDeleteOutfit(btn) {
    _deleteTargetId   = btn.getAttribute('data-outfit-id');
    _deleteTargetName = btn.getAttribute('data-outfit-name');

    document.getElementById('delete-outfit-name').textContent = _deleteTargetName;

    var modal = document.getElementById('delete-modal');
    modal.hidden = false;
    modal.querySelector('.modal-box').focus();
}

function closeDeleteModal() {
    document.getElementById('delete-modal').hidden = true;
    _deleteTargetId   = null;
    _deleteTargetName = null;
}

function executeDelete() {
    if (!_deleteTargetId) return;

    var btn = document.getElementById('delete-confirm-btn');
    btn.disabled = true;
    btn.textContent = 'Deleting…';

    // Capture these before closeDeleteModal() nulls them
    var deletingId   = _deleteTargetId;
    var deletingName = _deleteTargetName;

    var formData = new FormData();
    formData.append('outfit_id', deletingId);

    fetch('api.php?action=outfit_delete', {
        method: 'POST',
        body: csrfFd(formData)
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'ok') {
            // Reset button before closing so it's fresh next time the modal opens
            btn.disabled = false;
            btn.textContent = 'Delete';
            closeDeleteModal();
            // Remove card from DOM
            var deleteBtn = document.querySelector('.btn-delete[data-outfit-id="' + deletingId + '"]');
            if (deleteBtn) {
                var card = deleteBtn.closest('.outfit-card');
                if (card) card.remove();
            }
            showToast('Deleted: ' + deletingName, 'success');
        } else {
            showToast('Error: ' + (data.error || 'unknown error'), 'error');
            btn.disabled = false;
            btn.textContent = 'Delete';
        }
    })
    .catch(function() {
        showToast('Could not reach the server. Please try again.', 'error');
        btn.disabled = false;
        btn.textContent = 'Delete';
    });
}

// Close delete modal on backdrop click
document.getElementById('delete-modal').addEventListener('click', function(e) {
    if (e.target === this) closeDeleteModal();
});

// ══════════════════════════════════════════════════════════════
// OUTFIT PROPERTIES MODAL
// ══════════════════════════════════════════════════════════════
var _currentOutfitId   = null;
var _originalPropsData = null; // snapshot for "Discard changes"
var _isNewOutfit       = false; // true when opened via "Add New" (no existing DB record)

// Open the props modal in creation mode — no existing outfit, blank slate.
// Path field is editable immediately; wear/lock bars are hidden.
// Nothing is written to the DB until the user clicks Save.
function openAddOutfitModal() {
    _isNewOutfit       = true;
    _currentOutfitId   = null;
    _originalPropsData = null;

    // ── Clear all fields ─────────────────────────────────────
    document.getElementById('prop-title').value    = '';
    document.getElementById('prop-tags').value     = '';
    document.getElementById('prop-comments').value = '';
    opLoad('base-outfits',      '');
    opLoad('additional-items',  '');
    opLoad('wear-after-remove', '');

    // Path — blank and editable from the start
    var pathInput = document.getElementById('prop-folder-path');
    pathInput.value    = '';
    pathInput.readOnly = false;
    pathInput.classList.add('props-path-input--editing');
    var editBtn = document.getElementById('props-path-edit-btn');
    if (editBtn) {
        editBtn.classList.add('props-path-edit-btn--active');
        // Hide the Edit/Cancel toggle button — path is always editable here
        editBtn.style.display = 'none';
    }
    var hint = document.getElementById('props-path-hint');
    if (hint) hint.textContent = 'Enter the RLV folder path for this outfit (e.g. .ensemble/MyOutfit).';

    // Image — placeholder; upload not available until outfit is saved
    var preview = document.getElementById('prop-image-preview');
    preview.src = 'themes/' + ENSEMBLE_ACTIVE_THEME + '/placeholder.png';
    preview.onerror = null;

    // Access — default to public
    document.querySelectorAll('input[name="prop_access"]').forEach(function(r) {
        r.checked = (r.value === 'public');
    });

    // Wear mode — default to subfolders_replace
    document.querySelectorAll('input[name="prop_wear_scope"]').forEach(function(r) {
        r.checked = (r.value === 'subfolders');
    });
    document.querySelectorAll('input[name="prop_wear_method"]').forEach(function(r) {
        r.checked = (r.value === 'replace');
    });

    // Remove before wearing — off by default
    document.getElementById('prop-remove-before-wear').checked = false;
    document.getElementById('prop-removal-scope').style.display = 'none';
    document.getElementById('prop-removal-points-wrap').style.display = 'none';

    // ── Hide controls that need an existing outfit ────────────
    document.querySelector('.props-wear-bar').style.display = 'none';
    document.getElementById('props-lock-bar').style.display = 'none';

    // Hide image upload controls — outfit must exist before an image can be saved
    var imageRow = document.querySelector('.props-row--image');
    if (imageRow) imageRow.style.display = 'none';

    // ── Update modal title ────────────────────────────────────
    document.getElementById('props-modal-title').textContent = 'Add New Outfit';

    // Open modal and focus path (most important field)
    document.getElementById('props-modal').hidden = false;
    pathInput.focus();
}

function openOutfitProperties(outfit) {
    _isNewOutfit       = false;
    _currentOutfitId   = outfit.id;
    _originalPropsData = outfit;

    // Restore controls that openAddOutfitModal may have hidden
    document.querySelector('.props-wear-bar').style.display      = '';
    document.getElementById('props-lock-bar').style.display      = '';
    var imageRow = document.querySelector('.props-row--image');
    if (imageRow) imageRow.style.display = '';
    var editBtn = document.getElementById('props-path-edit-btn');
    if (editBtn) editBtn.style.display = '';
    document.getElementById('props-modal-title').textContent = 'Outfit Properties';

    // Populate fields
    document.getElementById('prop-title').value            = outfit.outfit_name   || '';
    document.getElementById('prop-tags').value             = outfit.tags          || '';
    document.getElementById('prop-comments').value         = outfit.comments      || '';
    opLoad('base-outfits',      outfit.base_outfits      || '');
    opLoad('additional-items',  outfit.additional_items   || '');
    opLoad('wear-after-remove', outfit.wear_after_remove  || '');

    // ── Remove before wearing ────────────────────────────────
    var rbw = !!outfit.remove_before_wear;
    document.getElementById('prop-remove-before-wear').checked = rbw;
    document.getElementById('prop-removal-scope').style.display = rbw ? '' : 'none';
    // Determine scope: custom if outfit has its own removal_points, else default
    var hasCustom = outfit.removal_points && outfit.removal_points !== '';
    document.querySelectorAll('input[name="prop_removal_scope"]').forEach(function(r) {
        r.checked = (r.value === (hasCustom ? 'custom' : 'default'));
    });
    // Store custom points on the modal for later use
    document.getElementById('prop-removal-points-wrap')._customPoints =
        hasCustom ? JSON.parse(outfit.removal_points) : null;
    document.getElementById('prop-removal-points-wrap').style.display =
        (rbw && hasCustom) ? '' : 'none';
    if (rbw && hasCustom) {
        renderRemovalChecklist(
            document.getElementById('prop-removal-points-wrap'),
            JSON.parse(outfit.removal_points),
            -1   // all groups start collapsed — user opens the one they need
        );
    }

    // Show folder path in the editable path field (display verbatim as stored)
    var rawPath = outfit.folder_path || '';
    var pathInput = document.getElementById('prop-folder-path');
    if (pathInput) {
        pathInput.value = rawPath;
        pathInput.readOnly = true;
        pathInput.classList.remove('props-path-input--editing');
    }
    var editBtn = document.getElementById('props-path-edit-btn');
    if (editBtn) {
        editBtn.classList.remove('props-path-edit-btn--active');
        editBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg> Edit';
    }

    // Image preview
    var preview = document.getElementById('prop-image-preview');
    if (outfit.image_filename) {
        preview.src = 'image.php?file=' + encodeURIComponent(outfit.image_filename);
    } else {
        preview.src = 'themes/' + ENSEMBLE_ACTIVE_THEME + '/placeholder.png';
    }
    preview.onerror = function() {
        this.src = 'themes/' + ENSEMBLE_ACTIVE_THEME + '/placeholder.png';
        this.onerror = null;
    };

    // Access radio
    var access = outfit.access_level || 'public';
    document.querySelectorAll('input[name="prop_access"]').forEach(function(r) {
        r.checked = (r.value === access);
    });

    // Wear mode — split stored value into scope + method
    // Stored values: folder_add, folder_replace, subfolders_add, subfolders_replace
    // Legacy values (pre-v0.6): 'folder_only', 'folder_subfolders', 'add', 'replace', ''
    // All legacy values and unknowns default to subfolders_replace
    var wearMode   = outfit.wear_mode || 'subfolders_replace';
    var wearScope  = (wearMode === 'folder_add' || wearMode === 'folder_replace') ? 'folder' : 'subfolders';
    var wearMethod = (wearMode === 'folder_add' || wearMode === 'subfolders_add') ? 'add' : 'replace';
    document.querySelectorAll('input[name="prop_wear_scope"]').forEach(function(r) {
        r.checked = (r.value === wearScope);
    });
    document.querySelectorAll('input[name="prop_wear_method"]').forEach(function(r) {
        r.checked = (r.value === wearMethod);
    });

    // ── Update lock bar ──────────────────────────────────────
    updateLockBar(outfit.locked);

    // Open modal
    var modal = document.getElementById('props-modal');
    modal.hidden = false;
    document.getElementById('prop-title').focus();
}

function closePropsModal() {
    opCloseAll();   // close any open outfit-picker dropdowns
    document.getElementById('props-modal').hidden = true;
    _currentOutfitId   = null;
    _originalPropsData = null;

    // Restore anything openAddOutfitModal may have hidden, so the modal
    // is in a clean state if it's next opened via openOutfitProperties()
    if (_isNewOutfit) {
        document.querySelector('.props-wear-bar').style.display = '';
        document.getElementById('props-lock-bar').style.display = '';
        var imageRow = document.querySelector('.props-row--image');
        if (imageRow) imageRow.style.display = '';
        var editBtn = document.getElementById('props-path-edit-btn');
        if (editBtn) editBtn.style.display = '';
        document.getElementById('props-modal-title').textContent = 'Outfit Properties';
    }
    _isNewOutfit = false;
}

function discardPropsChanges() {
    // In create mode there's no snapshot — just close
    if (_isNewOutfit) {
        closePropsModal();
        return;
    }
    // Re-populate from snapshot then close
    if (_originalPropsData) {
        openOutfitProperties(_originalPropsData);
    }
    closePropsModal();
}

// Toggle the folder path field between read-only display and editable state.
function togglePathEdit() {
    var input  = document.getElementById('prop-folder-path');
    var btn    = document.getElementById('props-path-edit-btn');
    var hint   = document.getElementById('props-path-hint');
    if (!input) return;

    if (input.readOnly) {
        // Switch to edit mode
        input.readOnly = false;
        input.classList.add('props-path-input--editing');
        btn.classList.add('props-path-edit-btn--active');
        btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><path d="M18 6L6 18"/><path d="M6 6l12 12"/></svg> Cancel';
        if (hint) hint.textContent = 'Enter the full path exactly as it is stored (e.g. RLVOutfits/MyOutfit or #RLV/MyOutfit).';
        input.focus();
        input.select();
    } else {
        // Cancel — restore original value from OUTFIT_DATA snapshot
        if (_originalPropsData) {
            var orig = _originalPropsData.folder_path || '';
            input.value = orig;
        }
        input.readOnly = true;
        input.classList.remove('props-path-input--editing');
        btn.classList.remove('props-path-edit-btn--active');
        btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg> Edit';
        if (hint) hint.textContent = 'The RLV folder path for this outfit. Edit only if it was saved incorrectly.';
    }
}

// Build a single wear_mode string from the two radio groups.
// Format: {scope}_{method}  e.g. "subfolders_replace", "folder_add"
// Maps to RLV commands:
//   folder_replace    → @attach          (replace existing item on that point)
//   folder_add        → @attachover      (add on top, keep existing)
//   subfolders_replace→ @attachall       (replace existing items across subfolders)
//   subfolders_add    → @attachallover   (add on top across subfolders, keep existing)
function buildWearMode() {
    var scope  = 'subfolders';
    var method = 'replace';
    document.querySelectorAll('input[name="prop_wear_scope"]').forEach(function(r) {
        if (r.checked) scope = r.value;
    });
    document.querySelectorAll('input[name="prop_wear_method"]').forEach(function(r) {
        if (r.checked) method = r.value;
    });
    return scope + '_' + method;
}

function saveOutfitProps() {
    // ── Shared field collection ───────────────────────────────
    var folderPath = document.getElementById('prop-folder-path').value.trim();

    // In create mode the path is required — block save if empty
    if (_isNewOutfit && folderPath === '') {
        showToast('Please enter a folder path before saving.', 'error');
        document.getElementById('prop-folder-path').focus();
        return;
    }

    if (!_isNewOutfit && !_currentOutfitId) return;

    var wearMode = buildWearMode();

    var access = 'public';
    document.querySelectorAll('input[name="prop_access"]').forEach(function(r) {
        if (r.checked) access = r.value;
    });

    var rbwChecked = document.getElementById('prop-remove-before-wear').checked;
    var removalPoints = '';
    if (rbwChecked) {
        var scope = 'default';
        document.querySelectorAll('input[name="prop_removal_scope"]').forEach(function(r) {
            if (r.checked) scope = r.value;
        });
        if (scope === 'custom') {
            var pts = getChecklistPoints(document.getElementById('prop-removal-points-wrap'));
            removalPoints = JSON.stringify(pts);
        }
    }

    var payload = new FormData();
    payload.append('outfit_name',        document.getElementById('prop-title').value.trim());
    payload.append('folder_path',        folderPath);
    payload.append('tags',               document.getElementById('prop-tags').value.trim());
    payload.append('comments',           document.getElementById('prop-comments').value.trim());
    payload.append('access_level',       access);
    payload.append('wear_mode',          wearMode);
    payload.append('base_outfits',       opSerialise('base-outfits'));
    payload.append('additional_items',   opSerialise('additional-items'));
    payload.append('wear_after_remove',  opSerialise('wear-after-remove'));
    payload.append('remove_before_wear', rbwChecked ? '1' : '0');
    payload.append('removal_points',     removalPoints);

    var saveBtn = document.querySelector('#props-modal .btn-primary');
    saveBtn.disabled    = true;
    saveBtn.textContent = 'Saving…';

    if (_isNewOutfit) {
        // ── Create new outfit ─────────────────────────────────
        fetch('api.php?action=outfit_create_web', {
            method: 'POST',
            body: csrfFd(payload)
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.status === 'ok') {
                showToast('Outfit "' + data.outfit_name + '" created.', 'success');
                closePropsModal();
                setTimeout(function() { window.location.reload(); }, 800);
            } else if (data.error && data.error.indexOf('already exists') !== -1) {
                showToast('An outfit with this path already exists.', 'error');
            } else {
                showToast('Error: ' + (data.error || 'unknown error'), 'error');
            }
        })
        .catch(function() {
            showToast('Could not reach the server. Please try again.', 'error');
        })
        .finally(function() {
            saveBtn.disabled    = false;
            saveBtn.textContent = 'Save';
        });

    } else {
        // ── Update existing outfit ────────────────────────────
        payload.append('outfit_id', _currentOutfitId);

        fetch('api.php?action=outfit_update', {
            method: 'POST',
            body: csrfFd(payload)
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.status === 'ok') {
                // Keep OUTFIT_DATA in sync so re-opening the modal before reload shows the new values
                if (OUTFIT_DATA[_currentOutfitId]) {
                    OUTFIT_DATA[_currentOutfitId].folder_path = folderPath;
                    OUTFIT_DATA[_currentOutfitId].outfit_name = document.getElementById('prop-title').value.trim();
                }
                showToast('Outfit saved.', 'success');
                closePropsModal();
                setTimeout(function() { window.location.reload(); }, 800);
            } else {
                showToast('Error: ' + (data.error || 'unknown error'), 'error');
            }
        })
        .catch(function() {
            showToast('Could not reach the server. Please try again.', 'error');
        })
        .finally(function() {
            saveBtn.disabled    = false;
            saveBtn.textContent = 'Save';
        });
    }
}

// Wear from properties modal — uses modal's wear mode selection
function wearFromProps() {
    if (!_currentOutfitId) return;

    var wearMode = buildWearMode();

    var btn = document.getElementById('props-wear-btn');
    btn.disabled = true;
    btn.textContent = 'Sending…';

    var formData = new FormData();
    formData.append('outfit_id', _currentOutfitId);
    formData.append('wear_mode', wearMode);

    fetch('api.php?action=wear', {
        method: 'POST',
        body: csrfFd(formData)
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'ok') {
            showToast('Wear command sent.', 'success');
        } else if (data.error === 'hud_offline') {
            showToast('HUD is offline — wear command not delivered.', 'error');
        } else {
            showToast('Error: ' + (data.error || 'unknown error'), 'error');
        }
    })
    .catch(function() {
        showToast('Could not reach the server. Please try again.', 'error');
    })
    .finally(function() {
        setTimeout(function() {
            btn.disabled = false;
            btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.38 3.46L16 2a4 4 0 01-8 0L3.62 3.46a2 2 0 00-1.34 2.23l.58 3.57a1 1 0 00.99.84H6v10c0 1.1.9 2 2 2h8a2 2 0 002-2V10h2.15a1 1 0 00.99-.84l.58-3.57a2 2 0 00-1.34-2.23z"/></svg> Wear';
        }, 2000);
    });
}

// Remove from properties modal — uses modal's wear mode to pick @detach vs @detachall
function removeFromProps() {
    if (!_currentOutfitId) return;

    var wearMode = buildWearMode();

    var btn = document.getElementById('props-remove-btn');
    btn.disabled = true;
    btn.textContent = 'Sending…';

    var formData = new FormData();
    formData.append('outfit_id', _currentOutfitId);
    formData.append('wear_mode', wearMode);

    fetch('api.php?action=remove', {
        method: 'POST',
        body: csrfFd(formData)
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'ok') {
            showToast('Remove command sent.', 'success');
        } else if (data.error === 'hud_offline') {
            showToast('HUD is offline — remove command not delivered.', 'error');
        } else {
            showToast('Error: ' + (data.error || 'unknown error'), 'error');
        }
    })
    .catch(function() {
        showToast('Could not reach the server. Please try again.', 'error');
    })
    .finally(function() {
        setTimeout(function() {
            btn.disabled = false;
            btn.textContent = 'Remove';
        }, 2000);
    });
}


// Image upload — triggers file picker
function browseOutfitImage() {
    if (!_currentOutfitId) return;
    document.getElementById('prop-image-file').click();
}

// Called when file is selected — uploads immediately, updates preview on success
function uploadOutfitImage(input) {
    if (!input.files || !input.files[0]) return;

    var file   = input.files[0];
    var status = document.getElementById('prop-image-status');

    // Client-side size check (server also validates)
    if (file.size > 2 * 1024 * 1024) {
        setImageStatus('File must be under 2 MB.', 'error');
        input.value = '';
        return;
    }

    setImageStatus('Uploading…', 'uploading');

    var formData = new FormData();
    formData.append('outfit_id', _currentOutfitId);
    formData.append('image',     file);

    fetch('api.php?action=outfit_image_upload', {
        method: 'POST',
        body: csrfFd(formData)
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'ok') {
            // Update preview using the new passthrough URL
            document.getElementById('prop-image-preview').src =
                'image.php?file=' + encodeURIComponent(data.filename) + '&t=' + Date.now();
            setImageStatus('Image saved.', 'ok');
            // Also update the card image in the background grid
            var cardImg = document.querySelector(
                '.btn-delete[data-outfit-id="' + _currentOutfitId + '"]'
            );
            if (cardImg) {
                var card = cardImg.closest('.outfit-card');
                if (card) {
                    var img = card.querySelector('.outfit-image');
                    if (img) img.src = 'image.php?file=' + encodeURIComponent(data.filename) + '&t=' + Date.now();
                }
            }
        } else {
            setImageStatus(data.error || 'Upload failed.', 'error');
        }
    })
    .catch(function() {
        setImageStatus('Could not reach the server.', 'error');
    })
    .finally(function() {
        input.value = ''; // reset so same file can be re-selected
    });
}

function setImageStatus(msg, type) {
    var el = document.getElementById('prop-image-status');
    el.textContent = msg;
    el.className = 'image-upload-status image-upload-status--' + type;
    if (type === 'ok') {
        setTimeout(function() { el.textContent = ''; el.className = 'image-upload-status'; }, 3000);
    }
}

// ── Outfit locking ───────────────────────────────────────────
function updateLockBar(isLocked) {
    var icon     = document.getElementById('props-lock-status-icon');
    var text     = document.getElementById('props-lock-status-text');
    var lockBtn  = document.getElementById('props-lock-btn');
    var forceBtn = document.getElementById('props-force-unlock-btn');
    var bar      = document.getElementById('props-lock-bar');

    if (isLocked) {
        icon.textContent    = '🔒';
        text.textContent    = 'This outfit is locked. Wear and Remove are disabled.';
        lockBtn.textContent = 'Unlock outfit';
        lockBtn.classList.add('btn-lock--active');
        forceBtn.style.display = '';
        bar.classList.add('props-lock-bar--locked');
    } else {
        icon.textContent    = '🔓';
        text.textContent    = 'This outfit is not locked.';
        lockBtn.textContent = 'Lock outfit';
        lockBtn.classList.remove('btn-lock--active');
        forceBtn.style.display = 'none';
        bar.classList.remove('props-lock-bar--locked');
    }
}

function toggleOutfitLock() {
    if (!_currentOutfitId) return;
    var outfit  = OUTFIT_DATA[_currentOutfitId];
    var newLock = outfit.locked ? 0 : 1;

    var btn = document.getElementById('props-lock-btn');
    btn.disabled = true;
    btn.textContent = newLock ? 'Locking…' : 'Unlocking…';

    var formData = new FormData();
    formData.append('outfit_id', _currentOutfitId);
    formData.append('lock', newLock);

    fetch('api.php?action=outfit_lock', { method: 'POST', body: csrfFd(formData) })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'ok') {
            outfit.locked = !!newLock;
            updateLockBar(outfit.locked);
            // Update the card in the background grid
            var card = document.querySelector('.outfit-card [data-outfit-id="' + _currentOutfitId + '"]');
            if (card) {
                var outfitCard = card.closest('.outfit-card');
                if (outfitCard) {
                    outfitCard.classList.toggle('outfit-card--locked', outfit.locked);
                    var badge = outfitCard.querySelector('.outfit-lock-badge');
                    if (outfit.locked && !badge) {
                        var wrap = outfitCard.querySelector('.outfit-image-wrap');
                        var newBadge = document.createElement('span');
                        newBadge.className = 'outfit-lock-badge';
                        newBadge.title = 'Outfit is locked';
                        newBadge.textContent = '🔒';
                        wrap.appendChild(newBadge);
                    } else if (!outfit.locked && badge) {
                        badge.remove();
                    }
                    // Update Wear button state
                    var wearBtn = outfitCard.querySelector('.btn-wear');
                    var remBtn  = outfitCard.querySelector('.btn-remove');
                    if (wearBtn) {
                        wearBtn.classList.toggle('btn-wear--offline', outfit.locked);
                        wearBtn.title = outfit.locked ? 'Outfit is locked — unlock in properties to wear' : '';
                    }
                    if (remBtn) {
                        remBtn.classList.toggle('btn-remove--offline', outfit.locked);
                        remBtn.title = outfit.locked ? 'Outfit is locked — unlock in properties to remove' : '';
                    }
                }
            }
            var msg = outfit.locked ? 'Outfit locked.' : 'Outfit unlocked.';
            if (!data.hud_online) msg += ' HUD offline — RLV will sync on next heartbeat.';
            showToast(msg, 'success');
        } else {
            showToast('Error: ' + (data.error || 'unknown'), 'error');
        }
    })
    .catch(function() { showToast('Could not reach the server.', 'error'); })
    .finally(function() { btn.disabled = false; });
}

function forceUnlockOutfit() {
    if (!_currentOutfitId) return;
    if (!confirm('Force unlock this outfit? This clears the lock in the database and attempts to release the RLV restriction in-world.')) return;

    var btn = document.getElementById('props-force-unlock-btn');
    btn.disabled = true;
    btn.textContent = 'Unlocking…';

    var formData = new FormData();
    formData.append('outfit_id', _currentOutfitId);

    fetch('api.php?action=outfit_force_unlock', { method: 'POST', body: csrfFd(formData) })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'ok') {
            var outfit = OUTFIT_DATA[_currentOutfitId];
            if (outfit) outfit.locked = false;
            updateLockBar(false);
            var msg = 'Force unlock complete.';
            if (!data.hud_online) msg += ' HUD was offline — restriction will clear on next relog.';
            showToast(msg, 'success');
        } else {
            showToast('Error: ' + (data.error || 'unknown'), 'error');
        }
    })
    .catch(function() { showToast('Could not reach the server.', 'error'); })
    .finally(function() {
        btn.disabled = false;
        btn.textContent = 'Force unlock';
    });
}

// ── Lightbox ─────────────────────────────────────────────────
function openLightbox(src, alt) {
    var lb = document.getElementById('lightbox');
    document.getElementById('lightbox-img').src = src;
    document.getElementById('lightbox-img').alt = alt || '';
    lb.hidden = false;
}

function closeLightbox() {
    document.getElementById('lightbox').hidden = true;
    document.getElementById('lightbox-img').src = '';
}

// Close lightbox on Escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && !document.getElementById('lightbox').hidden) {
        closeLightbox();
    }
});

// Close props modal on backdrop click
document.getElementById('props-modal').addEventListener('click', function(e) {
    if (e.target === this) closePropsModal();
});

// ── Toast notification ────────────────────────────────────────
function showToast(message, type) {
    var toast = document.getElementById('wear-toast');
    toast.textContent = message;
    toast.className   = 'wear-toast wear-toast--' + type + ' wear-toast--visible';
    clearTimeout(toast._timer);
    toast._timer = setTimeout(function() {
        toast.classList.remove('wear-toast--visible');
    }, 4000);
}

// ══════════════════════════════════════════════════════════════
// ACCOUNT MODAL
// ══════════════════════════════════════════════════════════════

function openAccountModal() {
    document.getElementById('account-modal').hidden = false;
    document.body.style.overflow = 'hidden';
    // Fetch a fresh snapshot so hud_locked (and last_seen) reflect
    // the most recent checkin, not the stale PHP page-load value.
    refreshAccountStatus();
}

function closeAccountModal() {
    document.getElementById('account-modal').hidden = true;
    document.body.style.overflow = '';
}

// Fetch a live snapshot of account status from the server and
// update the HUD Status row (and Last Seen) without a page reload.
function refreshAccountStatus() {
    fetch('api.php?action=get_account_status', { method: 'POST', body: csrfFd(new FormData()) })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status !== 'ok') return;

        // HUD status
        var hudRow = document.getElementById('acct-hud-status-dd');
        if (hudRow) {
            var locked = data.hud_locked;
            hudRow.textContent = locked ? '\uD83D\uDD12 Locked' : '\uD83D\uDD13 Unlocked';
            hudRow.className   = locked ? 'acct-hud-locked' : 'acct-hud-unlocked';
        }

        // Last seen (convert Unix timestamp to "X min ago" style)
        var lastSeenRow = document.getElementById('acct-last-seen-dd');
        if (lastSeenRow && data.last_seen) {
            lastSeenRow.textContent = timeAgo(data.last_seen);
        }
    })
    .catch(function() { /* silent — stale page-load value remains */ });
}

// Mirror of PHP ensemble_time_ago() for client-side use
function timeAgo(ts) {
    var age = Math.floor(Date.now() / 1000) - ts;
    if (age < 60)    return 'Just now';
    if (age < 3600)  return Math.floor(age / 60) + ' min ago';
    if (age < 86400) return Math.floor(age / 3600) + ' hr ago';
    var d = new Date(ts * 1000);
    return d.getDate() + ' ' + ['Jan','Feb','Mar','Apr','May','Jun',
           'Jul','Aug','Sep','Oct','Nov','Dec'][d.getMonth()] + ' ' +
           d.getFullYear() + ', ' + String(d.getHours()).padStart(2,'0') +
           ':' + String(d.getMinutes()).padStart(2,'0');
}

// Close on backdrop click
document.getElementById('account-modal').addEventListener('click', function(e) {
    if (e.target === this) closeAccountModal();
});

// ── Worn items ────────────────────────────────────────────────
function loadWornItems() {
    var area = document.getElementById('worn-items-area');
    var btn  = document.getElementById('refresh-worn-btn');

    area.innerHTML = '<p class="acct-worn-hint acct-worn-hint--loading">'
                   + '<span class="acct-spinner"></span> Asking your HUD…</p>';
    btn.disabled = true;

    var formData = new FormData();
    fetch('api.php?action=get_worn', { method: 'POST', body: csrfFd(formData) })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.error === 'hud_offline') {
            area.innerHTML = '<p class="acct-worn-offline">HUD is offline or hasn\'t checked in recently. '
                           + 'Make sure your HUD is worn and connected.</p>';
            return;
        }
        if (data.error || !data.items) {
            area.innerHTML = '<p class="acct-worn-offline">Could not retrieve worn items. Please try again.</p>';
            return;
        }
        if (data.items.length === 0) {
            area.innerHTML = '<p class="acct-worn-hint">No items currently attached.</p>';
            return;
        }
        renderWornItems(data.items);
    })
    .catch(function() {
        area.innerHTML = '<p class="acct-worn-offline">Could not reach the server. Please try again.</p>';
    })
    .finally(function() {
        btn.disabled = false;
    });
}

function renderWornItems(items) {
    // Group by HUD vs world attachments for clarity
    var hudItems   = items.filter(function(i) { return i.point.indexOf('hud') === 0; });
    var worldItems = items.filter(function(i) { return i.point.indexOf('hud') !== 0; });

    var html = '<table class="worn-table">'
             + '<thead><tr><th>Item</th><th>Point</th><th></th></tr></thead>'
             + '<tbody>';

    function renderRow(item) {
        var canDetach = item.can_detach;
        // Use data attributes instead of inline JS arguments to avoid
        // quoting issues with item names or point names containing
        // apostrophes, quotes, or other special characters.
        var removeBtn = canDetach
            ? '<button class="btn-worn-remove"'
              + ' data-point="' + escAttr(item.point) + '"'
              + ' data-item="'  + escAttr(item.item)  + '"'
              + ' onclick="detachWornItem(this)"'
              + ' title="Remove this item">Remove</button>'
            : '<span class="worn-no-remove" title="Body-layer wearables cannot be removed via the web panel">—</span>';
        html += '<tr>'
              + '<td class="worn-item-name">' + escHtml(item.item) + '</td>'
              + '<td class="worn-point">' + escHtml(item.point) + '</td>'
              + '<td class="worn-action">' + removeBtn + '</td>'
              + '</tr>';
    }

    if (worldItems.length > 0) {
        html += '<tr class="worn-group-header"><td colspan="3">Attachments</td></tr>';
        worldItems.forEach(renderRow);
    }
    if (hudItems.length > 0) {
        html += '<tr class="worn-group-header"><td colspan="3">HUD Attachments</td></tr>';
        hudItems.forEach(renderRow);
    }

    html += '</tbody></table>';
    document.getElementById('worn-items-area').innerHTML = html;
}

function detachWornItem(btn) {
    var point = btn.getAttribute('data-point');
    var item  = btn.getAttribute('data-item');

    btn.disabled = true;
    btn.textContent = '…';

    var formData = new FormData();
    formData.append('point', point);
    formData.append('item',  item);

    fetch('api.php?action=worn_detach', { method: 'POST', body: csrfFd(formData) })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'ok') {
            // Remove the row from the table
            var row = btn.closest('tr');
            if (row) row.remove();
            showToast('Removed: ' + item, 'success');
        } else if (data.error === 'hud_offline') {
            showToast('HUD is offline — item not removed.', 'error');
            btn.disabled = false;
            btn.textContent = 'Remove';
        } else {
            showToast('Error removing item.', 'error');
            btn.disabled = false;
            btn.textContent = 'Remove';
        }
    })
    .catch(function() {
        showToast('Could not reach the server.', 'error');
        btn.disabled = false;
        btn.textContent = 'Remove';
    });
}

// ══════════════════════════════════════════════════════════════
// ATTACHMENT POINT DATA
// All 55 points from the LSL wiki, grouped for display.
// ══════════════════════════════════════════════════════════════

var ATTACH_GROUPS = [
    {
        label: 'Body',
        points: [
            {id:2,  name:'Skull'},
            {id:17, name:'Nose'},
            {id:11, name:'Mouth'},
            {id:52, name:'Tongue'},
            {id:12, name:'Chin'},
            {id:47, name:'Jaw'},
            {id:13, name:'Left Ear'},
            {id:14, name:'Right Ear'},
            {id:48, name:'Alt Left Ear'},
            {id:49, name:'Alt Right Ear'},
            {id:15, name:'Left Eye'},
            {id:16, name:'Right Eye'},
            {id:50, name:'Alt Left Eye'},
            {id:51, name:'Alt Right Eye'},
            {id:39, name:'Neck'},
            {id:1,  name:'Chest'},
            {id:29, name:'Left Pec'},
            {id:30, name:'Right Pec'},
            {id:28, name:'Stomach'},
            {id:9,  name:'Spine'},
            {id:40, name:'Avatar Center'},
            {id:10, name:'Pelvis'},
            {id:53, name:'Groin'},
            {id:43, name:'Tail Base'},
            {id:44, name:'Tail Tip'},
            {id:45, name:'Left Wing'},
            {id:46, name:'Right Wing'},
            {id:54, name:'Left Hind Foot'},
            {id:55, name:'Right Hind Foot'}
        ]
    },
    {
        label: 'Clothing & Accessories',
        points: [
            {id:3,  name:'Left Shoulder'},
            {id:4,  name:'Right Shoulder'},
            {id:20, name:'L Upper Arm'},
            {id:18, name:'R Upper Arm'},
            {id:21, name:'L Lower Arm'},
            {id:19, name:'R Lower Arm'},
            {id:5,  name:'Left Hand'},
            {id:6,  name:'Right Hand'},
            {id:41, name:'Left Ring Finger'},
            {id:42, name:'Right Ring Finger'},
            {id:25, name:'Left Hip'},
            {id:22, name:'Right Hip'},
            {id:26, name:'L Upper Leg'},
            {id:23, name:'R Upper Leg'},
            {id:24, name:'R Lower Leg'},
            {id:27, name:'L Lower Leg'},
            {id:7,  name:'Left Foot'},
            {id:8,  name:'Right Foot'}
        ]
    },
    {
        label: 'HUDs',
        points: [
            {id:31, name:'HUD Center 2'},
            {id:32, name:'HUD Top Right'},
            {id:33, name:'HUD Top'},
            {id:34, name:'HUD Top Left'},
            {id:35, name:'HUD Center'},
            {id:36, name:'HUD Bottom Left'},
            {id:37, name:'HUD Bottom'},
            {id:38, name:'HUD Bottom Right'}
        ]
    }
];

// Build the checklist HTML into a container element.
// checkedIds: array of point integers that should be checked.
// openGroupIndex: which group starts expanded (0=Body, 1=Clothing, 2=HUDs).
// Pass -1 (or omit) to start all groups collapsed.
function renderRemovalChecklist(container, checkedIds, openGroupIndex) {
    if (openGroupIndex === undefined) openGroupIndex = -1;
    var checkedSet = {};
    if (checkedIds) checkedIds.forEach(function(id) { checkedSet[id] = true; });

    var html = '<div class="rp-groups">';
    ATTACH_GROUPS.forEach(function(group, gi) {
        var isOpen = (gi === openGroupIndex);
        html += '<div class="rp-group' + (isOpen ? ' rp-group--open' : '') + '">';
        html += '<button type="button" class="rp-group-header" onclick="toggleRpGroup(this)">'
              + '<span class="rp-group-label">' + group.label + '</span>'
              + '<span class="rp-group-count"></span>'
              + '<svg class="rp-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><polyline points="9 18 15 12 9 6"/></svg>'
              + '</button>';
        html += '<div class="rp-group-body">';
        html += '<div class="rp-check-all-row">'
              + '<label class="rp-check-all-label"><input type="checkbox" class="rp-select-all" data-group="' + gi + '" onchange="rpSelectAll(this)"> Select all</label>'
              + '</div>';
        html += '<div class="rp-points">';
        group.points.forEach(function(pt) {
            var chk = checkedSet[pt.id] ? ' checked' : '';
            html += '<label class="rp-point">'
                  + '<input type="checkbox" class="rp-pt-cb" data-group="' + gi + '" value="' + pt.id + '"' + chk + ' onchange="updateRpGroupCount(this)">'
                  + '<span>' + pt.name + '</span>'
                  + '</label>';
        });
        html += '</div></div></div>';
    });
    html += '</div>';
    container.innerHTML = html;
    // Initialise counts
    container.querySelectorAll('.rp-group').forEach(function(g) {
        updateRpGroupCountForGroup(g);
    });
}

function toggleRpGroup(btn) {
    var group = btn.closest('.rp-group');
    var isOpen = group.classList.contains('rp-group--open');
    // Close all siblings
    btn.closest('.rp-groups').querySelectorAll('.rp-group').forEach(function(g) {
        g.classList.remove('rp-group--open');
    });
    if (!isOpen) group.classList.add('rp-group--open');
}

function rpSelectAll(cb) {
    var gi = cb.getAttribute('data-group');
    var group = cb.closest('.rp-group');
    group.querySelectorAll('.rp-pt-cb').forEach(function(c) { c.checked = cb.checked; });
    updateRpGroupCountForGroup(group);
}

function updateRpGroupCount(cb) {
    updateRpGroupCountForGroup(cb.closest('.rp-group'));
}

function updateRpGroupCountForGroup(group) {
    var all  = group.querySelectorAll('.rp-pt-cb').length;
    var chkd = group.querySelectorAll('.rp-pt-cb:checked').length;
    var countEl = group.querySelector('.rp-group-count');
    if (countEl) countEl.textContent = chkd + ' / ' + all;
    var selAll = group.querySelector('.rp-select-all');
    if (selAll) selAll.checked = (chkd === all);
}

// Read checked point IDs from a rendered checklist container
function getChecklistPoints(container) {
    var pts = [];
    container.querySelectorAll('.rp-pt-cb:checked').forEach(function(cb) {
        pts.push(parseInt(cb.value, 10));
    });
    return pts;
}

// ══════════════════════════════════════════════════════════════
// OUTFIT PICKER — Base Outfits & Additional Items
// ══════════════════════════════════════════════════════════════
// Each picker is identified by a string key ('base-outfits' or
// 'additional-items'). State is held in _opState keyed by that
// string: an ordered array of outfit IDs.
//
// Storage format sent to the server: JSON array of integer IDs,
// e.g. "[12,7,3]". Empty = "[]". Old empty-string values from
// before this feature are treated as [].
// ══════════════════════════════════════════════════════════════

var _opState = {
    'base-outfits':     [],   // ordered array of outfit IDs
    'additional-items': [],
    'wear-after-remove': []
};

// Drag-and-drop tracking
var _opDragSrc  = null;   // chip element being dragged
var _opDragKey  = null;   // which picker it belongs to

// ── Load ─────────────────────────────────────────────────────
// Called when opening the props modal. raw is the stored JSON
// string (or empty string for no selection).
function opLoad(key, raw) {
    var ids = [];
    if (raw && raw !== '') {
        try { ids = JSON.parse(raw); } catch(e) { ids = []; }
    }
    _opState[key] = Array.isArray(ids) ? ids.map(Number) : [];
    opRender(key);
}

// ── Serialise ────────────────────────────────────────────────
// Returns the JSON string ready to POST.
function opSerialise(key) {
    return JSON.stringify(_opState[key] || []);
}

// ── Render chips ─────────────────────────────────────────────
function opRender(key) {
    var chipsEl = document.getElementById('picker-' + key + '__chips');
    var ids     = _opState[key];

    // Clear
    chipsEl.innerHTML = '';

    if (ids.length === 0) {
        var ph = document.createElement('span');
        ph.className = 'outfit-picker__placeholder';
        ph.textContent = (key === 'base-outfits')
            ? 'No base outfits selected…'
            : (key === 'additional-items')
                ? 'No additional items selected…'
                : 'No outfits selected…';
        chipsEl.appendChild(ph);
        return;
    }

    ids.forEach(function(id, idx) {
        var outfit = OUTFIT_DATA[id];
        var name   = outfit ? outfit.outfit_name : ('Outfit #' + id);

        var chip = document.createElement('div');
        chip.className   = 'outfit-picker__chip';
        chip.draggable   = true;
        chip.dataset.id  = id;
        chip.dataset.key = key;
        chip.dataset.idx = idx;

        // Drag handle
        var handle = document.createElement('span');
        handle.className = 'outfit-picker__drag-handle';
        handle.innerHTML = '&#8597;';   // ↕
        handle.title     = 'Drag to reorder';
        chip.appendChild(handle);

        // Name
        var label = document.createElement('span');
        label.className   = 'outfit-picker__chip-name';
        label.textContent = name;
        chip.appendChild(label);

        // Up button
        if (idx > 0) {
            var upBtn = document.createElement('button');
            upBtn.type      = 'button';
            upBtn.className = 'outfit-picker__arrow';
            upBtn.title     = 'Move up';
            upBtn.innerHTML = '&#8593;';
            upBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                opMove(key, idx, idx - 1);
            });
            chip.appendChild(upBtn);
        }

        // Down button
        if (idx < ids.length - 1) {
            var dnBtn = document.createElement('button');
            dnBtn.type      = 'button';
            dnBtn.className = 'outfit-picker__arrow';
            dnBtn.title     = 'Move down';
            dnBtn.innerHTML = '&#8595;';
            dnBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                opMove(key, idx, idx + 1);
            });
            chip.appendChild(dnBtn);
        }

        // Remove ×
        var xBtn = document.createElement('button');
        xBtn.type      = 'button';
        xBtn.className = 'outfit-picker__remove';
        xBtn.title     = 'Remove';
        xBtn.innerHTML = '&times;';
        xBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            opRemove(key, id);
        });
        chip.appendChild(xBtn);

        // Drag events
        chip.addEventListener('dragstart', function(e) {
            _opDragSrc  = chip;
            _opDragKey  = key;
            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('text/plain', String(id));
            setTimeout(function() { chip.classList.add('outfit-picker__chip--dragging'); }, 0);
        });
        chip.addEventListener('dragend', function() {
            chip.classList.remove('outfit-picker__chip--dragging');
            // Remove any lingering drag-over highlights
            chipsEl.querySelectorAll('.outfit-picker__chip--over')
                   .forEach(function(c) { c.classList.remove('outfit-picker__chip--over'); });
            _opDragSrc = null;
            _opDragKey = null;
        });
        chip.addEventListener('dragover', function(e) {
            if (_opDragKey !== key) return;
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            chip.classList.add('outfit-picker__chip--over');
        });
        chip.addEventListener('dragleave', function() {
            chip.classList.remove('outfit-picker__chip--over');
        });
        chip.addEventListener('drop', function(e) {
            if (_opDragKey !== key || _opDragSrc === chip) return;
            e.preventDefault();
            chip.classList.remove('outfit-picker__chip--over');
            var srcIdx  = parseInt(_opDragSrc.dataset.idx, 10);
            var tgtIdx  = parseInt(chip.dataset.idx, 10);
            opMove(key, srcIdx, tgtIdx);
        });

        chipsEl.appendChild(chip);
    });
}

// ── Move item ────────────────────────────────────────────────
function opMove(key, fromIdx, toIdx) {
    var arr = _opState[key];
    if (toIdx < 0 || toIdx >= arr.length) return;
    var item = arr.splice(fromIdx, 1)[0];
    arr.splice(toIdx, 0, item);
    opRender(key);
}

// ── Remove item ──────────────────────────────────────────────
function opRemove(key, id) {
    _opState[key] = _opState[key].filter(function(i) { return i !== id; });
    opRender(key);
    // Re-populate dropdown list in case it's open
    var dd = document.getElementById('picker-' + key + '__dropdown');
    if (dd && dd.style.display !== 'none') {
        opPopulateList(key, document.querySelector('#picker-' + key + '__dropdown .outfit-picker__search').value);
    }
}

// ── Toggle dropdown ──────────────────────────────────────────
function opToggle(key) {
    var dd = document.getElementById('picker-' + key + '__dropdown');
    var isOpen = dd.style.display !== 'none';
    // Close all first
    opCloseAll();
    if (isOpen) return;
    // Open this one
    dd.style.display = '';
    opPopulateList(key, '');
    var searchInput = dd.querySelector('.outfit-picker__search');
    if (searchInput) { searchInput.value = ''; searchInput.focus(); }
}

// ── Close all dropdowns ──────────────────────────────────────
function opCloseAll() {
    ['base-outfits', 'additional-items', 'wear-after-remove'].forEach(function(k) {
        var dd = document.getElementById('picker-' + k + '__dropdown');
        if (dd) dd.style.display = 'none';
    });
}

// ── Populate dropdown list ───────────────────────────────────
// Shows all outfits not already selected and not the current outfit,
// filtered by query string.
function opPopulateList(key, query) {
    var listEl   = document.getElementById('picker-' + key + '__list');
    var selected = _opState[key];
    var q        = (query || '').toLowerCase().trim();

    // Build sorted list of available outfits
    var available = Object.values(OUTFIT_DATA).filter(function(o) {
        if (o.id === _currentOutfitId) return false;   // can't select self
        if (selected.indexOf(o.id) !== -1) return false; // already picked
        if (q && o.outfit_name.toLowerCase().indexOf(q) === -1) return false;
        return true;
    }).sort(function(a, b) {
        return a.outfit_name.localeCompare(b.outfit_name);
    });

    listEl.innerHTML = '';

    if (available.length === 0) {
        var empty = document.createElement('li');
        empty.className   = 'outfit-picker__list-empty';
        empty.textContent = q ? 'No matches.' : 'No other outfits available.';
        listEl.appendChild(empty);
        return;
    }

    available.forEach(function(o) {
        var li = document.createElement('li');
        li.className = 'outfit-picker__list-item';
        li.textContent = o.outfit_name;
        li.addEventListener('click', function() {
            opAdd(key, o.id);
        });
        listEl.appendChild(li);
    });
}

// ── Filter dropdown ──────────────────────────────────────────
function opFilter(key, query) {
    opPopulateList(key, query);
}

// ── Add item ─────────────────────────────────────────────────
function opAdd(key, id) {
    if (_opState[key].indexOf(id) === -1) {
        _opState[key].push(id);
    }
    opRender(key);
    // Refresh list (removes the just-added item from dropdown)
    var searchInput = document.querySelector('#picker-' + key + '__dropdown .outfit-picker__search');
    opPopulateList(key, searchInput ? searchInput.value : '');
}

// ── Close dropdown on outside click ──────────────────────────
document.addEventListener('click', function(e) {
    ['base-outfits', 'additional-items', 'wear-after-remove'].forEach(function(key) {
        var picker = document.getElementById('picker-' + key);
        var dd     = document.getElementById('picker-' + key + '__dropdown');
        if (!picker || !dd) return;
        if (dd.style.display === 'none') return;
        if (!picker.contains(e.target)) {
            dd.style.display = 'none';
        }
    });
});

// ── Close on Escape ───────────────────────────────────────────
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') opCloseAll();
});

// ── Props modal — remove before wearing toggle ────────────────

document.getElementById('prop-remove-before-wear').addEventListener('change', function() {
    document.getElementById('prop-removal-scope').style.display = this.checked ? '' : 'none';
    if (!this.checked) return;
    // If switching to custom and no checklist yet, we'll populate on radio change
    var scope = 'default';
    document.querySelectorAll('input[name="prop_removal_scope"]').forEach(function(r) {
        if (r.checked) scope = r.value;
    });
    if (scope === 'custom') showPropsCustomPoints();
});

document.querySelectorAll('input[name="prop_removal_scope"]').forEach(function(r) {
    r.addEventListener('change', function() {
        var wrap = document.getElementById('prop-removal-points-wrap');
        if (this.value === 'custom') {
            showPropsCustomPoints();
        } else {
            wrap.style.display = 'none';
        }
    });
});

function showPropsCustomPoints() {
    var wrap = document.getElementById('prop-removal-points-wrap');
    wrap.style.display = '';
    // If checklist already rendered, leave it
    if (wrap.querySelector('.rp-groups')) return;
    // Seed from existing custom points or fetch defaults
    var existing = wrap._customPoints;
    if (existing) {
        renderRemovalChecklist(wrap, existing);
    } else {
        // Fetch user defaults as the starting point for a new custom list
        wrap.innerHTML = '<p class="acct-worn-hint"><span class="acct-spinner"></span> Loading defaults…</p>';
        fetch('api.php?action=get_removal_defaults', { method: 'POST', body: csrfFd(new FormData()) })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            renderRemovalChecklist(wrap, data.points || []);
        })
        .catch(function() {
            renderRemovalChecklist(wrap, []);
        });
    }
}

// ══════════════════════════════════════════════════════════════
// DEFAULT REMOVAL POINTS MODAL
// ══════════════════════════════════════════════════════════════

function openRemovalDefaultsModal() {
    var modal = document.getElementById('removal-modal');
    modal.hidden = false;
    document.body.style.overflow = 'hidden';
    // Load current defaults
    var wrap = document.getElementById('removal-checklist-wrap');
    wrap.innerHTML = '<p class="acct-worn-hint"><span class="acct-spinner"></span> Loading…</p>';
    fetch('api.php?action=get_removal_defaults', { method: 'POST', body: csrfFd(new FormData()) })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        renderRemovalChecklist(wrap, data.points || []);
    })
    .catch(function() {
        wrap.innerHTML = '<p class="acct-worn-offline">Could not load defaults. Please try again.</p>';
    });
}

function closeRemovalModal() {
    document.getElementById('removal-modal').hidden = true;
    document.body.style.overflow = '';
}

function saveRemovalDefaults() {
    var pts = getChecklistPoints(document.getElementById('removal-checklist-wrap'));
    var btn = document.getElementById('removal-save-btn');
    btn.disabled = true;
    btn.textContent = 'Saving…';

    var fd = new FormData();
    fd.append('points', JSON.stringify(pts));
    fetch('api.php?action=save_removal_defaults', { method: 'POST', body: csrfFd(fd) })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'ok') {
            showToast('Default removal points saved.', 'success');
            closeRemovalModal();
        } else {
            showToast('Error saving defaults.', 'error');
        }
    })
    .catch(function() {
        showToast('Could not reach the server.', 'error');
    })
    .finally(function() {
        btn.disabled = false;
        btn.textContent = 'Save defaults';
    });
}

// Close removal modal on backdrop click
document.getElementById('removal-modal').addEventListener('click', function(e) {
    if (e.target === this) closeRemovalModal();
});

function escHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// Escape for use inside an HTML attribute value (double-quote delimited)
function escAttr(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;');
}
</script>

<!-- ════════════════════════════════════════════════════════
     RLV MODAL  (Check RLV + Send RLV Command)
     ════════════════════════════════════════════════════════ -->
<div class="modal-backdrop" id="rlv-modal" hidden role="dialog" aria-modal="true" aria-labelledby="rlv-modal-title">
    <div class="modal-box modal-box--sm">
        <div class="modal-header">
            <h2 class="modal-title" id="rlv-modal-title">RLV</h2>
            <button class="modal-close" onclick="closeRLVModal()" aria-label="Close">×</button>
        </div>
        <div class="modal-body" id="rlv-modal-body">

            <!-- ── Check RLV panel ── -->
            <div id="rlv-check-panel">
                <p class="field-hint" style="margin-bottom:1rem">
                    Check whether your viewer currently has RLV (Restrained Love Viewer) enabled.
                    The HUD will probe your viewer and report back within a few seconds.
                </p>
                <div id="rlv-check-result" style="display:none;margin-bottom:1rem"></div>
                <button class="btn btn-primary" id="rlv-check-btn" onclick="doRLVCheck()">Check RLV Status</button>
            </div>

            <!-- ── Send RLV Command panel ── -->
            <div id="rlv-send-panel" style="display:none">
                <p class="field-hint" style="margin-bottom:1rem">
                    Send an RLV command directly to your viewer via the HUD.
                    Commands must begin with <code>@</code>, e.g. <code>@fly=n</code> or <code>@detach=y</code>.
                </p>
                <label class="field-label" for="rlv-cmd-input">RLV Command</label>
                <input type="text" id="rlv-cmd-input" class="field-input" placeholder="@fly=n"
                       autocomplete="off" spellcheck="false"
                       onkeydown="if(event.key==='Enter') doRLVSend()">
                <div id="rlv-send-result" style="display:none;margin-top:0.75rem"></div>
                <div style="margin-top:1rem;display:flex;gap:0.5rem">
                    <button class="btn btn-primary" id="rlv-send-btn" onclick="doRLVSend()">Send Command</button>
                </div>
            </div>

        </div>
        <!-- Tab switcher at the bottom of the header area -->
        <div class="modal-tabs" id="rlv-modal-tabs" style="padding:0 1.25rem 0.75rem;display:flex;gap:0.5rem">
            <button class="btn btn-ghost btn-sm" id="rlv-tab-check" onclick="switchRLVTab('check')" style="background:var(--color-primary);color:#fff;border-color:var(--color-primary)">Check RLV</button>
            <button class="btn btn-ghost btn-sm" id="rlv-tab-send" onclick="switchRLVTab('send')">Send Command</button>
        </div>
    </div>
</div>

<script>
// ── RLV Modal ────────────────────────────────────────────────

function openRLVModal(tab) {
    switchRLVTab(tab || 'check');
    // Reset state
    var checkResult = document.getElementById('rlv-check-result');
    checkResult.style.display = 'none';
    checkResult.innerHTML = '';
    var sendResult = document.getElementById('rlv-send-result');
    sendResult.style.display = 'none';
    sendResult.innerHTML = '';
    document.getElementById('rlv-cmd-input').value = '';
    document.getElementById('rlv-check-btn').disabled = false;
    document.getElementById('rlv-send-btn').disabled = false;
    document.getElementById('rlv-modal').hidden = false;
}

function closeRLVModal() {
    document.getElementById('rlv-modal').hidden = true;
}

function switchRLVTab(tab) {
    var checkPanel = document.getElementById('rlv-check-panel');
    var sendPanel  = document.getElementById('rlv-send-panel');
    var checkTab   = document.getElementById('rlv-tab-check');
    var sendTab    = document.getElementById('rlv-tab-send');
    var activeStyle   = 'background:var(--color-primary);color:#fff;border-color:var(--color-primary)';
    var inactiveStyle = '';
    if (tab === 'check') {
        checkPanel.style.display = '';
        sendPanel.style.display  = 'none';
        checkTab.style.cssText = activeStyle;
        sendTab.style.cssText  = inactiveStyle;
        document.getElementById('rlv-modal-title').textContent = 'Check RLV';
    } else {
        checkPanel.style.display = 'none';
        sendPanel.style.display  = '';
        checkTab.style.cssText = inactiveStyle;
        sendTab.style.cssText  = activeStyle;
        document.getElementById('rlv-modal-title').textContent = 'Send RLV Command';
    }
}

function doRLVCheck() {
    var btn    = document.getElementById('rlv-check-btn');
    var result = document.getElementById('rlv-check-result');
    btn.disabled = true;
    btn.textContent = 'Checking…';
    result.style.display = 'none';
    result.innerHTML = '';

    fetch('api.php?action=rlv_check', {
        method: 'POST',
        body: csrfFd(new FormData())
    })
    .then(function(r) { return r.json().then(function(d) { return {status: r.status, data: d}; }); })
    .then(function(r) {
        btn.disabled = false;
        btn.textContent = 'Check RLV Status';
        result.style.display = '';
        if (r.status === 200 && r.data.status === 'ok') {
            if (r.data.rlv) {
                result.innerHTML = '<span style="color:var(--color-success,#2e7d32)">✔ RLV is enabled</span>'
                    + (r.data.version ? '<br><span class="field-hint">' + escHtml(r.data.version) + '</span>' : '');
            } else {
                result.innerHTML = '<span style="color:var(--color-warn,#b45309)">✘ RLV is not enabled</span>'
                    + '<br><span class="field-hint">Your viewer does not appear to support RLV, or it is disabled.</span>';
            }
        } else if (r.status === 503) {
            result.innerHTML = '<span style="color:var(--color-error,#b91c1c)">HUD offline — cannot reach your viewer.</span>';
        } else {
            result.innerHTML = '<span style="color:var(--color-error,#b91c1c)">Check failed: ' + escHtml(r.data.error || 'unknown error') + '</span>';
        }
    })
    .catch(function() {
        btn.disabled = false;
        btn.textContent = 'Check RLV Status';
        result.style.display = '';
        result.innerHTML = '<span style="color:var(--color-error,#b91c1c)">Request failed. Please try again.</span>';
    });
}

function doRLVSend() {
    var btn    = document.getElementById('rlv-send-btn');
    var input  = document.getElementById('rlv-cmd-input');
    var result = document.getElementById('rlv-send-result');
    var cmd    = input.value.trim();

    if (!cmd) {
        result.style.display = '';
        result.innerHTML = '<span style="color:var(--color-error,#b91c1c)">Please enter an RLV command.</span>';
        input.focus();
        return;
    }
    if (cmd[0] !== '@') {
        result.style.display = '';
        result.innerHTML = '<span style="color:var(--color-error,#b91c1c)">Commands must begin with @.</span>';
        input.focus();
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Sending…';
    result.style.display = 'none';

    var rlvFd = new FormData();
    rlvFd.append('rlv_cmd', cmd);
    fetch('api.php?action=rlv_send', {
        method: 'POST',
        body: csrfFd(rlvFd)
    })
    .then(function(r) { return r.json().then(function(d) { return {status: r.status, data: d}; }); })
    .then(function(r) {
        btn.disabled = false;
        btn.textContent = 'Send Command';
        result.style.display = '';
        if (r.status === 200) {
            result.innerHTML = '<span style="color:var(--color-success,#2e7d32)">✔ Command sent: <code>' + escHtml(cmd) + '</code></span>';
        } else if (r.status === 503) {
            result.innerHTML = '<span style="color:var(--color-error,#b91c1c)">HUD offline — cannot reach your viewer.</span>';
        } else {
            result.innerHTML = '<span style="color:var(--color-error,#b91c1c)">' + escHtml(r.data.error || 'Send failed') + '</span>';
        }
    })
    .catch(function() {
        btn.disabled = false;
        btn.textContent = 'Send Command';
        result.style.display = '';
        result.innerHTML = '<span style="color:var(--color-error,#b91c1c)">Request failed. Please try again.</span>';
    });
}

// Close RLV modal on backdrop click
document.getElementById('rlv-modal').addEventListener('click', function(e) {
    if (e.target === this) closeRLVModal();
});
</script>

<!-- ════════════════════════════════════════════════════════
     MANAGE LINKS MODAL
     ════════════════════════════════════════════════════════ -->
<div class="modal-backdrop" id="links-modal" hidden role="dialog" aria-modal="true" aria-labelledby="links-modal-title">
    <div class="modal-box modal-box--md">
        <div class="modal-header">
            <h2 class="modal-title" id="links-modal-title">Manage Links</h2>
            <button class="modal-close-btn" onclick="closeLinksModal()" aria-label="Close">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="20" height="20">
                    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        </div>
        <div class="modal-body modal-body--scroll" id="links-modal-body" style="min-height:8rem">
            <!-- Content injected by JS -->
        </div>
    </div>
</div>

<!-- ── Create / Edit Link modal ───────────────────────────── -->
<div class="modal-backdrop" id="link-edit-modal" hidden role="dialog" aria-modal="true" aria-labelledby="link-edit-modal-title">
    <div class="modal-box modal-box--sm">
        <div class="modal-header">
            <h2 class="modal-title" id="link-edit-modal-title">Create Link</h2>
            <button class="modal-close-btn" onclick="closeLinkEditModal()" aria-label="Close">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="20" height="20">
                    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        </div>
        <div class="modal-body">
            <input type="hidden" id="link-edit-uuid" value="">

            <div class="field">
                <label class="field-label" for="link-edit-name">Label <span class="field-hint" style="display:inline">(optional)</span></label>
                <input type="text" id="link-edit-name" class="field-input" maxlength="80" placeholder="e.g. Bob's Link">
            </div>

            <div class="field">
                <label class="field-label">Scope</label>
                <label class="radio-label"><input type="radio" name="link_scope" value="public" checked> Public outfits only</label>
                <label class="radio-label"><input type="radio" name="link_scope" value="private"> All outfits (including private)</label>
            </div>

            <div class="field">
                <label class="field-label">Permissions</label>
                <label class="radio-label"><input type="radio" name="link_perm" value="view" checked> View only</label>
                <label class="radio-label"><input type="radio" name="link_perm" value="wear"> Wear / Remove</label>
            </div>
        </div>
        <div class="modal-footer modal-footer--right">
            <button class="btn btn-ghost" onclick="closeLinkEditModal()">Cancel</button>
            <button class="btn btn-primary" id="link-edit-save-btn" onclick="saveLinkEdit()">Create link</button>
        </div>
    </div>
</div>

<script>
// ══════════════════════════════════════════════════════════════
// MANAGE LINKS
// ══════════════════════════════════════════════════════════════

var LINKS_MAX = 20;
var linksCache = [];

function openLinksModal(mode) {
    // Close side menu
    document.getElementById('sideMenu').classList.remove('side-menu--open');
    document.getElementById('sideMenuOverlay').classList.remove('side-menu-overlay--visible');
    document.getElementById('hamburgerBtn').setAttribute('aria-expanded', 'false');
    document.body.style.overflow = 'hidden';

    if (mode === 'create') {
        // Go straight to create form — no need to show Manage Links behind it
        openLinkEditModal(null);
        return;
    }

    document.getElementById('links-modal').hidden = false;
    loadLinks(null);
}

function closeLinksModal() {
    document.getElementById('links-modal').hidden = true;
    document.body.style.overflow = '';
}

function loadLinks(callback) {
    var body = document.getElementById('links-modal-body');
    body.innerHTML = '<p class="acct-worn-hint"><span class="acct-spinner"></span> Loading…</p>';

    fetch('api.php?action=links_list', { method: 'POST', body: csrfFd(new FormData()) })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        linksCache = data.links || [];
        renderLinksTable(data.links || [], data.count || 0);
        if (callback) callback();
    })
    .catch(function() {
        body.innerHTML = '<p class="acct-worn-offline">Could not load links. Please try again.</p>';
    });
}

function renderLinksTable(links, count) {
    var body = document.getElementById('links-modal-body');
    var atLimit = (count >= LINKS_MAX);
    var baseUrl = window.location.href.replace(/\/[^\/]*$/, '') + '/view.php?id=';

    var html = '';

    // Header row with count and Create button
    html += '<div class="links-header-row">'
          + '<span class="links-count">' + count + ' / ' + LINKS_MAX + ' links</span>';

    if (!atLimit) {
        html += '<button class="btn btn-primary btn-sm" onclick="openLinkEditModal(null)">+ Create link</button>';
    } else {
        html += '<span class="links-limit-note">Limit reached (' + LINKS_MAX + ' max)</span>';
    }
    html += '</div>';

    if (links.length === 0) {
        html += '<p class="acct-worn-hint" style="margin-top:1rem">No links yet. Create one to let others view (and optionally wear) your outfits.</p>';
    } else {
        html += '<div class="links-table-wrap"><table class="links-table">'
              + '<thead><tr>'
              + '<th></th>'
              + '<th>Label</th>'
              + '<th>Scope</th>'
              + '<th>Permissions</th>'
              + '<th></th>'
              + '</tr></thead>'
              + '<tbody>';

        links.forEach(function(link) {
            var url   = baseUrl + escHtml(link.link_uuid);
            var label = link.link_name ? escHtml(link.link_name) : '<em class="links-no-label">—</em>';
            var scope = link.include_private ? 'All outfits' : 'Public only';
            var perm  = link.can_wear ? 'Wear / Remove' : 'View only';

            var linkJson = escAttr(JSON.stringify(link));
            var deleteLabel = escAttr(link.link_name || link.link_uuid.slice(0,8) + '…');
            html += '<tr>'
                  + '<td class="links-td-open"><a href="' + url + '" target="_blank" rel="noopener" class="btn btn-ghost btn-sm links-open-btn" title="' + escHtml(link.link_uuid) + '">Open link ↗</a></td>'
                  + '<td>' + label + '</td>'
                  + '<td>' + scope + '</td>'
                  + '<td>' + perm  + '</td>'
                  + '<td class="links-td-actions">'
                  + '<button class="btn btn-ghost btn-sm" data-link="' + linkJson + '" onclick="openLinkEditModal(JSON.parse(this.dataset.link))">Edit</button>'
                  + ' <button class="btn btn-delete-sm" data-uuid="' + escAttr(link.link_uuid) + '" data-label="' + deleteLabel + '" onclick="confirmDeleteLink(this.dataset.uuid, this.dataset.label)">Delete</button>'
                  + '</td>'
                  + '</tr>';
        });

        html += '</tbody></table></div>';
    }

    body.innerHTML = html;
}

// ── Create / Edit modal ──────────────────────────────────────

function openLinkEditModal(link) {
    var modal = document.getElementById('link-edit-modal');
    var title = document.getElementById('link-edit-modal-title');
    var saveBtn = document.getElementById('link-edit-save-btn');

    document.getElementById('link-edit-uuid').value = link ? link.link_uuid : '';
    document.getElementById('link-edit-name').value = link ? (link.link_name || '') : '';

    // Scope
    document.querySelector('input[name="link_scope"][value="public"]').checked   = !(link && link.include_private);
    document.querySelector('input[name="link_scope"][value="private"]').checked  = !!(link && link.include_private);

    // Permissions
    document.querySelector('input[name="link_perm"][value="view"]').checked = !(link && link.can_wear);
    document.querySelector('input[name="link_perm"][value="wear"]').checked  = !!(link && link.can_wear);

    title.textContent   = link ? 'Edit Link' : 'Create Link';
    saveBtn.textContent = link ? 'Save changes' : 'Create link';

    modal.hidden = false;
}

function closeLinkEditModal() {
    document.getElementById('link-edit-modal').hidden = true;
}

function saveLinkEdit() {
    var btn         = document.getElementById('link-edit-save-btn');
    var linkUUID    = document.getElementById('link-edit-uuid').value;
    var linkName    = document.getElementById('link-edit-name').value.trim();
    var inclPriv    = document.querySelector('input[name="link_scope"]:checked').value === 'private' ? 1 : 0;
    var canWear     = document.querySelector('input[name="link_perm"]:checked').value  === 'wear'    ? 1 : 0;
    var isEdit      = linkUUID !== '';

    btn.disabled = true;
    btn.textContent = isEdit ? 'Saving…' : 'Creating…';

    var fd = new FormData();
    fd.append('link_name',       linkName);
    fd.append('include_private', inclPriv);
    fd.append('can_wear',        canWear);
    if (isEdit) fd.append('link_uuid', linkUUID);

    var action = isEdit ? 'link_update' : 'link_create';

    fetch('api.php?action=' + action, { method: 'POST', body: csrfFd(fd) })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'ok') {
            closeLinkEditModal();
            if (!isEdit && data.link) {
                var newUrl = window.location.origin + window.location.pathname.replace(/[^/]*$/, '') + 'view.php?id=' + data.link.link_uuid;
                if (navigator.clipboard) {
                    navigator.clipboard.writeText(newUrl).then(function() {
                        showToast('Link created — URL copied to clipboard!', 'success');
                    }).catch(function() {
                        showToast('Link created.', 'success');
                    });
                } else {
                    showToast('Link created.', 'success');
                }
            } else {
                showToast('Link updated.', 'success');
            }
            if (!document.getElementById('links-modal').hidden) {
                loadLinks(null);
            }
        } else if (data.error === 'limit_reached') {
            showToast('You have reached the maximum of ' + LINKS_MAX + ' links.', 'error');
        } else {
            showToast('Error saving link.', 'error');
        }
    })
    .catch(function() { showToast('Could not reach the server.', 'error'); })
    .finally(function() {
        btn.disabled = false;
        btn.textContent = isEdit ? 'Save changes' : 'Create link';
    });
}

// ── Delete ───────────────────────────────────────────────────

function confirmDeleteLink(linkUUID, label) {
    if (!confirm('Delete link "' + label + '"?\n\nAnyone using this link will lose access immediately.')) return;
    var fd = new FormData();
    fd.append('link_uuid', linkUUID);
    fetch('api.php?action=link_delete', { method: 'POST', body: csrfFd(fd) })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'ok') {
            showToast('Link deleted.', 'success');
            loadLinks(null);
        } else {
            showToast('Could not delete link.', 'error');
        }
    })
    .catch(function() { showToast('Could not reach the server.', 'error'); });
}

// ── Close on backdrop click ──────────────────────────────────
document.getElementById('links-modal').addEventListener('click', function(e) {
    if (e.target === this) closeLinksModal();
});
document.getElementById('link-edit-modal').addEventListener('click', function(e) {
    if (e.target === this) closeLinkEditModal();
});
</script>
<?php endif; ?>

<!-- Password reveal toggle — used on login and force-change forms -->
<script>
function toggleReveal(fieldId, btn) {
    var input = document.getElementById(fieldId);
    if (!input) return;
    var showing = input.type === 'text';
    input.type  = showing ? 'password' : 'text';
    btn.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
    btn.innerHTML = showing
        ? <?= json_encode(EYE_ICON) ?>
        : <?= json_encode(EYE_OFF_ICON) ?>;
}
</script>
<!-- ── Theme Selection Modal ───────────────────────────────── -->
<div class="modal-backdrop" id="theme-modal" hidden role="dialog" aria-modal="true" aria-labelledby="theme-modal-title">
    <div class="modal-box modal-box--sm">
        <div class="modal-header">
            <h2 class="modal-title" id="theme-modal-title">Theme Selection</h2>
            <button class="modal-close-btn" onclick="closeThemeModal()" aria-label="Close">&times;</button>
        </div>
        <div class="modal-body">
            <p class="field-hint" style="margin-bottom:1rem;">
                Choose a display theme. Themes are loaded from the <code>themes/</code> folder —
                any subdirectory with a <code>style.css</code> file appears here automatically.
            </p>
            <div id="theme-list" class="theme-list">
                <!-- Populated by openThemeModal() -->
            </div>
        </div>
        <div class="modal-footer">
            <button class="btn btn-ghost" onclick="closeThemeModal()">Cancel</button>
            <button class="btn btn-primary" id="theme-save-btn" onclick="saveTheme()">Apply Theme</button>
        </div>
    </div>
</div>

<script>
var _themeSelected = ENSEMBLE_ACTIVE_THEME;

function openThemeModal() {
    // Close the side menu first (same pattern as menuStub)
    document.getElementById('sideMenu').classList.remove('side-menu--open');
    document.getElementById('sideMenuOverlay').classList.remove('side-menu-overlay--visible');
    document.getElementById('hamburgerBtn').setAttribute('aria-expanded', 'false');
    document.body.style.overflow = '';

    _themeSelected = ENSEMBLE_ACTIVE_THEME;

    // Build the theme list from the server-injected array
    var list = document.getElementById('theme-list');
    list.innerHTML = '';
    ENSEMBLE_AVAIL_THEMES.forEach(function(name) {
        var label = document.createElement('label');
        label.className = 'theme-option' + (name === _themeSelected ? ' theme-option--active' : '');
        label.setAttribute('data-theme', name);

        var radio = document.createElement('input');
        radio.type    = 'radio';
        radio.name    = 'theme_select';
        radio.value   = name;
        radio.checked = (name === _themeSelected);
        radio.addEventListener('change', function() {
            _themeSelected = name;
            list.querySelectorAll('.theme-option').forEach(function(el) {
                el.classList.toggle('theme-option--active', el.getAttribute('data-theme') === name);
            });
        });

        // Pretty-print the name: replace _ and - with spaces, title-case
        var pretty = name.replace(/[-_]/g, ' ').replace(/\b\w/g, function(c) { return c.toUpperCase(); });

        // Swatch — tries to load a preview image if it exists
        var swatch = document.createElement('div');
        swatch.className = 'theme-swatch';
        var img = document.createElement('img');
        img.src = 'themes/' + name + '/preview.png';
        img.alt = '';
        img.onerror = function() { this.style.display = 'none'; };
        swatch.appendChild(img);

        var info = document.createElement('div');
        info.className = 'theme-info';
        var nameEl = document.createElement('span');
        nameEl.className = 'theme-name';
        nameEl.textContent = pretty;
        info.appendChild(nameEl);

        label.appendChild(radio);
        label.appendChild(swatch);
        label.appendChild(info);
        list.appendChild(label);
    });

    document.getElementById('theme-modal').hidden = false;
}

function closeThemeModal() {
    document.getElementById('theme-modal').hidden = true;
}

async function saveTheme() {
    var btn = document.getElementById('theme-save-btn');
    btn.disabled = true;
    btn.textContent = 'Applying…';

    try {
        var fd = new FormData();
        fd.append('csrf_token', CSRF_TOKEN);
        fd.append('theme', _themeSelected);

        var resp = await fetch('api.php?action=save_theme', { method: 'POST', body: fd });
        var data = await resp.json();

        if (data.status === 'ok') {
            // Swap stylesheet without reloading the page
            var link = document.querySelector('link[rel="stylesheet"][href*="themes/"]');
            if (link) {
                link.href = 'themes/' + _themeSelected + '/style.css';
            }
            // Update the logo too
            var logo = document.querySelector('.logo-img');
            if (logo) {
                logo.src = 'themes/' + _themeSelected + '/ensemblelogo.png';
                // Dark theme uses screen blend; default uses multiply
                logo.style.mixBlendMode = (_themeSelected === 'dark') ? 'screen' : 'multiply';
            }
            // Keep JS vars in sync
            ENSEMBLE_ACTIVE_THEME = _themeSelected;
            showToast('Theme applied.');
            closeThemeModal();
        } else {
            showToast((data.error || 'Could not apply theme.'), true);
        }
    } catch (e) {
        showToast('Could not reach the server.', true);
    }

    btn.disabled = false;
    btn.textContent = 'Apply Theme';
}

document.getElementById('theme-modal').addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeThemeModal();
});
document.getElementById('theme-modal').addEventListener('click', function(e) {
    if (e.target === this) closeThemeModal();
});
</script>

<!-- ── Change Password Modal ──────────────────────────────── -->
<div class="modal-backdrop" id="change-pw-modal" hidden role="dialog" aria-modal="true" aria-labelledby="change-pw-modal-title">
    <div class="modal-box modal-box--sm">
        <div class="modal-header">
            <h2 class="modal-title" id="change-pw-modal-title">Change Password</h2>
            <button class="modal-close-btn" onclick="closeChangePasswordModal()" aria-label="Close">&times;</button>
        </div>
        <div class="modal-body">
            <div id="change-pw-error" class="alert alert-error" hidden></div>
            <div id="change-pw-success" class="alert alert-success" hidden>Password changed successfully.</div>

            <div class="field">
                <label class="field-label" for="change-pw-current">Current Password</label>
                <div class="pw-wrap">
                    <input type="password" id="change-pw-current" name="current_password" class="field-input" autocomplete="current-password">
                    <button type="button" class="pw-reveal" onclick="toggleReveal('change-pw-current', this)" aria-label="Show password">
                        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M2 10s3-6 8-6 8 6 8 6-3 6-8 6-8-6-8-6z"/><circle cx="10" cy="10" r="2.5"/></svg>
                    </button>
                </div>
            </div>

            <div class="field">
                <label class="field-label" for="change-pw-new">New Password</label>
                <div class="pw-wrap">
                    <input type="password" id="change-pw-new" name="new_password" class="field-input" autocomplete="new-password">
                    <button type="button" class="pw-reveal" onclick="toggleReveal('change-pw-new', this)" aria-label="Show password">
                        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M2 10s3-6 8-6 8 6 8 6-3 6-8 6-8-6-8-6z"/><circle cx="10" cy="10" r="2.5"/></svg>
                    </button>
                </div>
            </div>

            <div class="field">
                <label class="field-label" for="change-pw-confirm">Confirm New Password</label>
                <div class="pw-wrap">
                    <input type="password" id="change-pw-confirm" name="confirm_password" class="field-input" autocomplete="new-password">
                    <button type="button" class="pw-reveal" onclick="toggleReveal('change-pw-confirm', this)" aria-label="Show password">
                        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M2 10s3-6 8-6 8 6 8 6-3 6-8 6-8-6-8-6z"/><circle cx="10" cy="10" r="2.5"/></svg>
                    </button>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button class="btn btn-ghost" onclick="closeChangePasswordModal()">Cancel</button>
            <button class="btn btn-primary" id="change-pw-submit" onclick="submitChangePassword()">Change Password</button>
        </div>
    </div>
</div>

<script>
function openChangePasswordModal() {
    document.getElementById('change-pw-current').value = '';
    document.getElementById('change-pw-new').value = '';
    document.getElementById('change-pw-confirm').value = '';
    document.getElementById('change-pw-error').hidden = true;
    document.getElementById('change-pw-success').hidden = true;
    document.getElementById('change-pw-modal').hidden = false;
    document.getElementById('change-pw-current').focus();
}

function closeChangePasswordModal() {
    document.getElementById('change-pw-modal').hidden = true;
}

async function submitChangePassword() {
    var errEl     = document.getElementById('change-pw-error');
    var successEl = document.getElementById('change-pw-success');
    var submitBtn = document.getElementById('change-pw-submit');

    errEl.hidden     = true;
    successEl.hidden = true;

    var current = document.getElementById('change-pw-current').value;
    var newPw   = document.getElementById('change-pw-new').value;
    var confirm = document.getElementById('change-pw-confirm').value;

    submitBtn.disabled = true;
    submitBtn.textContent = 'Saving…';

    try {
        var resp = await fetch('api.php?action=change_password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                csrf_token:       CSRF_TOKEN,
                current_password: current,
                new_password:     newPw,
                confirm_password: confirm,
            }),
        });

        var data = await resp.json();

        if (data.status === 'ok') {
            document.getElementById('change-pw-current').value = '';
            document.getElementById('change-pw-new').value = '';
            document.getElementById('change-pw-confirm').value = '';
            successEl.hidden = false;
            setTimeout(function() {
                closeChangePasswordModal();
                showToast('Password changed successfully.');
            }, 1500);
        } else {
            var msg = data.error === 'wrong_password'
                ? 'Current password is incorrect.'
                : (data.error || 'An error occurred. Please try again.');
            errEl.textContent = msg;
            errEl.hidden = false;
        }
    } catch (e) {
        errEl.textContent = 'An error occurred. Please try again.';
        errEl.hidden = false;
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Change Password';
    }
}

// Enter key submits, Escape closes
document.getElementById('change-pw-modal').addEventListener('keydown', function(e) {
    if (e.key === 'Enter')  { e.preventDefault(); submitChangePassword(); }
    if (e.key === 'Escape') { closeChangePasswordModal(); }
});

// Backdrop click closes
document.getElementById('change-pw-modal').addEventListener('click', function(e) {
    if (e.target === this) closeChangePasswordModal();
});
</script>

<!-- ── Restore Backup Modal ───────────────────────────────── -->
<div class="modal-backdrop" id="restore-modal" hidden role="dialog" aria-modal="true" aria-labelledby="restore-modal-title">
    <div class="modal-box modal-box--sm">
        <div class="modal-header">
            <h2 class="modal-title" id="restore-modal-title">Restore Backup</h2>
            <button class="modal-close-btn" onclick="closeRestoreModal()" aria-label="Close">&times;</button>
        </div>
        <div class="modal-body">
            <div id="restore-error"   class="alert alert-error"   hidden></div>
            <div id="restore-success" class="alert alert-success" hidden></div>

            <!-- File picker — always shown initially -->
            <div id="restore-pick-row">
                <p class="field-hint" style="margin-bottom:0.75rem">
                    Select an Ensemble backup file (<code>.zip</code>) to restore.
                    <strong>This will replace all your current outfits and links.</strong>
                </p>
                <div class="props-image-controls">
                    <button class="btn btn-ghost btn-sm" onclick="browseRestoreFile()">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14">
                            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                            <polyline points="17 8 12 3 7 8"/>
                            <line x1="12" y1="3" x2="12" y2="15"/>
                        </svg>
                        Browse…
                    </button>
                    <span id="restore-file-name" class="field-hint"></span>
                    <input type="file" id="restore-file-input" accept=".zip" style="display:none" onchange="restoreFileChosen(this)">
                </div>
            </div>

            <!-- UUID mismatch warning — shown only AFTER server reads the file and finds a different avatar -->
            <div id="restore-mismatch-warning" hidden>
                <div class="alert alert-error" style="margin-bottom:0.75rem">
                    <strong>&#9888; This backup belongs to a different avatar.</strong><br>
                    <span id="restore-mismatch-text"></span>
                </div>
                <p class="field-hint">
                    Restoring may cause unpredictable results as the outfit folders in this
                    backup may not match your in-world inventory. You can still proceed if you
                    have a good reason (e.g. restoring to an alt that has had an IAR restore
                    of the original avatar's inventory).
                </p>
            </div>
        </div>
        <div class="modal-footer">
            <button class="btn btn-ghost" onclick="closeRestoreModal()">Cancel</button>
            <!-- This button's label and handler are updated by JS after a mismatch -->
            <button class="btn btn-primary" id="restore-action-btn">Restore</button>
        </div>
    </div>
</div>

<script>
// ══════════════════════════════════════════════════════════════
// BACKUP — DOWNLOAD
// ══════════════════════════════════════════════════════════════

function closeSideMenu() {
    document.getElementById('sideMenu').classList.remove('side-menu--open');
    document.getElementById('sideMenuOverlay').classList.remove('side-menu-overlay--visible');
    document.getElementById('hamburgerBtn').setAttribute('aria-expanded', 'false');
    document.body.style.overflow = '';
}

function downloadBackup() {
    closeSideMenu();

    // Build a hidden form and submit it — triggers a file download
    // without navigating away from the page, and sends CSRF as POST.
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = 'backup.php?action=download';
    form.style.display = 'none';

    var csrfInput = document.createElement('input');
    csrfInput.type  = 'hidden';
    csrfInput.name  = 'csrf_token';
    csrfInput.value = CSRF_TOKEN;
    form.appendChild(csrfInput);

    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);

    showToast('Preparing your backup\u2026', 'info');
}

// ══════════════════════════════════════════════════════════════
// BACKUP — RESTORE
// ══════════════════════════════════════════════════════════════

function browseRestoreFile() {
    document.getElementById('restore-file-input').click();
}

function restoreFileChosen(input) {
    var nameEl = document.getElementById('restore-file-name');
    nameEl.textContent = input.files && input.files[0] ? input.files[0].name : '';
}

function openRestoreModal() {
    closeSideMenu();

    // Reset to clean initial state
    document.getElementById('restore-file-input').value = '';
    document.getElementById('restore-file-name').textContent   = '';
    document.getElementById('restore-error').hidden            = true;
    document.getElementById('restore-success').hidden          = true;
    document.getElementById('restore-mismatch-warning').hidden = true;
    document.getElementById('restore-pick-row').hidden         = false;

    var btn = document.getElementById('restore-action-btn');
    btn.textContent = 'Restore';
    btn.disabled    = false;
    btn.className   = 'btn btn-primary';
    btn.onclick     = function() { submitRestore(false); };

    document.getElementById('restore-modal').hidden = false;
    document.body.style.overflow = 'hidden';
}

function closeRestoreModal() {
    document.getElementById('restore-modal').hidden = true;
    document.body.style.overflow = '';
}

async function submitRestore(confirmed) {
    var errEl     = document.getElementById('restore-error');
    var successEl = document.getElementById('restore-success');
    var btn       = document.getElementById('restore-action-btn');
    var fileInput = document.getElementById('restore-file-input');

    errEl.hidden     = true;
    successEl.hidden = true;

    if (!fileInput.files || fileInput.files.length === 0) {
        errEl.textContent = 'Please select a backup file first.';
        errEl.hidden = false;
        return;
    }

    btn.disabled    = true;
    btn.textContent = 'Restoring\u2026';

    var fd = new FormData();
    fd.append('csrf_token',  CSRF_TOKEN);
    fd.append('backup_file', fileInput.files[0]);
    if (confirmed) fd.append('confirm', '1');

    try {
        var resp = await fetch('backup.php?action=restore', { method: 'POST', body: fd });
        var data = await resp.json();

        if (data.status === 'uuid_mismatch') {
            // Server read the file and found it belongs to a different avatar.
            // Show the warning and re-label the action button.
            document.getElementById('restore-mismatch-text').textContent =
                'This backup was made for ' + (data.backup_username || 'an unknown user') +
                ' (' + data.backup_uuid + '). The current logged-in user is not the original owner.';
            document.getElementById('restore-mismatch-warning').hidden = false;

            btn.textContent = 'Restore Anyway';
            btn.className   = 'btn btn-danger';
            btn.disabled    = false;
            btn.onclick     = function() { submitRestore(true); };
            return;
        }

        if (data.status === 'ok') {
            var msg = 'Restore complete — ' + data.outfits + ' outfit(s)';
            if (data.links > 0) msg += ', ' + data.links + ' link(s)';
            if (data.images_restored > 0) msg += ', ' + data.images_restored + ' image(s)';
            msg += ' restored.';
            if (data.image_errors > 0) {
                msg += ' Note: ' + data.image_errors + ' image(s) could not be restored — you may need to re-upload them.';
            }
            successEl.textContent = msg;
            successEl.hidden = false;
            // Reload after a pause so the outfit grid reflects the restored data
            setTimeout(function() {
                closeRestoreModal();
                window.location.reload();
            }, 2500);
        } else {
            errEl.textContent = data.error || 'An error occurred during restore.';
            errEl.hidden = false;
            btn.textContent = 'Restore';
            btn.disabled    = false;
        }
    } catch (e) {
        errEl.textContent = 'Could not reach the server. Please try again.';
        errEl.hidden = false;
        btn.textContent = 'Restore';
        btn.disabled    = false;
    }
}

document.getElementById('restore-modal').addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeRestoreModal();
});
document.getElementById('restore-modal').addEventListener('click', function(e) {
    if (e.target === this) closeRestoreModal();
});
</script>

</body>
</html>
