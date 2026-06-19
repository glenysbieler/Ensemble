<?php
// ============================================================
// Ensemble - Cleanup Script
// ensemble_cleanup.php
// ============================================================
// Removes users who have not been seen for INACTIVITY_DAYS
// (default: 365 days), along with all their associated data:
//   - outfits
//   - links
//   - remember_me tokens
//   - uploaded images (uploads/<access_uuid>/ directory)
//
// Also cleans up:
//   - Expired remember_me tokens (regardless of user age)
//   - Orphaned outfit image files with no matching DB record
//
// ── How to run ────────────────────────────────────────────
// From the command line (recommended — use cron):
//   php ensemble_cleanup.php
//
// As a web request (lock it down — see WEB_ALLOWED below):
//   https://yoursite.example.com/ensemble_cleanup.php
//
// ── Cron example (monthly, first of the month at 3am) ────
//   0 3 1 * * /usr/bin/php /path/to/ensemble_cleanup.php >> /var/log/ensemble_cleanup.log 2>&1
//
// ── Dry run (preview only, no changes made) ───────────────
//   php ensemble_cleanup.php --dry-run
//   Or: https://yoursite.example.com/ensemble_cleanup.php?dry_run=1
//
// ── Safety ───────────────────────────────────────────────
// This script makes irreversible deletions. A dry run is
// always recommended before the first live execution.
// Consider taking a database backup first.
// ============================================================

// ── Configuration ─────────────────────────────────────────

// Days of inactivity before a user account is removed.
// last_seen is updated on every HUD heartbeat, checkin, and
// web panel login. A user who has been offline for this many
// days and never logged into the web panel will be deleted.
const INACTIVITY_DAYS = 365;

// Set to true to allow this script to be called via HTTP.
// If false (default), web requests are rejected.
// Only enable this if the script lives outside the web root
// or you protect it with your own auth layer (e.g. .htaccess
// IP restriction). Never leave this open on a public server.
const WEB_ALLOWED = false;

// ── End configuration ──────────────────────────────────────

require_once __DIR__ . '/config.php';

// ── Web request gate ───────────────────────────────────────
if (php_sapi_name() !== 'cli') {
    if (!WEB_ALLOWED) {
        http_response_code(403);
        echo "This script may only be run from the command line.\n";
        echo "Set WEB_ALLOWED = true in ensemble_cleanup.php to enable web access.\n";
        exit(1);
    }
    // Minimal output wrapper for browser readability
    header('Content-Type: text/plain; charset=utf-8');
}

// ── Dry run flag ───────────────────────────────────────────
$dryRun = false;
if (php_sapi_name() === 'cli') {
    $dryRun = in_array('--dry-run', $argv ?? [], true);
} else {
    $dryRun = !empty($_GET['dry_run']);
}

// ── Logging helper ─────────────────────────────────────────
function log_line(string $msg): void
{
    echo '[' . date('Y-m-d H:i:s') . '] ' . $msg . "\n";
}

// ── Main ───────────────────────────────────────────────────

log_line('Ensemble cleanup started' . ($dryRun ? ' (DRY RUN — no changes will be made)' : ''));

$pdo = new PDO('sqlite:' . DB_PATH);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
$pdo->exec('PRAGMA journal_mode=WAL');
$pdo->exec('PRAGMA foreign_keys=ON');

$cutoff = time() - (INACTIVITY_DAYS * 86400);
log_line(sprintf(
    'Inactivity threshold: %d days (accounts not seen since before %s)',
    INACTIVITY_DAYS,
    date('Y-m-d', $cutoff)
));

// ── 1. Find stale users ────────────────────────────────────
$staleUsers = $pdo->prepare('SELECT access_uuid, username, last_seen FROM users WHERE last_seen < ? AND last_seen > 0');
$staleUsers->execute([$cutoff]);
$stale = $staleUsers->fetchAll();

if (empty($stale)) {
    log_line('No stale user accounts found.');
} else {
    log_line(sprintf('Found %d stale user account(s):', count($stale)));
    foreach ($stale as $u) {
        $lastSeen = $u['last_seen'] > 0 ? date('Y-m-d', $u['last_seen']) : 'never';
        log_line(sprintf('  - %s (%s) — last seen %s', $u['username'] ?: '(no username)', $u['access_uuid'], $lastSeen));
    }
}

if (!empty($stale)) {
    foreach ($stale as $user) {
        $uuid = $user['access_uuid'];

        // Count records for the log
        $outfitCount = $pdo->prepare('SELECT COUNT(*) as n FROM outfits WHERE user_uuid = ?');
        $outfitCount->execute([$uuid]);
        $nOutfits = (int)$outfitCount->fetch()['n'];

        $linkCount = $pdo->prepare('SELECT COUNT(*) as n FROM links WHERE user_uuid = ?');
        $linkCount->execute([$uuid]);
        $nLinks = (int)$linkCount->fetch()['n'];

        $tokenCount = $pdo->prepare('SELECT COUNT(*) as n FROM remember_tokens WHERE user_uuid = ?');
        $tokenCount->execute([$uuid]);
        $nTokens = (int)$tokenCount->fetch()['n'];

        log_line(sprintf(
            '  Removing %s — %d outfit(s), %d link(s), %d token(s)',
            $uuid, $nOutfits, $nLinks, $nTokens
        ));

        if (!$dryRun) {
            // Delete child records first (FK safety, even though cascade may handle it)
            $pdo->prepare('DELETE FROM outfits           WHERE user_uuid = ?')->execute([$uuid]);
            $pdo->prepare('DELETE FROM links             WHERE user_uuid = ?')->execute([$uuid]);
            $pdo->prepare('DELETE FROM remember_tokens   WHERE user_uuid = ?')->execute([$uuid]);
            $pdo->prepare('DELETE FROM users             WHERE access_uuid = ?')->execute([$uuid]);
        }

        // Remove upload directory
        $uploadDir = rtrim(UPLOADS_DIR, '/') . '/' . $uuid;
        if (is_dir($uploadDir)) {
            $files = glob($uploadDir . '/*') ?: [];
            log_line(sprintf('  Removing uploads directory: %s (%d file(s))', $uploadDir, count($files)));
            if (!$dryRun) {
                foreach ($files as $file) {
                    @unlink($file);
                }
                @rmdir($uploadDir);
            }
        }
    }

    if ($dryRun) {
        log_line(sprintf('DRY RUN: would have removed %d user account(s) and associated data.', count($stale)));
    } else {
        log_line(sprintf('Removed %d stale user account(s).', count($stale)));
    }
}

// ── 2. Expired remember_me tokens ─────────────────────────
$expiredTokens = $pdo->prepare('SELECT COUNT(*) as n FROM remember_tokens WHERE expires_at < ?');
$expiredTokens->execute([time()]);
$nExpired = (int)$expiredTokens->fetch()['n'];

if ($nExpired > 0) {
    log_line(sprintf('Removing %d expired remember_me token(s).', $nExpired));
    if (!$dryRun) {
        $pdo->prepare('DELETE FROM remember_tokens WHERE expires_at < ?')->execute([time()]);
    }
} else {
    log_line('No expired remember_me tokens found.');
}

// ── 3. Orphaned image files ────────────────────────────────
// Any file in uploads/<uuid>/ where that user_uuid no longer
// exists in the DB, or where the filename doesn't match any
// outfit's image_filename for that user.
$uploadsRoot = rtrim(UPLOADS_DIR, '/');
$orphanedFiles = 0;

if (is_dir($uploadsRoot)) {
    $userDirs = glob($uploadsRoot . '/*', GLOB_ONLYDIR) ?: [];
    foreach ($userDirs as $userDir) {
        $dirUuid = basename($userDir);

        // Check user still exists
        $userExists = $pdo->prepare('SELECT 1 FROM users WHERE access_uuid = ?');
        $userExists->execute([$dirUuid]);
        if (!$userExists->fetch()) {
            // Whole directory is orphaned (user deleted above, or left from a manual DB wipe)
            $files = glob($userDir . '/*') ?: [];
            if (!empty($files)) {
                log_line(sprintf('  Orphaned directory (no matching user): %s (%d file(s))', $userDir, count($files)));
                if (!$dryRun) {
                    foreach ($files as $f) {
                        @unlink($f);
                    }
                    @rmdir($userDir);
                }
                $orphanedFiles += count($files);
            }
            continue;
        }

        // Check individual files against DB records
        $knownFiles = $pdo->prepare('SELECT image_filename FROM outfits WHERE user_uuid = ? AND image_filename IS NOT NULL AND image_filename != \'\'');
        $knownFiles->execute([$dirUuid]);
        $known = array_column($knownFiles->fetchAll(), 'image_filename');

        $files = glob($userDir . '/*') ?: [];
        foreach ($files as $file) {
            $filename = basename($file);
            if (!in_array($filename, $known, true)) {
                log_line(sprintf('  Orphaned file: %s', $file));
                if (!$dryRun) {
                    @unlink($file);
                }
                $orphanedFiles++;
            }
        }
    }
}

if ($orphanedFiles > 0) {
    if ($dryRun) {
        log_line(sprintf('DRY RUN: would have removed %d orphaned image file(s).', $orphanedFiles));
    } else {
        log_line(sprintf('Removed %d orphaned image file(s).', $orphanedFiles));
    }
} else {
    log_line('No orphaned image files found.');
}

// ── Done ───────────────────────────────────────────────────
log_line('Cleanup complete' . ($dryRun ? ' (DRY RUN — no changes were made)' : '') . '.');
