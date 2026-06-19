<?php
// ============================================================
// Ensemble - Image Passthrough
// ============================================================
// Serves outfit images from outside the web root.
// Only serves images belonging to the currently logged-in user.
//
// Usage: image.php?file=abc123def456.jpg
//
// Security:
//   - Session must be active (user must be logged in)
//   - Filename is validated against the database to confirm
//     the image belongs to this user's outfit
//   - Filename is sanitised — no path traversal possible
//   - Only .jpg files (all uploads are normalised to JPEG)
// ============================================================

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';

auth_start();

// ── Resolve identity — link_uuid param takes priority ────────
// If a link_uuid is present in the URL, use link-based auth
// regardless of session state. This handles the case where the
// viewer is also a logged-in owner — their session must not
// interfere with serving another user's images via a link.
$linkUUID = null;
$userUUID = null;

$rawLink = trim($_GET['link_uuid'] ?? '');
if (preg_match('/^[0-9a-f]{32}$/', $rawLink)) {
    $linkUUID = $rawLink;
} else {
    // No link_uuid — fall back to session auth
    $userUUID = auth_uuid();
}

if ($userUUID === null && $linkUUID === null) {
    http_response_code(403);
    header('Content-Type: text/plain');
    echo 'Forbidden';
    exit;
}

// ── Validate filename parameter ───────────────────────────────
$filename = $_GET['file'] ?? '';

// Strip any directory components and allow only safe characters.
// Filenames are hex strings + .jpg — nothing else should ever appear.
$filename = basename($filename);
if (!preg_match('/^[0-9a-f]{32}\.jpg$/', $filename)) {
    http_response_code(400);
    header('Content-Type: text/plain');
    echo 'Invalid filename';
    exit;
}

// ── Confirm this image belongs to this user ───────────────────
// We check against the database rather than just trusting the filename.
// This means a user cannot access another user's images by guessing names.
try {
    $pdo  = db_connect();
    if ($userUUID !== null) {
        // Logged-in user — image must belong to them
        $stmt = $pdo->prepare('
            SELECT id FROM outfits
            WHERE image_filename = ? AND user_uuid = ?
        ');
        $stmt->execute([$filename, $userUUID]);
    } else {
        // Link visitor — image must belong to the link owner
        // Also respect include_private: if link is public-only,
        // only serve images from non-private outfits
        // Use a placeholder for 'private' to avoid PHP reserved-word parse issues
        $stmt = $pdo->prepare("
            SELECT o.id FROM outfits o
            JOIN links l ON l.user_uuid = o.user_uuid
            WHERE o.image_filename = ?
              AND l.link_uuid = ?
              AND (l.include_private = 1 OR o.access_level != ?)
        ");
        $stmt->execute([$filename, $linkUUID, 'private']);
    }

    if (!$stmt->fetch()) {
        // Either doesn't exist or belongs to someone else — same response
        http_response_code(404);
        header('Content-Type: text/plain');
        echo 'Not found';
        exit;
    }
} catch (Exception $e) {
    http_response_code(500);
    header('Content-Type: text/plain');
    echo 'Server error';
    exit;
}

// ── Serve the file ────────────────────────────────────────────
// Images live under UPLOADS_DIR/<user_uuid>/ — resolve the owner UUID
// from whichever auth path we took (session or link).
$ownerUUID = $userUUID ?? null;
if ($ownerUUID === null && $linkUUID !== null) {
    // For link visitors, look up the link owner's UUID
    try {
        $stmt = $pdo->prepare('SELECT user_uuid FROM links WHERE link_uuid = ?');
        $stmt->execute([$linkUUID]);
        $link = $stmt->fetch();
        $ownerUUID = $link ? $link['user_uuid'] : null;
    } catch (Exception $e) {
        $ownerUUID = null;
    }
}

if ($ownerUUID === null) {
    http_response_code(403);
    header('Content-Type: text/plain');
    echo 'Forbidden';
    exit;
}

$filePath = UPLOADS_DIR . $ownerUUID . '/' . $filename;

if (!file_exists($filePath) || !is_file($filePath)) {
    http_response_code(404);
    header('Content-Type: text/plain');
    echo 'Not found';
    exit;
}

$fileSize = filesize($filePath);
$etag     = '"' . md5($filename . $fileSize) . '"';

// ── Cache headers — images don't change once uploaded ─────────
// Short cache (5 min) so a new upload is picked up quickly,
// but repeated views of the same image don't hit the server.
header('Content-Type: image/jpeg');
header('Content-Length: ' . $fileSize);
header('Cache-Control: private, max-age=300');
header('ETag: ' . $etag);

// Honour If-None-Match for browser cache efficiency
if (isset($_SERVER['HTTP_IF_NONE_MATCH']) && $_SERVER['HTTP_IF_NONE_MATCH'] === $etag) {
    http_response_code(304);
    exit;
}

http_response_code(200);
readfile($filePath);
exit;
