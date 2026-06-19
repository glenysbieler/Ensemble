<?php
// ============================================================
// Ensemble - Backup / Restore
// ============================================================
// Handles two operations, selected by ?action= query param:
//
//   download  — POST: streams a .zip to the browser containing:
//                 ensemble_backup.json  — all user data
//                 uploads/<uuid>/       — user's outfit images
//
//   restore   — POST (multipart): accepts an uploaded .zip,
//                 validates it, warns on UUID mismatch,
//                 then replaces outfits + images.
//
// Both require an active session. CSRF is checked on every request.
//
// The JSON inside the zip has this shape:
// {
//   "version"    : 1,
//   "user_uuid"  : "<access_uuid>",
//   "username"   : "<display name>",
//   "exported_at": <unix timestamp>,
//   "user"       : { ...row from users table... },
//   "outfits"    : [ ...rows from outfits table... ],
//   "links"      : [ ...rows from links table... ]
// }
//
// Image filenames stored in outfits[].image_filename are bare
// names only (no path). Inside the zip they live at:
//   uploads/<user_uuid>/<filename>
//
// On restore, the user record itself is NOT replaced — we only
// restore outfits, links, and images. Passwords, sim_url, and
// last_seen are left untouched so the HUD keeps working.
// ============================================================

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';

auth_start();

// ── Auth gate ─────────────────────────────────────────────────
$accessUUID = auth_uuid();
if ($accessUUID === null) {
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'forbidden']);
    exit;
}

// ── CSRF check ───────────────────────────────────────────────
// Supports both form field and header (for fetch() callers).
$csrfToken = $_POST['csrf_token'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $csrfToken)) {
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'csrf']);
    exit;
}

// ── Only accept POST ─────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$action = $_GET['action'] ?? '';

try {
    $pdo = db_connect();

    switch ($action) {
        case 'download':
            backup_download($pdo, $accessUUID);
            break;

        case 'restore':
            backup_restore($pdo, $accessUUID);
            break;

        default:
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Unknown action']);
    }
} catch (Exception $e) {
    // If headers not yet sent we can still return JSON
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Server error']);
    }
    error_log('Ensemble backup error: ' . $e->getMessage());
}


// ============================================================
// DOWNLOAD
// ============================================================

function backup_download(PDO $pdo, string $accessUUID): void
{
    // ── Fetch user row ────────────────────────────────────────
    $stmt = $pdo->prepare('SELECT * FROM users WHERE access_uuid = ?');
    $stmt->execute([$accessUUID]);
    $user = $stmt->fetch();
    if (!$user) {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'forbidden']);
        return;
    }

    // ── Fetch outfits ─────────────────────────────────────────
    $stmt = $pdo->prepare('SELECT * FROM outfits WHERE user_uuid = ? ORDER BY created_at ASC');
    $stmt->execute([$accessUUID]);
    $outfits = $stmt->fetchAll();

    // ── Fetch links ───────────────────────────────────────────
    $stmt = $pdo->prepare('SELECT * FROM links WHERE user_uuid = ? ORDER BY created_at ASC');
    $stmt->execute([$accessUUID]);
    $links = $stmt->fetchAll();

    // ── Build JSON payload ────────────────────────────────────
    $payload = [
        'version'     => 1,
        'user_uuid'   => $accessUUID,
        'username'    => $user['username'] ?? '',
        'exported_at' => time(),
        'user'        => $user,
        'outfits'     => $outfits,
        'links'       => $links,
    ];
    $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

    // ── Build zip in memory ───────────────────────────────────
    // ZipArchive can write to a temp file; we stream it on close.
    $tmpFile = tempnam(sys_get_temp_dir(), 'ensemble_backup_');
    $zip = new ZipArchive();
    if ($zip->open($tmpFile, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Could not create backup archive']);
        return;
    }

    // Add JSON data file
    $zip->addFromString('ensemble_backup.json', $json);

    // Add images from the user's uploads subfolder
    $uploadsDir = rtrim(UPLOADS_DIR, '/\\') . DIRECTORY_SEPARATOR . $accessUUID . DIRECTORY_SEPARATOR;
    if (is_dir($uploadsDir)) {
        $files = scandir($uploadsDir);
        foreach ($files as $file) {
            if ($file === '.' || $file === '..') continue;
            $fullPath = $uploadsDir . $file;
            if (is_file($fullPath)) {
                // Store as: uploads/<uuid>/<filename>
                $zip->addFile($fullPath, 'uploads/' . $accessUUID . '/' . $file);
            }
        }
    }

    $zip->close();

    // ── Stream zip to browser ─────────────────────────────────
    $safeUsername = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $user['username'] ?: 'ensemble');
    $filename     = 'ensemble_backup_' . $safeUsername . '_' . date('Ymd_His') . '.zip';

    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . filesize($tmpFile));
    header('Cache-Control: no-cache, no-store');
    header('Pragma: no-cache');

    readfile($tmpFile);
    unlink($tmpFile);
}


// ============================================================
// RESTORE
// ============================================================

function backup_restore(PDO $pdo, string $accessUUID): void
{
    header('Content-Type: application/json');

    // ── Validate upload ───────────────────────────────────────
    if (!isset($_FILES['backup_file']) || $_FILES['backup_file']['error'] !== UPLOAD_ERR_OK) {
        $uploadErr = $_FILES['backup_file']['error'] ?? -1;
        http_response_code(400);
        echo json_encode(['error' => 'No file uploaded or upload error (code ' . $uploadErr . ')']);
        return;
    }

    $tmpPath  = $_FILES['backup_file']['tmp_name'];
    $origName = $_FILES['backup_file']['name'] ?? '';

    // Basic MIME / extension guard — ZipArchive will also reject non-zips
    $ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
    if ($ext !== 'zip') {
        http_response_code(400);
        echo json_encode(['error' => 'File must be a .zip archive']);
        return;
    }

    // ── Open zip ──────────────────────────────────────────────
    $zip = new ZipArchive();
    $opened = $zip->open($tmpPath);
    if ($opened !== true) {
        http_response_code(400);
        echo json_encode(['error' => 'Could not open zip file (code ' . $opened . ')']);
        return;
    }

    // ── Read and validate JSON ────────────────────────────────
    $jsonContent = $zip->getFromName('ensemble_backup.json');
    if ($jsonContent === false) {
        $zip->close();
        http_response_code(400);
        echo json_encode(['error' => 'This does not appear to be an Ensemble backup file (ensemble_backup.json not found)']);
        return;
    }

    $data = json_decode($jsonContent, true);
    if (!is_array($data) || ($data['version'] ?? 0) !== 1 || empty($data['user_uuid'])) {
        $zip->close();
        http_response_code(400);
        echo json_encode(['error' => 'Backup file is corrupt or from an unsupported version']);
        return;
    }

    $backupUUID     = $data['user_uuid'];
    $backupUsername = $data['username'] ?? $backupUUID;
    $outfits        = $data['outfits'] ?? [];
    $links          = $data['links']   ?? [];

    // ── UUID mismatch check ───────────────────────────────────
    // If the backup was made by a different avatar, we warn but still allow.
    // The caller sends ?confirm=1 to proceed after seeing the warning.
    $uuidMismatch = ($backupUUID !== $accessUUID);
    if ($uuidMismatch && ($_POST['confirm'] ?? '') !== '1') {
        $zip->close();
        // Return 200 with a special status so the JS can show the warning modal
        echo json_encode([
            'status'          => 'uuid_mismatch',
            'backup_uuid'     => $backupUUID,
            'backup_username' => $backupUsername,
        ]);
        return;
    }

    // ── Determine which user UUID the images live under in the zip ─
    // Images in the zip are always under the original backup owner's UUID.
    $imageZipPrefix = 'uploads/' . $backupUUID . '/';

    // ── Begin restore transaction ─────────────────────────────
    $pdo->beginTransaction();

    try {
        // Delete existing outfits and links for this user
        $pdo->prepare('DELETE FROM outfits WHERE user_uuid = ?')->execute([$accessUUID]);
        $pdo->prepare('DELETE FROM links   WHERE user_uuid = ?')->execute([$accessUUID]);

        // ── Insert outfits, building an old-ID → new-ID map ──────
        //
        // base_outfits and additional_items store JSON arrays of outfit IDs.
        // Because we DELETE then re-INSERT, SQLite assigns new auto-increment
        // IDs. We must record the old→new mapping and fix up those JSON arrays
        // in a second pass, otherwise cross-outfit references are silently lost.
        //
        // All other columns are restored as-is. notes and comments are both
        // present in the outfits table (notes from original schema, comments
        // added later via ALTER TABLE); we restore both.
        $insertOutfit = $pdo->prepare("
            INSERT INTO outfits
                (user_uuid, folder_path, outfit_name, attachments,
                 has_space_warning, image_filename, tags, notes, creator,
                 is_public, created_at, locked, comments, access_level,
                 wear_mode, base_outfits, additional_items, wear_after_remove,
                 remove_before_wear, removal_points)
            VALUES
                (:user_uuid, :folder_path, :outfit_name, :attachments,
                 :has_space_warning, :image_filename, :tags, :notes, :creator,
                 :is_public, :created_at, :locked, :comments, :access_level,
                 :wear_mode, :base_outfits, :additional_items, :wear_after_remove,
                 :remove_before_wear, :removal_points)
        ");

        // $idMap[oldId] = newId
        $idMap = [];

        foreach ($outfits as $o) {
            $oldId        = (int)($o['id'] ?? 0);
            $imageFilename = isset($o['image_filename']) && (string)$o['image_filename'] !== ''
                                ? (string)$o['image_filename']
                                : null;

            // Use explicit bindValue for image_filename so PDO uses the correct
            // NULL type — passing null in an associative array to execute() can
            // silently store an empty string in some PDO/SQLite builds.
            $insertOutfit->bindValue(':user_uuid',          $accessUUID,                         PDO::PARAM_STR);
            $insertOutfit->bindValue(':folder_path',        $o['folder_path']        ?? '',       PDO::PARAM_STR);
            $insertOutfit->bindValue(':outfit_name',        $o['outfit_name']        ?? '',       PDO::PARAM_STR);
            $insertOutfit->bindValue(':attachments',        $o['attachments']        ?? '[]',     PDO::PARAM_STR);
            $insertOutfit->bindValue(':has_space_warning',  (int)($o['has_space_warning'] ?? 0),  PDO::PARAM_INT);
            $insertOutfit->bindValue(':image_filename',     $imageFilename,                       $imageFilename === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
            $insertOutfit->bindValue(':tags',               $o['tags']               ?? '',       PDO::PARAM_STR);
            $insertOutfit->bindValue(':notes',              $o['notes']              ?? '',       PDO::PARAM_STR);
            $insertOutfit->bindValue(':creator',            $o['creator']            ?? '',       PDO::PARAM_STR);
            $insertOutfit->bindValue(':is_public',          (int)($o['is_public']    ?? 1),       PDO::PARAM_INT);
            $insertOutfit->bindValue(':created_at',         (int)($o['created_at']   ?? 0),       PDO::PARAM_INT);
            $insertOutfit->bindValue(':locked',             0,                                    PDO::PARAM_INT);
            $insertOutfit->bindValue(':comments',           $o['comments']           ?? '',       PDO::PARAM_STR);
            $insertOutfit->bindValue(':access_level',       $o['access_level']       ?? 'public',PDO::PARAM_STR);
            $insertOutfit->bindValue(':wear_mode',          $o['wear_mode']          ?? 'subfolders_replace', PDO::PARAM_STR);
            $insertOutfit->bindValue(':base_outfits',       $o['base_outfits']       ?? '',       PDO::PARAM_STR);
            $insertOutfit->bindValue(':additional_items',   $o['additional_items']   ?? '',       PDO::PARAM_STR);
            $insertOutfit->bindValue(':wear_after_remove',  $o['wear_after_remove']  ?? '',       PDO::PARAM_STR);
            $insertOutfit->bindValue(':remove_before_wear', (int)($o['remove_before_wear'] ?? 0), PDO::PARAM_INT);
            $insertOutfit->bindValue(':removal_points',     $o['removal_points']     ?? '',       PDO::PARAM_STR);
            $insertOutfit->execute();

            $newId = (int)$pdo->lastInsertId();
            if ($oldId > 0) {
                $idMap[$oldId] = $newId;
            }
        }

        // ── Second pass: remap base_outfits, additional_items, wear_after_remove ──
        // Each is a JSON array of integer outfit IDs referencing old IDs.
        // Translate each via $idMap; drop any IDs not found in the map
        // (which would mean a reference to an outfit that wasn't in the backup).
        if (!empty($idMap)) {
            $updateRefs = $pdo->prepare('
                UPDATE outfits SET base_outfits = ?, additional_items = ?, wear_after_remove = ?
                WHERE id = ?
            ');

            foreach ($outfits as $o) {
                $oldId = (int)($o['id'] ?? 0);
                if ($oldId === 0 || !isset($idMap[$oldId])) continue;
                $newId = $idMap[$oldId];

                $rawBase   = $o['base_outfits']     ?? '';
                $rawExtra  = $o['additional_items']  ?? '';
                $rawAfter  = $o['wear_after_remove'] ?? '';

                // Skip if there's nothing to remap (empty, "[]", or "null" string)
                $isEmpty = function(string $v): bool {
                    return $v === '' || $v === '[]' || $v === 'null';
                };
                if ($isEmpty($rawBase) && $isEmpty($rawExtra) && $isEmpty($rawAfter)) continue;

                $newBase  = remap_id_array($rawBase,  $idMap);
                $newExtra = remap_id_array($rawExtra, $idMap);
                $newAfter = remap_id_array($rawAfter, $idMap);

                $updateRefs->execute([$newBase, $newExtra, $newAfter, $newId]);
            }
        }

        // ── Insert links ───────────────────────────────────────
        // Generate fresh UUIDs — the old link_uuid values may have been
        // shared publicly and shouldn't survive a cross-user restore.
        // For a same-user restore this is a minor inconvenience (existing
        // shared URLs stop working) but is safer than leaving stale links.
        $insertLink = $pdo->prepare("
            INSERT INTO links (link_uuid, user_uuid, link_name, can_wear, include_private, created_at)
            VALUES (:link_uuid, :user_uuid, :link_name, :can_wear, :include_private, :created_at)
        ");

        foreach ($links as $l) {
            $newLinkUUID = sprintf(
                '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
                mt_rand(0, 0xffff), mt_rand(0, 0xffff),
                mt_rand(0, 0xffff),
                mt_rand(0, 0x0fff) | 0x4000,
                mt_rand(0, 0x3fff) | 0x8000,
                mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
            );
            $insertLink->execute([
                ':link_uuid'       => $newLinkUUID,
                ':user_uuid'       => $accessUUID,
                ':link_name'       => $l['link_name']       ?? '',
                ':can_wear'        => (int)($l['can_wear']        ?? 0),
                ':include_private' => (int)($l['include_private'] ?? 0),
                ':created_at'      => (int)($l['created_at']      ?? 0),
            ]);
        }

        $pdo->commit();

    } catch (Exception $e) {
        $pdo->rollBack();
        $zip->close();
        throw $e;   // Caught by outer handler
    }

    // ── Restore images ────────────────────────────────────────
    // Done after the DB transaction commits. Image failures are
    // non-fatal — outfit records are still restored correctly.
    $destDir = rtrim(UPLOADS_DIR, '/\\') . DIRECTORY_SEPARATOR . $accessUUID . DIRECTORY_SEPARATOR;

    // Clear existing images for this user
    if (is_dir($destDir)) {
        foreach (scandir($destDir) as $f) {
            if ($f !== '.' && $f !== '..') @unlink($destDir . $f);
        }
    } else {
        @mkdir($destDir, 0755, true);
    }

    // Extract matching images from zip
    $imageErrors    = 0;
    $imagesRestored = 0;
    $numFiles       = $zip->numFiles;

    for ($i = 0; $i < $numFiles; $i++) {
        $name = $zip->getNameIndex($i);
        if ($name === false) continue;
        // Only process files inside the expected image prefix
        if (strpos($name, $imageZipPrefix) !== 0) continue;
        $basename = basename($name);
        if ($basename === '') continue;
        // Validate filename — must be 32 hex chars + .jpg (same rule as image.php)
        if (!preg_match('/^[0-9a-f]{32}\.jpg$/i', $basename)) continue;

        $fileData = $zip->getFromIndex($i);
        if ($fileData === false) {
            $imageErrors++;
            continue;
        }
        if (file_put_contents($destDir . $basename, $fileData) === false) {
            $imageErrors++;
        } else {
            $imagesRestored++;
        }
    }

    $zip->close();

    echo json_encode([
        'status'          => 'ok',
        'outfits'         => count($outfits),
        'links'           => count($links),
        'images_restored' => $imagesRestored,
        'image_errors'    => $imageErrors,
        'uuid_mismatch'   => $uuidMismatch,
    ]);
}


// ============================================================
// HELPERS
// ============================================================

/**
 * Given a JSON-encoded array of integer outfit IDs (or an empty string),
 * translate each ID through $idMap and return the re-encoded JSON string.
 * IDs absent from the map are dropped.
 */
function remap_id_array(string $raw, array $idMap): string
{
    if ($raw === '' || $raw === '[]' || $raw === 'null') return '';
    $ids = json_decode($raw, true);
    if (!is_array($ids) || empty($ids)) return '';
    $remapped = [];
    foreach ($ids as $oldId) {
        $key = (int)$oldId;
        if (isset($idMap[$key])) {
            $remapped[] = $idMap[$key];
        }
    }
    return empty($remapped) ? '' : json_encode($remapped);
}
