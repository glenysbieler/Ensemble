<?php
// ============================================================
// Ensemble - API Endpoint
// ============================================================
// Receives POST requests from the HUD.
//
// All responses are JSON. HTTP status codes are meaningful:
//   200 — success
//   400 — bad request (missing required fields)
//   403 — forbidden (invalid access UUID for protected actions)
//   405 — method not allowed
//   500 — server error
//
// Phase 1 actions:
//   checkin — called on HUD init and each heartbeat
//             Creates user if new, updates sim_url + last_seen always.
//
// Phase 2 will add: outfit_create, outfit_list, etc.
// ============================================================

require_once __DIR__ . '/db.php';
// (LINKS_MAX and ACCESS_CODE are defined in config.php, loaded via db.php)

// ── Only accept POST ─────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// ── Route by action ──────────────────────────────────────────
$action = $_GET['action'] ?? '';

header('Content-Type: application/json');

try {
    $pdo = db_connect();

    switch ($action) {

        case 'checkin':
            api_checkin($pdo);
            break;

        case 'set_temp_password':
            api_set_temp_password($pdo);
            break;

        case 'outfit_create':
            api_outfit_create($pdo);
            break;

        case 'outfit_create_web':
            api_outfit_create_web($pdo);
            break;

        case 'wear':
            api_wear($pdo);
            break;

        case 'remove':
            api_remove($pdo);
            break;

        case 'outfit_image_upload':
            api_outfit_image_upload($pdo);
            break;

        case 'outfit_delete':
            api_outfit_delete($pdo);
            break;

        case 'outfit_update':
            api_outfit_update($pdo);
            break;

        case 'outfit_lock':
            api_outfit_lock($pdo);
            break;

        case 'outfit_force_unlock':
            api_outfit_force_unlock($pdo);
            break;

        case 'get_worn':
            api_get_worn($pdo);
            break;

        case 'worn_detach':
            api_worn_detach($pdo);
            break;

        case 'get_account_status':
            api_get_account_status($pdo);
            break;

        case 'get_removal_defaults':
            api_get_removal_defaults($pdo);
            break;

        case 'save_removal_defaults':
            api_save_removal_defaults($pdo);
            break;

        case 'links_list':
            api_links_list($pdo);
            break;

        case 'link_create':
            api_link_create($pdo);
            break;

        case 'link_update':
            api_link_update($pdo);
            break;

        case 'link_delete':
            api_link_delete($pdo);
            break;

        case 'link_wear':
            api_link_wear($pdo);
            break;

        case 'link_remove':
            api_link_remove($pdo);
            break;

        case 'rlv_check':
            api_rlv_check($pdo);
            break;

        case 'rlv_send':
            api_rlv_send($pdo);
            break;

        case 'change_password':
            api_change_password($pdo);
            break;

        case 'save_theme':
            api_save_theme($pdo);
            break;

        default:
            http_response_code(400);
            echo json_encode(['error' => 'Unknown action']);
    }

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Server error']);
    // Log to PHP error log — don't expose internals to caller
    error_log('Ensemble API error: ' . $e->getMessage());
}

// ============================================================
// SET TEMP PASSWORD
// ============================================================
// POST /api.php?action=set_temp_password
// Fields: access_uuid, pw_hash
//
// Called by the HUD on every init where pws=0, and whenever
// the wearer uses the "Reset Password" menu option.
//
// Stores the hash and resets pw_set=0 so the next web login
// triggers a force-change. Does NOT set pw_set=1 — that only
// happens after the user completes the force-change form.
//
// The user must already exist (created by checkin). If they
// don't exist yet, we return 404 — the HUD will retry after
// the next successful checkin creates the account.
//
// Returns:
//   200 {"status":"ok"}
//   400 {"error":"..."}   — missing/invalid fields
//   404 {"error":"..."}   — user not found (checkin not yet done)
// ============================================================

function api_set_temp_password(PDO $pdo): void
{
    $accessUUID = trim($_POST['access_uuid'] ?? '');
    $pwHash     = trim($_POST['pw_hash']     ?? '');

    if ($accessUUID === '') {
        http_response_code(400);
        echo json_encode(['error' => 'access_uuid is required']);
        return;
    }

    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $accessUUID)) {
        http_response_code(400);
        echo json_encode(['error' => 'access_uuid format invalid']);
        return;
    }

    if (!preg_match('/^[0-9a-f]{32}$/', $pwHash)) {
        http_response_code(400);
        echo json_encode(['error' => 'pw_hash format invalid']);
        return;
    }

    // ── User must already exist ───────────────────────────────
    $stmt = $pdo->prepare('SELECT access_uuid FROM users WHERE access_uuid = ?');
    $stmt->execute([$accessUUID]);
    if (!$stmt->fetch()) {
        http_response_code(404);
        echo json_encode(['error' => 'user not found — HUD checkin required first']);
        return;
    }

    // ── Store hash and reset pw_set to 0 ─────────────────────
    // pw_set=0 means the next login will force a password change.
    $stmt = $pdo->prepare('UPDATE users SET pw_hash = ?, pw_set = 0 WHERE access_uuid = ?');
    $stmt->execute([$pwHash, $accessUUID]);

    http_response_code(200);
    echo json_encode(['status' => 'ok']);
}

// ============================================================
// CHECKIN
// ============================================================
// POST /api.php?action=checkin
// Fields: access_uuid, username, sim_url
//
// Used for both initial HUD checkin and every subsequent
// heartbeat — the effect is identical: keep sim_url and
// last_seen current. The 'new_user' flag in the response
// lets the HUD say "Account created" vs "Connected".
// ============================================================

// ============================================================
// WEAR SEQUENCE HELPER
// ============================================================
// Resolves a JSON array of outfit IDs into their DB rows
// (preserving user-defined order, scoped to $accessUUID).
// Used by api_wear and api_remove (wear_after_remove).
// ============================================================

function resolve_outfit_ids(PDO $pdo, string $json, string $accessUUID): array
{
    $ids = json_decode($json, true);
    if (!is_array($ids) || count($ids) === 0) return [];
    $placeholders = implode(',', array_fill(0, count($ids), '?'));
    $params       = array_merge(array_map('intval', $ids), [$accessUUID]);
    $stmt = $pdo->prepare("
        SELECT id, folder_path, wear_mode, remove_before_wear, removal_points
        FROM outfits
        WHERE id IN ($placeholders) AND user_uuid = ?
    ");
    $stmt->execute($params);
    $fetched = [];
    foreach ($stmt->fetchAll() as $r) $fetched[(int)$r['id']] = $r;
    // Return in the user-defined order
    $ordered = [];
    foreach ($ids as $id) {
        $id = (int)$id;
        if (isset($fetched[$id])) $ordered[] = $fetched[$id];
    }
    return $ordered;
}

// ============================================================
// send_wear_sequence
// ============================================================
// Sends an ordered array of outfit rows to the HUD one at a time,
// sleeping $STEP_DELAY seconds between each step to give RLV time
// to process each attach/detach.
//
// Returns null on success, or an error string on failure.
// ============================================================

function send_wear_sequence(array $sequence, string $simURL, string $accessUUID, string $defaultPoints): ?string
{
    $STEP_DELAY = 1.5;

    foreach ($sequence as $i => $step) {
        $removalPointsStr = resolve_removal_points($step, $defaultPoints);

        $postBody = http_build_query([
            'access_uuid'    => $accessUUID,
            'command'        => 'wear',
            'folder'         => $step['folder_path'],
            'wear_mode'      => $step['wear_mode'] ?: 'subfolders_replace',
            'removal_points' => $removalPointsStr,
        ]);

        $context = stream_context_create([
            'http' => [
                'method'        => 'POST',
                'header'        => "Content-Type: application/x-www-form-urlencoded\r\n"
                                 . "Content-Length: " . strlen($postBody) . "\r\n",
                'content'       => $postBody,
                'timeout'       => 8,
                'ignore_errors' => true,
            ]
        ]);

        $response = @file_get_contents($simURL, false, $context);
        if ($response === false) return 'hud_offline';

        // Sleep between steps (not after the last one)
        if ($i < count($sequence) - 1) {
            usleep((int)($STEP_DELAY * 1_000_000));
        }
    }
    return null;
}

// ============================================================
// WEAR
// ============================================================
// POST /api.php?action=wear
// Fields: outfit_id  (from web session — no access_uuid needed,
//         the session already proves identity)
//
// Looks up the outfit's folder_path, then POSTs a wear command
// to the HUD's current sim_url. The HUD (WebRelay) validates
// the access_uuid we send and routes the command to Core.
//
// Returns:
//   200 {"status":"ok"}          — command delivered to HUD
//   400 {"error":"..."}          — missing/invalid fields
//   403 {"error":"forbidden"}    — not logged in / not your outfit
//   404 {"error":"not found"}    — outfit id doesn't exist
//   503 {"error":"hud_offline"}  — sim_url empty or HUD not responding
// ============================================================

function api_wear(PDO $pdo): void
{
    // ── Must be logged in via session ────────────────────────
    require_once __DIR__ . '/auth.php';
    auth_start();
    $accessUUID = auth_uuid();
    if ($accessUUID === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    $outfitId = (int)($_POST['outfit_id'] ?? 0);
    if ($outfitId === 0) {
        http_response_code(400);
        echo json_encode(['error' => 'outfit_id is required']);
        return;
    }

    // ── Fetch main outfit + user removal defaults ────────────
    $stmt = $pdo->prepare('
        SELECT o.folder_path, o.wear_mode, o.locked,
               o.remove_before_wear, o.removal_points,
               o.base_outfits, o.additional_items,
               u.sim_url, u.last_seen, u.default_removal_points
        FROM outfits o
        JOIN users u ON u.access_uuid = o.user_uuid
        WHERE o.id = ? AND o.user_uuid = ?
    ');
    $stmt->execute([$outfitId, $accessUUID]);
    $row = $stmt->fetch();

    if (!$row) {
        http_response_code(404);
        echo json_encode(['error' => 'outfit not found']);
        return;
    }

    // ── Refuse to wear a locked outfit ──────────────────────
    if (!empty($row['locked'])) {
        http_response_code(403);
        echo json_encode(['error' => 'outfit_locked']);
        return;
    }

    // ── Check HUD is reachable (last_seen within 10 minutes) ─
    $age = time() - (int)$row['last_seen'];
    if ($row['sim_url'] === '' || $age > 600) {
        http_response_code(503);
        echo json_encode(['error' => 'hud_offline']);
        return;
    }

    // wear_mode from POST overrides stored value — allows web panel to
    // send the currently selected mode without saving it first
    $wearMode = trim($_POST['wear_mode'] ?? '') ?: ($row['wear_mode'] ?: 'subfolders_replace');
    $validModes = ['folder_add', 'folder_replace', 'subfolders_add', 'subfolders_replace'];
    if (!in_array($wearMode, $validModes, true)) $wearMode = 'subfolders_replace';

    // ── Build the wear sequence ───────────────────────────────
    // Order: base outfits (in stored order) → main outfit → additional items
    $simURL        = $row['sim_url'];
    $defaultPoints = $row['default_removal_points'] ?? '';
    $sequence      = [];

    foreach (resolve_outfit_ids($pdo, $row['base_outfits'] ?? '', $accessUUID) as $bo) {
        $sequence[] = $bo;
    }

    // Main outfit — use the POSTed wear_mode override
    $mainRow              = $row;
    $mainRow['wear_mode'] = $wearMode;
    $sequence[]           = $mainRow;

    foreach (resolve_outfit_ids($pdo, $row['additional_items'] ?? '', $accessUUID) as $ai) {
        $sequence[] = $ai;
    }

    $error = send_wear_sequence($sequence, $simURL, $accessUUID, $defaultPoints);
    if ($error !== null) {
        http_response_code(503);
        echo json_encode(['error' => $error]);
        return;
    }

    http_response_code(200);
    echo json_encode(['status' => 'ok']);
}

// ============================================================
// OUTFIT CREATE
// ============================================================
// POST /api.php?action=outfit_create
// Fields: access_uuid, folder_path, outfit_name, attachments,
//         has_space_warning
//
// Creates a new outfit record for this user.
// Returns 409 Conflict if an outfit with this folder_path
// already exists for this user — the HUD reports this clearly
// so the user knows to delete the old record first.
// ============================================================

function api_outfit_create(PDO $pdo): void
{
    $accessUUID      = trim($_POST['access_uuid']      ?? '');
    $folderPath      = trim($_POST['folder_path']      ?? '');
    $outfitName      = trim($_POST['outfit_name']      ?? '');
    $attachments     = trim($_POST['attachments']      ?? '[]');
    $hasSpaceWarning = (int)($_POST['has_space_warning'] ?? 0);

    // ── Validate required fields ─────────────────────────────
    if ($accessUUID === '') {
        http_response_code(400);
        echo json_encode(['error' => 'access_uuid is required']);
        return;
    }

    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $accessUUID)) {
        http_response_code(400);
        echo json_encode(['error' => 'access_uuid format invalid']);
        return;
    }

    if ($folderPath === '') {
        http_response_code(400);
        echo json_encode(['error' => 'folder_path is required']);
        return;
    }

    // ── Verify user exists ───────────────────────────────────
    $stmt = $pdo->prepare('SELECT access_uuid FROM users WHERE access_uuid = ?');
    $stmt->execute([$accessUUID]);
    if (!$stmt->fetch()) {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    // ── Validate attachments is at least plausible JSON ──────
    // We store whatever the HUD sends; malformed JSON won't break
    // the database but we log it for diagnostics
    if ($attachments !== '' && json_decode($attachments) === null) {
        error_log('Ensemble: malformed attachments JSON from ' . $accessUUID);
        $attachments = '[]';
    }

    // ── Default outfit name if empty ─────────────────────────
    if ($outfitName === '') {
        $parts      = explode('/', $folderPath);
        $outfitName = str_replace('_', ' ', end($parts));
    }

    $now = time();

    // ── Insert — UNIQUE constraint on (user_uuid, folder_path) ─
    try {
        $stmt = $pdo->prepare('
            INSERT INTO outfits
                (user_uuid, folder_path, outfit_name, attachments,
                 has_space_warning, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ');
        $stmt->execute([
            $accessUUID,
            $folderPath,
            $outfitName,
            $attachments,
            $hasSpaceWarning ? 1 : 0,
            $now,
        ]);
    } catch (PDOException $e) {
        // UNIQUE constraint violation — outfit already exists
        if (strpos($e->getMessage(), 'UNIQUE') !== false) {
            http_response_code(409);
            echo json_encode(['error' => 'outfit already exists for this folder path']);
            return;
        }
        throw $e;  // re-throw anything unexpected
    }

    http_response_code(200);
    echo json_encode([
        'status'      => 'ok',
        'outfit_name' => $outfitName,
    ]);
}

// ============================================================
// OUTFIT CREATE (WEB)
// ============================================================
// POST /api.php?action=outfit_create_web
// Fields: folder_path, outfit_name (optional), tags, comments,
//         access_level, wear_mode, base_outfits, additional_items,
//         remove_before_wear, removal_points
//
// Creates a new outfit from the website UI — no HUD involved.
// Auth via session + CSRF (same as outfit_update).
// folder_path is required; outfit_name is derived from the last
// path component if left blank.
//
// Returns:
//   200 {"status":"ok","outfit_id":N,"outfit_name":"..."}
//   400 {"error":"..."}   — missing/invalid fields
//   403 {"error":"forbidden"} — not logged in / bad CSRF
//   409 {"error":"..."}  — outfit already exists for this path
// ============================================================

function api_outfit_create_web(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();

    $userUUID = auth_uuid();
    if ($userUUID === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();

    $folderPath  = trim($_POST['folder_path']  ?? '');
    $outfitName  = trim($_POST['outfit_name']  ?? '');
    $tags        = trim($_POST['tags']         ?? '');
    $comments    = trim($_POST['comments']     ?? '');
    $accessLevel = trim($_POST['access_level'] ?? 'public');
    $wearMode    = trim($_POST['wear_mode']    ?? 'subfolders_replace');
    $baseOutfits     = trim($_POST['base_outfits']     ?? '');
    $additionalItems = trim($_POST['additional_items'] ?? '');
    $wearAfterRemove = trim($_POST['wear_after_remove'] ?? '');
    $removeBeforeWear = isset($_POST['remove_before_wear']) ? (int)(bool)$_POST['remove_before_wear'] : 0;
    $removalPoints    = trim($_POST['removal_points'] ?? '');

    if ($folderPath === '') {
        http_response_code(400);
        echo json_encode(['error' => 'folder_path is required']);
        return;
    }

    // Derive name from last path component if not supplied
    if ($outfitName === '') {
        $parts      = explode('/', $folderPath);
        $outfitName = str_replace('_', ' ', end($parts));
    }

    // Whitelist access_level and wear_mode
    $validAccess   = ['public', 'private'];
    $validWearMode = ['folder_add', 'folder_replace', 'subfolders_add', 'subfolders_replace'];
    if (!in_array($accessLevel, $validAccess, true))   $accessLevel = 'public';
    if (!in_array($wearMode,    $validWearMode, true)) $wearMode    = 'subfolders_replace';

    // Validate removal_points — must be empty or a valid JSON array
    if ($removalPoints !== '') {
        $decoded = json_decode($removalPoints, true);
        if (!is_array($decoded)) $removalPoints = '';
    }

    // has_space_warning: flag if any path component contains a space
    $hasSpaceWarning = (int)(strpos($folderPath, ' ') !== false);

    $now = time();

    try {
        $stmt = $pdo->prepare('
            INSERT INTO outfits
                (user_uuid, folder_path, outfit_name, attachments,
                 has_space_warning, tags, comments, access_level,
                 wear_mode, base_outfits, additional_items, wear_after_remove,
                 remove_before_wear, removal_points, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');
        $stmt->execute([
            $userUUID,
            $folderPath,
            $outfitName,
            '[]',               // no attachments — created from web, not HUD scan
            $hasSpaceWarning,
            $tags,
            $comments,
            $accessLevel,
            $wearMode,
            $baseOutfits,
            $additionalItems,
            $wearAfterRemove,
            $removeBeforeWear,
            $removalPoints,
            $now,
        ]);
    } catch (PDOException $e) {
        if (strpos($e->getMessage(), 'UNIQUE') !== false) {
            http_response_code(409);
            echo json_encode(['error' => 'An outfit with this path already exists.']);
            return;
        }
        throw $e;
    }

    $outfitId = (int)$pdo->lastInsertId();

    http_response_code(200);
    echo json_encode([
        'status'      => 'ok',
        'outfit_id'   => $outfitId,
        'outfit_name' => $outfitName,
    ]);
}

// ============================================================
// CHECKIN
// ============================================================
// POST /api.php?action=checkin
// Fields: access_uuid, username, sim_url, owner_uuid, region_name, hud_locked (optional)
//
// Used for both initial HUD checkin and every subsequent
// heartbeat — the effect is identical: keep sim_url and
// last_seen current. The 'new_user' flag in the response
// lets the HUD say "Account created" vs "Connected".
//
// owner_uuid is the avatar's permanent grid UUID. It is stored
// on every checkin and used as a hard-match security check on
// backup restore. It cannot be changed by the user.
//
// region_name is the human-readable name of the region the HUD
// is currently in (e.g. "Tempura Island"). Stored for display
// in the Account modal alongside the raw sim_url.
//
// hud_locked is 1 if the wearer currently has an RLV restriction
// preventing them from detaching the HUD; 0 otherwise. Sent on
// every heartbeat so the web panel can show current lock status.
// Older HUD versions that don't send this field default to 0.
//
// core_version and relay_version are the version strings of the
// Core and WebRelay scripts (e.g. "0.24", "0.11"). Stored on every
// checkin for display in the Account section and support purposes.
// Absent in HUDs predating Core v0.24 — stored as empty string.
// ============================================================

function api_checkin(PDO $pdo): void
{
    // ── Validate required fields ─────────────────────────────
    $accessUUID  = trim($_POST['access_uuid']  ?? '');
    $username    = trim($_POST['username']     ?? '');
    $simURL      = trim($_POST['sim_url']      ?? '');
    $ownerUUID   = trim($_POST['owner_uuid']   ?? '');
    $regionName  = trim($_POST['region_name']  ?? '');
    // hud_locked is optional — defaults to 0 if not sent (e.g. older HUD versions)
    $hudLocked    = isset($_POST['hud_locked']) ? (int)(bool)$_POST['hud_locked'] : 0;
    // core_version and relay_version — optional, absent in HUDs pre-v0.24
    $coreVersion  = substr(trim($_POST['core_version']  ?? ''), 0, 20);
    $relayVersion = substr(trim($_POST['relay_version'] ?? ''), 0, 20);

    if ($accessUUID === '') {
        http_response_code(400);
        echo json_encode(['error' => 'access_uuid is required']);
        return;
    }

    // access_uuid is the avatar's plain owner UUID (standard hyphenated format
    // from llGetOwner()): xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $accessUUID)) {
        http_response_code(400);
        echo json_encode(['error' => 'access_uuid format invalid']);
        return;
    }

    // ── Access code gate ─────────────────────────────────────
    // If ACCESS_CODE is configured, reject any HUD that does not send
    // the matching code. HUDs without a code set (older versions or
    // unconfigured) will send an empty string and fail if a code is required.
    if (ACCESS_CODE !== '') {
        $sentCode = trim($_POST['access_code'] ?? '');
        if ($sentCode !== ACCESS_CODE) {
            http_response_code(403);
            echo json_encode(['error' => 'access_code_mismatch']);
            return;
        }
    }

    $now = time();

    // ── Check if this user already exists ────────────────────
    $stmt = $pdo->prepare('SELECT access_uuid, pw_set FROM users WHERE access_uuid = ?');
    $stmt->execute([$accessUUID]);
    $existing = $stmt->fetch();
    $isNew    = ($existing === false);
    // For existing users, report whether they have a real password set.
    // The HUD uses this to skip sending a new temp password on link account.
    $pwSet = $isNew ? 0 : (int)$existing['pw_set'];

    if ($isNew) {
        // ── New user: insert record ───────────────────────────
        $stmt = $pdo->prepare('
            INSERT INTO users (access_uuid, username, sim_url, last_seen, created_at, owner_uuid, region_name, hud_locked, core_version, relay_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');
        $stmt->execute([$accessUUID, $username, $simURL, $now, $now, $ownerUUID, $regionName, $hudLocked, $coreVersion, $relayVersion]);
    } else {
        // ── Returning user: update sim_url, last_seen, username, owner_uuid, region_name, hud_locked
        // Username changes are rare but possible; owner_uuid is immutable in
        // practice but we update it in case an older HUD version omitted it.
        $stmt = $pdo->prepare('
            UPDATE users
            SET sim_url       = ?,
                last_seen     = ?,
                username      = ?,
                owner_uuid    = ?,
                region_name   = ?,
                hud_locked    = ?,
                core_version  = ?,
                relay_version = ?
            WHERE access_uuid = ?
        ');
        $stmt->execute([$simURL, $now, $username, $ownerUUID, $regionName, $hudLocked, $coreVersion, $relayVersion, $accessUUID]);
    }

    // ── Return locked outfit folders with wear_mode ─────────
    // The HUD re-issues @detachthis/@detachallthis on every heartbeat
    // so locks survive relog and region crossing.
    // wear_mode determines which command to use:
    //   subfolders_* → @detachallthis (locks all subfolders)
    //   folder_*     → @detachthis    (locks top-level folder only)
    $lockedStmt = $pdo->prepare('SELECT folder_path, wear_mode FROM outfits WHERE user_uuid = ? AND locked = 1');
    $lockedStmt->execute([$accessUUID]);
    $lockedFolders = array_map(function($row) {
        return ['folder' => $row['folder_path'], 'wear_mode' => $row['wear_mode']];
    }, $lockedStmt->fetchAll());

    http_response_code(200);
    echo json_encode([
        'status'         => 'ok',
        'new_user'       => $isNew,
        'pw_set'         => $pwSet,   // 1 = user has a real password; 0 = temp only or new account
        'locked_folders' => $lockedFolders,
    ]);
}
// ============================================================
// OUTFIT DELETE
// ============================================================
// POST /api.php?action=outfit_delete
// Fields: outfit_id
//
// Deletes an outfit belonging to the currently logged-in user.
// Ownership is validated via the session — a user can only
// delete their own outfits.
//
// Returns:
//   200 {"status":"ok"}
//   400 {"error":"..."}   — missing field
//   403 {"error":"forbidden"} — not logged in or not your outfit
//   404 {"error":"not_found"} — outfit doesn't exist
// ============================================================

function api_outfit_delete(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();

    $userUUID = auth_uuid();
    if ($userUUID === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    $outfitId = (int)($_POST['outfit_id'] ?? 0);
    if ($outfitId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing outfit_id']);
        return;
    }

    // Verify ownership and fetch image filename before deleting
    $stmt = $pdo->prepare('SELECT id, image_filename FROM outfits WHERE id = ? AND user_uuid = ?');
    $stmt->execute([$outfitId, $userUUID]);
    $outfit = $stmt->fetch();
    if (!$outfit) {
        http_response_code(404);
        echo json_encode(['error' => 'not_found']);
        return;
    }

    $stmt = $pdo->prepare('DELETE FROM outfits WHERE id = ? AND user_uuid = ?');
    $stmt->execute([$outfitId, $userUUID]);

    // ── Clean up image file if one existed ───────────────────
    // Image is stored in the user's own subdirectory under uploads/
    if ($outfit['image_filename']) {
        $imagePath = UPLOADS_DIR . $userUUID . '/' . $outfit['image_filename'];
        if (file_exists($imagePath)) {
            @unlink($imagePath);
        }
    }

    http_response_code(200);
    echo json_encode(['status' => 'ok']);
}

// ============================================================
// OUTFIT UPDATE
// ============================================================
// POST /api.php?action=outfit_update
// Fields: outfit_id, outfit_name, folder_path, tags, comments,
//         access_level, wear_mode, base_outfits, additional_items,
//         remove_before_wear, removal_points
//
// Updates the editable properties of an existing outfit.
// folder_path may be submitted without a leading #RLV/ prefix —
// the server normalises it. has_space_warning is recalculated.
// Ownership validated via session.
//
// Returns:
//   200 {"status":"ok"}
//   400 {"error":"..."}
//   403 {"error":"forbidden"}
//   404 {"error":"not_found"}
// ============================================================

function api_outfit_update(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();

    $userUUID = auth_uuid();
    if ($userUUID === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    $outfitId = (int)($_POST['outfit_id'] ?? 0);
    if ($outfitId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing outfit_id']);
        return;
    }

    // Verify ownership
    $stmt = $pdo->prepare('SELECT id, folder_path FROM outfits WHERE id = ? AND user_uuid = ?');
    $stmt->execute([$outfitId, $userUUID]);
    $existing = $stmt->fetch();
    if (!$existing) {
        http_response_code(404);
        echo json_encode(['error' => 'not_found']);
        return;
    }

    // Sanitise and validate inputs
    $outfitName        = trim($_POST['outfit_name']        ?? '');
    $tags              = trim($_POST['tags']               ?? '');
    $comments          = trim($_POST['comments']           ?? '');
    $accessLevel       = trim($_POST['access_level']       ?? 'public');
    $wearMode          = trim($_POST['wear_mode']          ?? 'folder_only');
    $baseOutfits       = trim($_POST['base_outfits']       ?? '');
    $additionalItems   = trim($_POST['additional_items']   ?? '');
    $wearAfterRemove   = trim($_POST['wear_after_remove']  ?? '');
    $removeBeforeWear  = isset($_POST['remove_before_wear']) ? (int)(bool)$_POST['remove_before_wear'] : 0;
    // removal_points: JSON array of ints, or empty string (= use defaults)
    $removalPoints     = trim($_POST['removal_points'] ?? '');
    // Validate: must be empty or a valid JSON array of integers
    if ($removalPoints !== '') {
        $decoded = json_decode($removalPoints, true);
        if (!is_array($decoded)) $removalPoints = '';
    }

    // ── folder_path: optional edit ────────────────────────────
    // Store exactly what the user submits — no prefix manipulation.
    // The wear/remove commands use folder_path verbatim from the DB,
    // so we must not transform it here. Fall back to existing if empty.
    if (isset($_POST['folder_path']) && trim($_POST['folder_path']) !== '') {
        $folderPath = trim($_POST['folder_path']);
    } else {
        $folderPath = $existing['folder_path'];
    }

    // Recalculate has_space_warning based on the final path
    // (warning if any path component contains a space)
    $hasSpaceWarning = (int)(strpos($folderPath, ' ') !== false);

    // Whitelist access_level and wear_mode to prevent arbitrary values
    $validAccess   = ['public', 'private'];
    $validWearMode = ['folder_add', 'folder_replace', 'subfolders_add', 'subfolders_replace'];

    if (!in_array($accessLevel, $validAccess, true)) {
        $accessLevel = 'public';
    }
    if (!in_array($wearMode, $validWearMode, true)) {
        $wearMode = 'subfolders_replace';
    }

    $stmt = $pdo->prepare('
        UPDATE outfits
        SET outfit_name        = ?,
            folder_path        = ?,
            has_space_warning  = ?,
            tags               = ?,
            comments           = ?,
            access_level       = ?,
            wear_mode          = ?,
            base_outfits       = ?,
            additional_items   = ?,
            wear_after_remove  = ?,
            remove_before_wear = ?,
            removal_points     = ?
        WHERE id = ? AND user_uuid = ?
    ');
    $stmt->execute([
        $outfitName,
        $folderPath,
        $hasSpaceWarning,
        $tags,
        $comments,
        $accessLevel,
        $wearMode,
        $baseOutfits,
        $additionalItems,
        $wearAfterRemove,
        $removeBeforeWear,
        $removalPoints,
        $outfitId,
        $userUUID,
    ]);

    http_response_code(200);
    echo json_encode(['status' => 'ok']);
}
// ============================================================
// OUTFIT IMAGE UPLOAD
// ============================================================
// POST /api.php?action=outfit_image_upload
// Fields: outfit_id (POST), image (FILE)
//
// Accepts JPEG, PNG, or WebP up to 2 MB.
// Resizes to fit within 800×800 (preserving aspect ratio).
// Saves to UPLOADS_DIR with a random filename.
// Deletes the previous image file if one existed.
// Updates image_filename in the database.
//
// Returns:
//   200 {"status":"ok", "filename":"abc123.jpg"}
//   400 {"error":"..."}
//   403 {"error":"forbidden"}
//   404 {"error":"not_found"}
//   422 {"error":"..."}  — invalid image
// ============================================================

function api_outfit_image_upload(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();

    $userUUID = auth_uuid();
    if ($userUUID === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    $outfitId = (int)($_POST['outfit_id'] ?? 0);
    if ($outfitId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'Missing outfit_id']);
        return;
    }

    // ── Verify ownership and get current image filename ──────
    $stmt = $pdo->prepare('SELECT id, image_filename FROM outfits WHERE id = ? AND user_uuid = ?');
    $stmt->execute([$outfitId, $userUUID]);
    $outfit = $stmt->fetch();
    if (!$outfit) {
        http_response_code(404);
        echo json_encode(['error' => 'not_found']);
        return;
    }

    // ── Validate uploaded file ────────────────────────────────
    if (empty($_FILES['image']) || $_FILES['image']['error'] !== UPLOAD_ERR_OK) {
        $uploadErrors = [
            UPLOAD_ERR_INI_SIZE   => 'File exceeds server upload limit.',
            UPLOAD_ERR_FORM_SIZE  => 'File exceeds form size limit.',
            UPLOAD_ERR_PARTIAL    => 'File was only partially uploaded.',
            UPLOAD_ERR_NO_FILE    => 'No file was uploaded.',
            UPLOAD_ERR_NO_TMP_DIR => 'Server temporary directory missing.',
            UPLOAD_ERR_CANT_WRITE => 'Server could not write file.',
            UPLOAD_ERR_EXTENSION  => 'Upload blocked by server extension.',
        ];
        $errCode = $_FILES['image']['error'] ?? UPLOAD_ERR_NO_FILE;
        http_response_code(400);
        echo json_encode(['error' => $uploadErrors[$errCode] ?? 'Upload failed.']);
        return;
    }

    $tmpPath  = $_FILES['image']['tmp_name'];
    $fileSize = $_FILES['image']['size'];

    // 2 MB limit
    if ($fileSize > 2 * 1024 * 1024) {
        http_response_code(422);
        echo json_encode(['error' => 'File must be under 2 MB.']);
        return;
    }

    // Validate image type via GD (not just MIME header — more secure)
    $imageInfo = @getimagesize($tmpPath);
    if (!$imageInfo) {
        http_response_code(422);
        echo json_encode(['error' => 'File does not appear to be a valid image.']);
        return;
    }

    $allowedTypes = [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_WEBP];
    if (!in_array($imageInfo[2], $allowedTypes, true)) {
        http_response_code(422);
        echo json_encode(['error' => 'Only JPEG, PNG, and WebP images are accepted.']);
        return;
    }

    // ── Load image via GD ─────────────────────────────────────
    $srcImage = match($imageInfo[2]) {
        IMAGETYPE_JPEG => imagecreatefromjpeg($tmpPath),
        IMAGETYPE_PNG  => imagecreatefrompng($tmpPath),
        IMAGETYPE_WEBP => imagecreatefromwebp($tmpPath),
        default        => false,
    };

    if (!$srcImage) {
        http_response_code(422);
        echo json_encode(['error' => 'Could not read image data.']);
        return;
    }

    // ── Resize to fit within 800×800 (preserve aspect ratio) ─
    $srcW = imagesx($srcImage);
    $srcH = imagesy($srcImage);

    $maxDim = 800;
    if ($srcW > $maxDim || $srcH > $maxDim) {
        $ratio  = min($maxDim / $srcW, $maxDim / $srcH);
        $dstW   = (int)round($srcW * $ratio);
        $dstH   = (int)round($srcH * $ratio);
    } else {
        // Already within limits — use original dimensions
        $dstW = $srcW;
        $dstH = $srcH;
    }

    $dstImage = imagecreatetruecolor($dstW, $dstH);

    // Preserve transparency for PNG
    if ($imageInfo[2] === IMAGETYPE_PNG) {
        imagealphablending($dstImage, false);
        imagesavealpha($dstImage, true);
        $transparent = imagecolorallocatealpha($dstImage, 0, 0, 0, 127);
        imagefilledrectangle($dstImage, 0, 0, $dstW, $dstH, $transparent);
    }

    imagecopyresampled($dstImage, $srcImage, 0, 0, 0, 0, $dstW, $dstH, $srcW, $srcH);
    imagedestroy($srcImage);

    // ── Ensure per-user uploads directory exists ─────────────
    // Images are stored under UPLOADS_DIR/<user_uuid>/ so each user's
    // files are isolated. The filename alone is stored in the DB;
    // the path is reconstructed at serve time from the known user UUID.
    $userUploadDir = UPLOADS_DIR . $userUUID . '/';
    if (!is_dir($userUploadDir)) {
        mkdir($userUploadDir, 0750, true);
    }

    // ── Generate unique filename and save ────────────────────
    // Always save as JPEG for consistency (smaller, universally supported)
    $newFilename = bin2hex(random_bytes(16)) . '.jpg';
    $destPath    = $userUploadDir . $newFilename;

    if (!imagejpeg($dstImage, $destPath, 85)) {
        imagedestroy($dstImage);
        http_response_code(500);
        echo json_encode(['error' => 'Could not save image to disk.']);
        return;
    }

    imagedestroy($dstImage);

    // ── Delete old image file if one existed ─────────────────
    $oldFilename = $outfit['image_filename'];
    if ($oldFilename) {
        $oldPath = $userUploadDir . $oldFilename;
        if (file_exists($oldPath)) {
            @unlink($oldPath);
        }
    }

    // ── Update database ───────────────────────────────────────
    $stmt = $pdo->prepare('UPDATE outfits SET image_filename = ? WHERE id = ? AND user_uuid = ?');
    $stmt->execute([$newFilename, $outfitId, $userUUID]);

    http_response_code(200);
    echo json_encode(['status' => 'ok', 'filename' => $newFilename]);
}
// ============================================================
// REMOVE OUTFIT
// ============================================================
// POST /api.php?action=remove
// Fields: outfit_id
//
// Sends a remove command to the HUD, which issues:
//   @detach:folderPath=force
//
// If the outfit has a wear_after_remove list, each outfit in
// that list is worn (in order, with full dressing policy) after
// the remove command succeeds. This only fires when the Remove
// button is used — not for in-world removal or sequence-based
// removal.
//
// Returns:
//   200 {"status":"ok"}
//   400 {"error":"..."}
//   403 {"error":"forbidden"}
//   404 {"error":"outfit not found"}
//   503 {"error":"hud_offline"}
// ============================================================

function api_remove(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();

    $accessUUID = auth_uuid();
    if ($accessUUID === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    $outfitId = (int)($_POST['outfit_id'] ?? 0);
    if ($outfitId === 0) {
        http_response_code(400);
        echo json_encode(['error' => 'outfit_id is required']);
        return;
    }

    // ── Fetch outfit and sim URL — must belong to this user ──
    $stmt = $pdo->prepare('
        SELECT o.folder_path, o.wear_mode, o.locked, o.wear_after_remove,
               u.sim_url, u.last_seen, u.default_removal_points
        FROM outfits o
        JOIN users u ON u.access_uuid = o.user_uuid
        WHERE o.id = ? AND o.user_uuid = ?
    ');
    $stmt->execute([$outfitId, $accessUUID]);
    $row = $stmt->fetch();

    if (!$row) {
        http_response_code(404);
        echo json_encode(['error' => 'outfit not found']);
        return;
    }

    // ── Refuse to remove a locked outfit ─────────────────────
    if (!empty($row['locked'])) {
        http_response_code(403);
        echo json_encode(['error' => 'outfit_locked']);
        return;
    }

    // ── Check HUD is reachable ────────────────────────────────
    $age = time() - (int)$row['last_seen'];
    if ($row['sim_url'] === '' || $age > 600) {
        http_response_code(503);
        echo json_encode(['error' => 'hud_offline']);
        return;
    }

    // Normalise wear_mode — legacy rows default to subfolders_replace
    $validModes = ['folder_add', 'folder_replace', 'subfolders_add', 'subfolders_replace'];
    $wearMode   = in_array($row['wear_mode'], $validModes, true) ? $row['wear_mode'] : 'subfolders_replace';

    // ── POST remove command to HUD sim URL ────────────────────
    $postBody = http_build_query([
        'access_uuid' => $accessUUID,
        'command'     => 'remove',
        'folder'      => $row['folder_path'],
        'wear_mode'   => $wearMode,
    ]);

    $context = stream_context_create([
        'http' => [
            'method'        => 'POST',
            'header'        => "Content-Type: application/x-www-form-urlencoded\r\n"
                             . "Content-Length: " . strlen($postBody) . "\r\n",
            'content'       => $postBody,
            'timeout'       => 8,
            'ignore_errors' => true,
        ]
    ]);

    $response = @file_get_contents($row['sim_url'], false, $context);

    if ($response === false) {
        http_response_code(503);
        echo json_encode(['error' => 'hud_offline']);
        return;
    }

    // ── Wear-after-remove sequence ────────────────────────────
    // Each outfit in wear_after_remove is worn exactly as if its
    // own Wear button had been pressed — full dressing policy
    // (base outfits → main → additional items) via send_wear_sequence.
    $afterRaw = $row['wear_after_remove'] ?? '';
    if ($afterRaw !== '' && $afterRaw !== '[]') {
        $simURL        = $row['sim_url'];
        $defaultPoints = $row['default_removal_points'] ?? '';

        foreach (resolve_outfit_ids($pdo, $afterRaw, $accessUUID) as $afterOutfit) {
            // Fetch the full outfit row so we can build its own wear sequence
            $stmt2 = $pdo->prepare('
                SELECT id, folder_path, wear_mode, locked,
                       remove_before_wear, removal_points,
                       base_outfits, additional_items
                FROM outfits
                WHERE id = ? AND user_uuid = ?
            ');
            $stmt2->execute([(int)$afterOutfit['id'], $accessUUID]);
            $fullRow = $stmt2->fetch();
            if (!$fullRow || !empty($fullRow['locked'])) continue;

            // Build the full wear sequence for this outfit
            $sequence = [];
            foreach (resolve_outfit_ids($pdo, $fullRow['base_outfits'] ?? '', $accessUUID) as $bo) {
                $sequence[] = $bo;
            }
            $sequence[] = $fullRow;
            foreach (resolve_outfit_ids($pdo, $fullRow['additional_items'] ?? '', $accessUUID) as $ai) {
                $sequence[] = $ai;
            }

            // A 1.5 s gap before the first after-remove outfit gives RLV time
            // to finish processing the removal
            usleep(1_500_000);

            // If HUD goes offline mid-sequence, stop silently — the remove
            // itself already succeeded so we return 200 regardless
            $err = send_wear_sequence($sequence, $simURL, $accessUUID, $defaultPoints);
            if ($err !== null) break;
        }
    }

    http_response_code(200);
    echo json_encode(['status' => 'ok']);
}

// ============================================================
// OUTFIT LOCK
// ============================================================
// POST /api.php?action=outfit_lock
// Fields: outfit_id, lock (1=lock, 0=unlock)
//
// Sets or clears the locked flag for an outfit.
// On lock:   sets locked=1 in DB, sends @detachthis command to HUD.
// On unlock: sets locked=0 in DB, sends @detachthis=y release to HUD.
//
// HUD command is best-effort — if HUD is offline the DB change
// still succeeds. On lock, the HUD will re-apply on next heartbeat.
// On unlock, the restriction will lapse on next relog if HUD is offline.
//
// Returns:
//   200 {"status":"ok"}
//   400 {"error":"..."}
//   403 {"error":"forbidden"}
//   404 {"error":"not_found"}
// ============================================================

function api_outfit_lock(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();

    $userUUID = auth_uuid();
    if ($userUUID === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    $outfitId = (int)($_POST['outfit_id'] ?? 0);
    if ($outfitId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'outfit_id is required']);
        return;
    }

    $lock = (int)($_POST['lock'] ?? 0) === 1 ? 1 : 0;

    // ── Fetch outfit and sim URL ──────────────────────────────
    $stmt = $pdo->prepare('
        SELECT o.folder_path, o.wear_mode, u.sim_url, u.last_seen
        FROM outfits o
        JOIN users u ON u.access_uuid = o.user_uuid
        WHERE o.id = ? AND o.user_uuid = ?
    ');
    $stmt->execute([$outfitId, $userUUID]);
    $row = $stmt->fetch();

    if (!$row) {
        http_response_code(404);
        echo json_encode(['error' => 'not_found']);
        return;
    }

    // ── Update lock state in database ────────────────────────
    $stmt = $pdo->prepare('UPDATE outfits SET locked = ? WHERE id = ? AND user_uuid = ?');
    $stmt->execute([$lock, $outfitId, $userUUID]);

    // ── Send RLV command to HUD (best-effort) ─────────────────
    // n = lock, y = release
    $rlvValue  = $lock ? 'n' : 'y';
    $rlvAction = $lock ? 'lock' : 'unlock';

    $age = time() - (int)$row['last_seen'];
    $hudOnline = ($row['sim_url'] !== '' && $age <= 600);

    if ($hudOnline) {
        $postBody = http_build_query([
            'access_uuid' => $userUUID,
            'command'     => 'rlv_lock',
            'folder'      => $row['folder_path'],
            'wear_mode'   => $row['wear_mode'],
            'rlv_value'   => $rlvValue,
        ]);

        $context = stream_context_create([
            'http' => [
                'method'        => 'POST',
                'header'        => "Content-Type: application/x-www-form-urlencoded\r\n"
                                 . "Content-Length: " . strlen($postBody) . "\r\n",
                'content'       => $postBody,
                'timeout'       => 8,
                'ignore_errors' => true,
            ]
        ]);

        @file_get_contents($row['sim_url'], false, $context);
        // Intentionally ignore HUD response — DB is the source of truth
    }

    http_response_code(200);
    echo json_encode([
        'status'     => 'ok',
        'locked'     => $lock,
        'hud_online' => $hudOnline,
    ]);
}

// ============================================================
// OUTFIT FORCE UNLOCK
// ============================================================
// POST /api.php?action=outfit_force_unlock
// Fields: outfit_id
//
// Emergency escape hatch — clears locked=0 in the database
// unconditionally and attempts to release the RLV restriction
// if the HUD is online. Works even if the normal unlock flow
// is broken.
//
// Returns:
//   200 {"status":"ok"}
//   400 {"error":"..."}
//   403 {"error":"forbidden"}
//   404 {"error":"not_found"}
// ============================================================

function api_outfit_force_unlock(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();

    $userUUID = auth_uuid();
    if ($userUUID === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    $outfitId = (int)($_POST['outfit_id'] ?? 0);
    if ($outfitId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'outfit_id is required']);
        return;
    }

    // ── Fetch outfit ──────────────────────────────────────────
    $stmt = $pdo->prepare('
        SELECT o.folder_path, o.wear_mode, u.sim_url, u.last_seen
        FROM outfits o
        JOIN users u ON u.access_uuid = o.user_uuid
        WHERE o.id = ? AND o.user_uuid = ?
    ');
    $stmt->execute([$outfitId, $userUUID]);
    $row = $stmt->fetch();

    if (!$row) {
        http_response_code(404);
        echo json_encode(['error' => 'not_found']);
        return;
    }

    // ── Clear lock in database unconditionally ────────────────
    $stmt = $pdo->prepare('UPDATE outfits SET locked = 0 WHERE id = ? AND user_uuid = ?');
    $stmt->execute([$outfitId, $userUUID]);

    // ── Attempt RLV release if HUD is reachable ───────────────
    $age       = time() - (int)$row['last_seen'];
    $hudOnline = ($row['sim_url'] !== '' && $age <= 600);

    if ($hudOnline) {
        $postBody = http_build_query([
            'access_uuid' => $userUUID,
            'command'     => 'rlv_lock',
            'folder'      => $row['folder_path'],
            'wear_mode'   => $row['wear_mode'],
            'rlv_value'   => 'y',
        ]);

        $context = stream_context_create([
            'http' => [
                'method'        => 'POST',
                'header'        => "Content-Type: application/x-www-form-urlencoded\r\n"
                                 . "Content-Length: " . strlen($postBody) . "\r\n",
                'content'       => $postBody,
                'timeout'       => 8,
                'ignore_errors' => true,
            ]
        ]);

        @file_get_contents($row['sim_url'], false, $context);
    }

    http_response_code(200);
    echo json_encode([
        'status'     => 'ok',
        'hud_online' => $hudOnline,
    ]);
}

// ============================================================
// GET WORN ITEMS
// ============================================================
// POST /api.php?action=get_worn
//
// Asks the HUD for the current list of worn attachments by
// sending a "get_worn" command to its sim_url. The HUD responds
// with a JSON array of {point, item, can_detach} objects.
//
// can_detach is determined by the HUD — body-layer wearables
// (skin, shape, eyes, hair base) cannot be detached via RLV and
// are flagged accordingly.
//
// Returns:
//   200 {"status":"ok", "items":[...]}
//   403 {"error":"forbidden"}
//   503 {"error":"hud_offline"}
// ============================================================

function api_get_worn(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();
    $userUUID = auth_uuid();
    if ($userUUID === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    // ── Get sim_url and last_seen ────────────────────────────
    $stmt = $pdo->prepare('SELECT sim_url, last_seen FROM users WHERE access_uuid = ?');
    $stmt->execute([$userUUID]);
    $row = $stmt->fetch();

    $age = time() - (int)($row['last_seen'] ?? 0);
    if (!$row || $row['sim_url'] === '' || $age > 600) {
        http_response_code(503);
        echo json_encode(['error' => 'hud_offline']);
        return;
    }

    // ── POST get_worn command to HUD ─────────────────────────
    $postBody = http_build_query([
        'access_uuid' => $userUUID,
        'command'     => 'get_worn',
    ]);

    $context = stream_context_create([
        'http' => [
            'method'        => 'POST',
            'header'        => "Content-Type: application/x-www-form-urlencoded\r\n"
                             . "Content-Length: " . strlen($postBody) . "\r\n",
            'content'       => $postBody,
            'timeout'       => 10,
            'ignore_errors' => true,
        ]
    ]);

    $response = @file_get_contents($row['sim_url'], false, $context);

    if ($response === false) {
        http_response_code(503);
        echo json_encode(['error' => 'hud_offline']);
        return;
    }

    // HUD responds with JSON: {"items":[{"point":"..","item":"..","can_detach":true}, ...]}
    $data = json_decode($response, true);
    if (!isset($data['items']) || !is_array($data['items'])) {
        http_response_code(502);
        echo json_encode(['error' => 'invalid_response']);
        return;
    }

    http_response_code(200);
    echo json_encode(['status' => 'ok', 'items' => $data['items']]);
}

// ============================================================
// WORN ITEM DETACH
// ============================================================
// POST /api.php?action=worn_detach
// Fields: point (attachment point name), item (item name)
//
// Sends a "detach_item" command to the HUD, which uses
// @detachthis on the specific attachment point.
//
// Returns:
//   200 {"status":"ok"}
//   400 {"error":"..."}
//   403 {"error":"forbidden"}
//   503 {"error":"hud_offline"}
// ============================================================

function api_worn_detach(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();
    $userUUID = auth_uuid();
    if ($userUUID === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    $point = trim($_POST['point'] ?? '');
    $item  = trim($_POST['item']  ?? '');

    if ($point === '' || $item === '') {
        http_response_code(400);
        echo json_encode(['error' => 'point and item are required']);
        return;
    }

    // ── Get sim_url ───────────────────────────────────────────
    $stmt = $pdo->prepare('SELECT sim_url, last_seen FROM users WHERE access_uuid = ?');
    $stmt->execute([$userUUID]);
    $row = $stmt->fetch();

    $age = time() - (int)($row['last_seen'] ?? 0);
    if (!$row || $row['sim_url'] === '' || $age > 600) {
        http_response_code(503);
        echo json_encode(['error' => 'hud_offline']);
        return;
    }

    // ── POST detach_item command to HUD ──────────────────────
    $postBody = http_build_query([
        'access_uuid' => $userUUID,
        'command'     => 'detach_item',
        'point'       => $point,
        'item'        => $item,
    ]);

    $context = stream_context_create([
        'http' => [
            'method'        => 'POST',
            'header'        => "Content-Type: application/x-www-form-urlencoded\r\n"
                             . "Content-Length: " . strlen($postBody) . "\r\n",
            'content'       => $postBody,
            'timeout'       => 8,
            'ignore_errors' => true,
        ]
    ]);

    $response = @file_get_contents($row['sim_url'], false, $context);

    if ($response === false) {
        http_response_code(503);
        echo json_encode(['error' => 'hud_offline']);
        return;
    }

    http_response_code(200);
    echo json_encode(['status' => 'ok']);
}

// ============================================================
// GET ACCOUNT STATUS
// ============================================================
// POST /api.php?action=get_account_status
// Fields: (none — identity from session)
//
// Returns a fresh snapshot of the current user's account data
// for the Account modal. Called when the modal opens so it
// always reflects the latest checkin, including hud_locked.
//
// Returns:
//   200 {"status":"ok", "hud_locked":0|1, "last_seen":..., ...}
//   403 {"error":"forbidden"} — not logged in
// ============================================================

function api_get_account_status(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();
    $accessUUID = auth_uuid();
    if ($accessUUID === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    $stmt = $pdo->prepare('
        SELECT username, owner_uuid, sim_url, region_name,
               last_seen, created_at, hud_locked
        FROM users
        WHERE access_uuid = ?
    ');
    $stmt->execute([$accessUUID]);
    $row = $stmt->fetch();

    if (!$row) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }

    http_response_code(200);
    echo json_encode([
        'status'      => 'ok',
        'hud_locked'  => (int)$row['hud_locked'],
        'last_seen'   => (int)$row['last_seen'],
        'region_name' => $row['region_name'],
        'sim_url'     => $row['sim_url'],
    ]);
}

// ============================================================
// GET REMOVAL DEFAULTS
// ============================================================
// POST /api.php?action=get_removal_defaults
// Returns the user's saved default_removal_points JSON array,
// or the hardcoded system defaults if not yet configured.
// ============================================================

// System default: all body + clothing points checked, HUDs unchecked.
// These are the attachment point integers from the LSL wiki.
function removal_defaults_system(): array {
    return [
        // Body
        2,  // Skull
        17, // Nose
        11, // Mouth
        52, // Tongue
        12, // Chin
        47, // Jaw
        13, // Left Ear
        14, // Right Ear
        48, // Alt Left Ear
        49, // Alt Right Ear
        15, // Left Eye
        16, // Right Eye
        50, // Alt Left Eye
        51, // Alt Right Eye
        39, // Neck
        1,  // Chest
        29, // Left Pec
        30, // Right Pec
        28, // Stomach
        9,  // Spine
        40, // Avatar Center
        10, // Pelvis
        53, // Groin
        43, // Tail Base
        44, // Tail Tip
        45, // Left Wing
        46, // Right Wing
        54, // Left Hind Foot
        55, // Right Hind Foot
        // Clothing & Accessories
        3,  // Left Shoulder
        4,  // Right Shoulder
        20, // L Upper Arm
        18, // R Upper Arm
        21, // L Lower Arm
        19, // R Lower Arm
        5,  // Left Hand
        6,  // Right Hand
        41, // Left Ring Finger
        42, // Right Ring Finger
        25, // Left Hip
        22, // Right Hip
        26, // L Upper Leg
        23, // R Upper Leg
        24, // R Lower Leg
        27, // L Lower Leg
        7,  // Left Foot
        8,  // Right Foot
        // HUDs — unchecked by default (empty — not included)
    ];
}

// ── resolve_removal_points ────────────────────────────────────
// Given an outfit row and the user's default_removal_points JSON,
// returns a comma-separated string of attachment point integers
// to pass to the HUD, or '' if remove_before_wear is off.
function resolve_removal_points(array $row, string $defaultPointsJson): string {
    if (empty($row['remove_before_wear'])) return '';
    $custom = $row['removal_points'] ?? '';
    if ($custom !== '') {
        $points = json_decode($custom, true);
    } elseif ($defaultPointsJson !== '') {
        $points = json_decode($defaultPointsJson, true);
    } else {
        $points = removal_defaults_system();
    }
    if (!is_array($points) || count($points) === 0) return '';
    return implode(',', array_map('intval', $points));
}

function api_get_removal_defaults(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();
    $uuid = auth_uuid();
    if ($uuid === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    $stmt = $pdo->prepare('SELECT default_removal_points FROM users WHERE access_uuid = ?');
    $stmt->execute([$uuid]);
    $row = $stmt->fetch();

    $saved = $row['default_removal_points'] ?? '';
    if ($saved !== '') {
        $points = json_decode($saved, true);
        if (!is_array($points)) $points = removal_defaults_system();
    } else {
        $points = removal_defaults_system();
    }

    echo json_encode(['status' => 'ok', 'points' => $points]);
}

// ============================================================
// SAVE REMOVAL DEFAULTS
// ============================================================
// POST /api.php?action=save_removal_defaults
// Fields: points — JSON array of attachment point integers
// ============================================================

function api_save_removal_defaults(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();
    $uuid = auth_uuid();
    if ($uuid === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    $raw = trim($_POST['points'] ?? '');
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        http_response_code(400);
        echo json_encode(['error' => 'points must be a JSON array']);
        return;
    }
    // Ensure all values are integers in valid range
    $clean = array_values(array_filter(array_map('intval', $decoded), function($v) {
        return $v >= 1 && $v <= 55;
    }));

    $stmt = $pdo->prepare('UPDATE users SET default_removal_points = ? WHERE access_uuid = ?');
    $stmt->execute([json_encode($clean), $uuid]);

    echo json_encode(['status' => 'ok', 'points' => $clean]);
}

// ============================================================
// LINKS LIST
// ============================================================
// POST /api.php?action=links_list
// Returns all links for the logged-in user.
//
// Returns:
//   200 {"status":"ok", "links":[...], "count":N}
//   403 {"error":"forbidden"}
// ============================================================

function api_links_list(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();
    $uuid = auth_uuid();
    if ($uuid === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    $stmt = $pdo->prepare('
        SELECT link_uuid, link_name, can_wear, include_private, created_at
        FROM links
        WHERE user_uuid = ?
        ORDER BY created_at DESC
    ');
    $stmt->execute([$uuid]);
    $links = $stmt->fetchAll();

    echo json_encode([
        'status' => 'ok',
        'links'  => $links,
        'count'  => count($links),
    ]);
}

// ============================================================
// LINK CREATE
// ============================================================
// POST /api.php?action=link_create
// Fields: link_name (optional), can_wear (0|1), include_private (0|1)
//
// Generates a new random link_uuid and inserts the row.
// Maximum 20 links per user.
//
// Returns:
//   200 {"status":"ok", "link":{...}}
//   400 {"error":"..."}
//   403 {"error":"forbidden"}
//   409 {"error":"limit_reached"}   — already at 20 links
// ============================================================

function api_link_create(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();
    $uuid = auth_uuid();
    if ($uuid === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    // ── Enforce 20-link cap ───────────────────────────────────
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM links WHERE user_uuid = ?');
    $stmt->execute([$uuid]);
    if ((int)$stmt->fetchColumn() >= LINKS_MAX) {
        http_response_code(409);
        echo json_encode(['error' => 'limit_reached']);
        return;
    }

    $linkName      = substr(trim($_POST['link_name']      ?? ''), 0, 80);
    $canWear       = (int)(bool)($_POST['can_wear']        ?? 0);
    $includePriv   = (int)(bool)($_POST['include_private'] ?? 0);

    // Generate a random link UUID (32-char hex)
    $linkUUID = bin2hex(random_bytes(16));
    $now      = time();

    $stmt = $pdo->prepare('
        INSERT INTO links (link_uuid, user_uuid, link_name, can_wear, include_private, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ');
    $stmt->execute([$linkUUID, $uuid, $linkName, $canWear, $includePriv, $now]);

    echo json_encode([
        'status' => 'ok',
        'link'   => [
            'link_uuid'       => $linkUUID,
            'link_name'       => $linkName,
            'can_wear'        => $canWear,
            'include_private' => $includePriv,
            'created_at'      => $now,
        ],
    ]);
}

// ============================================================
// LINK UPDATE
// ============================================================
// POST /api.php?action=link_update
// Fields: link_uuid, link_name (optional), can_wear (0|1), include_private (0|1)
//
// Updates an existing link. Ownership is verified.
//
// Returns:
//   200 {"status":"ok"}
//   400 {"error":"..."}
//   403 {"error":"forbidden"}
//   404 {"error":"not_found"}
// ============================================================

function api_link_update(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();
    $uuid = auth_uuid();
    if ($uuid === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    $linkUUID    = trim($_POST['link_uuid'] ?? '');
    if (!preg_match('/^[0-9a-f]{32}$/', $linkUUID)) {
        http_response_code(400);
        echo json_encode(['error' => 'link_uuid format invalid']);
        return;
    }

    // Verify ownership
    $stmt = $pdo->prepare('SELECT link_uuid FROM links WHERE link_uuid = ? AND user_uuid = ?');
    $stmt->execute([$linkUUID, $uuid]);
    if (!$stmt->fetch()) {
        http_response_code(404);
        echo json_encode(['error' => 'not_found']);
        return;
    }

    $linkName    = substr(trim($_POST['link_name']      ?? ''), 0, 80);
    $canWear     = (int)(bool)($_POST['can_wear']        ?? 0);
    $includePriv = (int)(bool)($_POST['include_private'] ?? 0);

    $stmt = $pdo->prepare('
        UPDATE links
        SET link_name = ?, can_wear = ?, include_private = ?
        WHERE link_uuid = ? AND user_uuid = ?
    ');
    $stmt->execute([$linkName, $canWear, $includePriv, $linkUUID, $uuid]);

    echo json_encode(['status' => 'ok']);
}

// ============================================================
// LINK DELETE
// ============================================================
// POST /api.php?action=link_delete
// Fields: link_uuid
//
// Returns:
//   200 {"status":"ok"}
//   400 {"error":"..."}
//   403 {"error":"forbidden"}
//   404 {"error":"not_found"}
// ============================================================

function api_link_delete(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();
    $uuid = auth_uuid();
    if ($uuid === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    $linkUUID = trim($_POST['link_uuid'] ?? '');
    if (!preg_match('/^[0-9a-f]{32}$/', $linkUUID)) {
        http_response_code(400);
        echo json_encode(['error' => 'link_uuid format invalid']);
        return;
    }

    $stmt = $pdo->prepare('DELETE FROM links WHERE link_uuid = ? AND user_uuid = ?');
    $stmt->execute([$linkUUID, $uuid]);

    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode(['error' => 'not_found']);
        return;
    }

    echo json_encode(['status' => 'ok']);
}

// ============================================================
// LINK WEAR (third-party)
// ============================================================
// POST /api.php?action=link_wear
// Fields: link_uuid, outfit_id, wear_mode (optional)
//
// Called by view.php on behalf of a link visitor (no session).
// Verifies link exists, can_wear=1, outfit belongs to the link
// owner, outfit is not locked, then forwards to the HUD.
//
// Returns:
//   200 {"status":"ok"}
//   400 {"error":"..."}
//   403 {"error":"forbidden"}   — link missing or can_wear=0
//   404 {"error":"not_found"}   — outfit not found / private + not included
//   503 {"error":"hud_offline"}
// ============================================================

function api_link_wear(PDO $pdo): void
{
    $linkUUID = trim($_POST['link_uuid'] ?? '');
    $outfitId = (int)($_POST['outfit_id'] ?? 0);

    if (!preg_match('/^[0-9a-f]{32}$/', $linkUUID) || $outfitId === 0) {
        http_response_code(400);
        echo json_encode(['error' => 'link_uuid and outfit_id are required']);
        return;
    }

    // ── Fetch link ────────────────────────────────────────────
    $stmt = $pdo->prepare('SELECT user_uuid, can_wear, include_private FROM links WHERE link_uuid = ?');
    $stmt->execute([$linkUUID]);
    $link = $stmt->fetch();

    if (!$link || !$link['can_wear']) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }

    $ownerUUID = $link['user_uuid'];

    // ── Fetch main outfit — must belong to link owner ─────────
    $stmt = $pdo->prepare('
        SELECT o.folder_path, o.wear_mode, o.locked, o.access_level,
               o.remove_before_wear, o.removal_points,
               o.base_outfits, o.additional_items,
               u.sim_url, u.last_seen, u.default_removal_points
        FROM outfits o
        JOIN users u ON u.access_uuid = o.user_uuid
        WHERE o.id = ? AND o.user_uuid = ?
    ');
    $stmt->execute([$outfitId, $ownerUUID]);
    $row = $stmt->fetch();

    if (!$row) {
        http_response_code(404);
        echo json_encode(['error' => 'not_found']);
        return;
    }

    if ($row['access_level'] === 'private' && !$link['include_private']) {
        http_response_code(404);
        echo json_encode(['error' => 'not_found']);
        return;
    }

    if (!empty($row['locked'])) {
        http_response_code(403);
        echo json_encode(['error' => 'outfit_locked']);
        return;
    }

    // ── Check HUD reachable ───────────────────────────────────
    $age = time() - (int)$row['last_seen'];
    if ($row['sim_url'] === '' || $age > 600) {
        http_response_code(503);
        echo json_encode(['error' => 'hud_offline']);
        return;
    }

    $wearMode = trim($_POST['wear_mode'] ?? '') ?: ($row['wear_mode'] ?: 'subfolders_replace');
    $validModes = ['folder_add', 'folder_replace', 'subfolders_add', 'subfolders_replace'];
    if (!in_array($wearMode, $validModes, true)) $wearMode = 'subfolders_replace';

    // ── Build wear sequence (same logic as api_wear) ──────────
    $simURL        = $row['sim_url'];
    $defaultPoints = $row['default_removal_points'] ?? '';
    $sequence      = [];

    $resolveIds = function(string $json) use ($pdo, $ownerUUID): array {
        $ids = json_decode($json, true);
        if (!is_array($ids) || count($ids) === 0) return [];
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $params       = array_merge(array_map('intval', $ids), [$ownerUUID]);
        $stmt = $pdo->prepare("
            SELECT id, folder_path, wear_mode, remove_before_wear, removal_points
            FROM outfits
            WHERE id IN ($placeholders) AND user_uuid = ?
        ");
        $stmt->execute($params);
        $fetched = [];
        foreach ($stmt->fetchAll() as $r) $fetched[(int)$r['id']] = $r;
        $ordered = [];
        foreach ($ids as $id) {
            $id = (int)$id;
            if (isset($fetched[$id])) $ordered[] = $fetched[$id];
        }
        return $ordered;
    };

    foreach ($resolveIds($row['base_outfits'] ?? '') as $bo) {
        $sequence[] = $bo;
    }
    $mainRow              = $row;
    $mainRow['wear_mode'] = $wearMode;
    $sequence[]           = $mainRow;
    foreach ($resolveIds($row['additional_items'] ?? '') as $ai) {
        $sequence[] = $ai;
    }

    // ── Send sequence to HUD ──────────────────────────────────
    $STEP_DELAY = 1.5;

    foreach ($sequence as $i => $step) {
        $removalPointsStr = resolve_removal_points($step, $defaultPoints);

        $postBody = http_build_query([
            'access_uuid'    => $ownerUUID,
            'command'        => 'wear',
            'folder'         => $step['folder_path'],
            'wear_mode'      => $step['wear_mode'] ?: 'subfolders_replace',
            'removal_points' => $removalPointsStr,
        ]);

        $context = stream_context_create([
            'http' => [
                'method'        => 'POST',
                'header'        => "Content-Type: application/x-www-form-urlencoded\r\n"
                                 . "Content-Length: " . strlen($postBody) . "\r\n",
                'content'       => $postBody,
                'timeout'       => 8,
                'ignore_errors' => true,
            ]
        ]);

        $response = @file_get_contents($simURL, false, $context);
        if ($response === false) {
            http_response_code(503);
            echo json_encode(['error' => 'hud_offline']);
            return;
        }

        if ($i < count($sequence) - 1) {
            usleep((int)($STEP_DELAY * 1_000_000));
        }
    }

    echo json_encode(['status' => 'ok']);
}

// ============================================================
// LINK REMOVE (third-party)
// ============================================================
// POST /api.php?action=link_remove
// Fields: link_uuid, outfit_id
//
// Same auth path as link_wear but sends command=remove.
// ============================================================

function api_link_remove(PDO $pdo): void
{
    $linkUUID = trim($_POST['link_uuid'] ?? '');
    $outfitId = (int)($_POST['outfit_id'] ?? 0);

    if (!preg_match('/^[0-9a-f]{32}$/', $linkUUID) || $outfitId === 0) {
        http_response_code(400);
        echo json_encode(['error' => 'link_uuid and outfit_id are required']);
        return;
    }

    $stmt = $pdo->prepare('SELECT user_uuid, can_wear, include_private FROM links WHERE link_uuid = ?');
    $stmt->execute([$linkUUID]);
    $link = $stmt->fetch();

    if (!$link || !$link['can_wear']) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }

    $ownerUUID = $link['user_uuid'];

    $stmt = $pdo->prepare('
        SELECT o.folder_path, o.locked, o.access_level,
               u.sim_url, u.last_seen
        FROM outfits o
        JOIN users u ON u.access_uuid = o.user_uuid
        WHERE o.id = ? AND o.user_uuid = ?
    ');
    $stmt->execute([$outfitId, $ownerUUID]);
    $row = $stmt->fetch();

    if (!$row) {
        http_response_code(404);
        echo json_encode(['error' => 'not_found']);
        return;
    }

    if ($row['access_level'] === 'private' && !$link['include_private']) {
        http_response_code(404);
        echo json_encode(['error' => 'not_found']);
        return;
    }

    if (!empty($row['locked'])) {
        http_response_code(403);
        echo json_encode(['error' => 'outfit_locked']);
        return;
    }

    $age = time() - (int)$row['last_seen'];
    if ($row['sim_url'] === '' || $age > 600) {
        http_response_code(503);
        echo json_encode(['error' => 'hud_offline']);
        return;
    }

    $postBody = http_build_query([
        'access_uuid' => $ownerUUID,
        'command'     => 'remove',
        'folder'      => $row['folder_path'],
    ]);

    $context = stream_context_create([
        'http' => [
            'method'        => 'POST',
            'header'        => "Content-Type: application/x-www-form-urlencoded\r\n"
                             . "Content-Length: " . strlen($postBody) . "\r\n",
            'content'       => $postBody,
            'timeout'       => 8,
            'ignore_errors' => true,
        ]
    ]);

    $response = @file_get_contents($row['sim_url'], false, $context);
    if ($response === false) {
        http_response_code(503);
        echo json_encode(['error' => 'hud_offline']);
        return;
    }

    echo json_encode(['status' => 'ok']);
}

// ============================================================
// RLV CHECK
// ============================================================
// POST /api.php?action=rlv_check
// Fields: (none beyond session auth)
//
// Asks the wearer's HUD to probe @version — checks whether the
// viewer has RLV enabled. The HUD opens a listen for the viewer's
// response, waits up to 3 seconds, then responds to this request.
//
// Because the HUD takes up to 3 seconds to respond, this request
// uses a 10-second PHP timeout so we don't cut it off early.
//
// Returns:
//   200 {"status":"ok","rlv":true,"version":"RestrainedLove viewer v2.x"}
//   200 {"status":"ok","rlv":false,"version":""}
//   403 {"error":"forbidden"}   — not logged in
//   503 {"error":"hud_offline"} — sim_url empty or HUD not reachable
// ============================================================

function api_rlv_check(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();
    $accessUUID = auth_uuid();
    if ($accessUUID === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    // Fetch sim_url and last_seen for online check
    $stmt = $pdo->prepare('SELECT sim_url, last_seen FROM users WHERE access_uuid = ?');
    $stmt->execute([$accessUUID]);
    $user = $stmt->fetch();

    if (!$user) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }

    $age = time() - (int)$user['last_seen'];
    if ($user['sim_url'] === '' || $age > 600) {
        http_response_code(503);
        echo json_encode(['error' => 'hud_offline']);
        return;
    }

    // POST check_rlv command to the HUD.
    // The HUD takes up to 3 seconds to probe @version and respond,
    // so we allow 10 seconds here to be safe.
    $postBody = http_build_query([
        'access_uuid' => $accessUUID,
        'command'     => 'check_rlv',
    ]);

    $context = stream_context_create([
        'http' => [
            'method'        => 'POST',
            'header'        => "Content-Type: application/x-www-form-urlencoded\r\n"
                             . "Content-Length: " . strlen($postBody) . "\r\n",
            'content'       => $postBody,
            'timeout'       => 10,
            'ignore_errors' => true,
        ]
    ]);

    $response = @file_get_contents($user['sim_url'], false, $context);
    if ($response === false) {
        http_response_code(503);
        echo json_encode(['error' => 'hud_offline']);
        return;
    }

    // HUD returns {"rlv":true,"version":"..."} or {"rlv":false,"version":""}
    $data = json_decode($response, true);
    if (!is_array($data) || !isset($data['rlv'])) {
        http_response_code(503);
        echo json_encode(['error' => 'invalid_response']);
        return;
    }

    echo json_encode([
        'status'  => 'ok',
        'rlv'     => (bool)$data['rlv'],
        'version' => $data['version'] ?? '',
    ]);
}

// ============================================================
// RLV SEND
// ============================================================
// POST /api.php?action=rlv_send
// Fields: rlv_cmd
//
// Sends an arbitrary RLV command string to the wearer's HUD.
// The HUD issues it via llOwnerSay. Fire-and-forget — RLV does
// not acknowledge commands so we return 200 on delivery to HUD.
//
// The command must begin with "@". We enforce this server-side
// to prevent accidental plain-chat messages being issued.
//
// Returns:
//   200 {"status":"ok"}
//   400 {"error":"..."}        — missing or invalid rlv_cmd
//   403 {"error":"forbidden"}  — not logged in
//   503 {"error":"hud_offline"}
// ============================================================

function api_rlv_send(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();
    $accessUUID = auth_uuid();
    if ($accessUUID === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();
    $rlvCmd = trim($_POST['rlv_cmd'] ?? '');

    if ($rlvCmd === '') {
        http_response_code(400);
        echo json_encode(['error' => 'rlv_cmd is required']);
        return;
    }

    // Commands must start with @ — anything else is not a valid RLV command
    if ($rlvCmd[0] !== '@') {
        http_response_code(400);
        echo json_encode(['error' => 'rlv_cmd must begin with @']);
        return;
    }

    // Basic length guard — RLV commands do not need to be long
    if (strlen($rlvCmd) > 256) {
        http_response_code(400);
        echo json_encode(['error' => 'rlv_cmd too long (max 256 chars)']);
        return;
    }

    $stmt = $pdo->prepare('SELECT sim_url, last_seen FROM users WHERE access_uuid = ?');
    $stmt->execute([$accessUUID]);
    $user = $stmt->fetch();

    if (!$user) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }

    $age = time() - (int)$user['last_seen'];
    if ($user['sim_url'] === '' || $age > 600) {
        http_response_code(503);
        echo json_encode(['error' => 'hud_offline']);
        return;
    }

    $postBody = http_build_query([
        'access_uuid' => $accessUUID,
        'command'     => 'rlv_command',
        'rlv_cmd'     => $rlvCmd,
    ]);

    $context = stream_context_create([
        'http' => [
            'method'        => 'POST',
            'header'        => "Content-Type: application/x-www-form-urlencoded\r\n"
                             . "Content-Length: " . strlen($postBody) . "\r\n",
            'content'       => $postBody,
            'timeout'       => 8,
            'ignore_errors' => true,
        ]
    ]);

    $response = @file_get_contents($user['sim_url'], false, $context);
    if ($response === false) {
        http_response_code(503);
        echo json_encode(['error' => 'hud_offline']);
        return;
    }

    echo json_encode(['status' => 'ok']);
}

// ============================================================
// CHANGE PASSWORD
// ============================================================
// POST /api.php?action=change_password
// Fields: current_password, new_password, confirm_password
//
// Allows a logged-in user to change their own password from the
// website. Not a forgotten-password flow — that's handled via
// set_temp_password on the HUD.
//
// Accepts users who are still on a temp password (force_change),
// so the change-password modal works as an alternative to the
// force-change form.
//
// Returns:
//   200 {"status":"ok"}
//   400 {"error":"..."}             — missing/invalid fields
//   403 {"error":"forbidden"}       — not logged in / bad CSRF
//   403 {"error":"wrong_password"}  — current password incorrect
// ============================================================

function api_change_password(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_start();
    $accessUUID = auth_uuid();
    if ($accessUUID === null) {
        http_response_code(403);
        echo json_encode(['error' => 'forbidden']);
        return;
    }
    auth_check_csrf();

    $currentPassword = $_POST['current_password'] ?? '';
    $newPassword     = $_POST['new_password']      ?? '';
    $confirmPassword = $_POST['confirm_password']  ?? '';

    if ($currentPassword === '' || $newPassword === '' || $confirmPassword === '') {
        http_response_code(400);
        echo json_encode(['error' => 'All three password fields are required.']);
        return;
    }

    // Verify the current password — accept both ok and force_change states
    $result = auth_verify_password($pdo, $accessUUID, $currentPassword);
    if ($result === 'wrong' || $result === 'no_password') {
        http_response_code(403);
        echo json_encode(['error' => 'wrong_password']);
        return;
    }

    // New passwords must match
    if ($newPassword !== $confirmPassword) {
        http_response_code(400);
        echo json_encode(['error' => 'New passwords do not match.']);
        return;
    }

    // New password must differ from current
    if ($newPassword === $currentPassword) {
        http_response_code(400);
        echo json_encode(['error' => 'New password must be different from current password.']);
        return;
    }

    // Enforce password strength rules
    $strengthError = auth_check_password_strength($newPassword);
    if ($strengthError !== '') {
        http_response_code(400);
        echo json_encode(['error' => $strengthError]);
        return;
    }

    // Store bcrypt hash and set pw_set=1
    auth_set_password($pdo, $accessUUID, $newPassword);

    // Clear force_pw_change session flag if the user was on a temp password
    unset($_SESSION['force_pw_change']);

    // Notify HUD that password has been set (fire-and-forget)
    auth_notify_hud_password_set($pdo, $accessUUID);

    echo json_encode(['status' => 'ok']);
}

// ============================================================
// SAVE THEME
// ============================================================
// POST /api.php?action=save_theme
// Fields: theme (string — folder name under themes/)
//
// Validates that the named theme folder exists on disk before
// saving, so the user can't store a theme name that won't load.
// Strips any path characters to prevent directory traversal.
//
// Returns:
//   200 {"status":"ok","theme":"<name>"}
//   400 {"error":"..."}   — missing/invalid theme name
//   401 {"error":"..."}   — not logged in
//   404 {"error":"..."}   — theme folder not found on disk
// ============================================================
function api_save_theme(PDO $pdo): void
{
    require_once __DIR__ . '/auth.php';
    auth_check_csrf();
    $accessUUID = auth_uuid();
    if ($accessUUID === null) {
        http_response_code(401);
        echo json_encode(['error' => 'Not logged in']);
        return;
    }

    $raw = trim($_POST['theme'] ?? '');

    // Strip any path components — theme name must be a plain directory name
    $theme = basename($raw);

    if ($theme === '' || $theme === '.' || $theme === '..') {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid theme name']);
        return;
    }

    // Only allow alphanumeric, hyphens, and underscores
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $theme)) {
        http_response_code(400);
        echo json_encode(['error' => 'Theme name contains invalid characters']);
        return;
    }

    // Check the theme folder exists
    $themeDir = __DIR__ . '/themes/' . $theme;
    if (!is_dir($themeDir)) {
        http_response_code(404);
        echo json_encode(['error' => 'Theme not found']);
        return;
    }

    $stmt = $pdo->prepare('UPDATE users SET theme = ? WHERE access_uuid = ?');
    $stmt->execute([$theme, $accessUUID]);

    echo json_encode(['status' => 'ok', 'theme' => $theme]);
}
