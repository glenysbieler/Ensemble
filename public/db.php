<?php
// ============================================================
// Ensemble - Database Layer
// ============================================================
// Handles SQLite connection and schema bootstrap.
// Called by api.php and index.php.
//
// The database file lives in /data/ relative to this file.
// On most shared hosting you can make this directory writable
// via your file manager or: chmod 755 data/
//
// Path and other settings are configured in config.php.
// ============================================================

require_once __DIR__ . '/config.php';

function db_connect(): PDO
{
    $dir = dirname(DB_PATH);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }

    $pdo = new PDO('sqlite:' . DB_PATH);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    // Enable WAL mode — safer for concurrent reads during heartbeats
    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA foreign_keys=ON');

    db_bootstrap($pdo);

    return $pdo;
}

function db_bootstrap(PDO $pdo): void
{
    // ── Phase 1 schema ───────────────────────────────────────
    // users: one row per HUD wearer
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users (
            access_uuid   TEXT PRIMARY KEY,
            username      TEXT NOT NULL DEFAULT '',
            sim_url       TEXT NOT NULL DEFAULT '',
            last_seen     INTEGER NOT NULL DEFAULT 0,
            created_at    INTEGER NOT NULL DEFAULT 0
        )
    ");

    // ── Password columns (added in password phase) ───────────
    // pw_hash : MD5(plaintext + access_uuid) sent by HUD for temp password,
    //           or password_hash() of user-chosen password after force-change.
    //           NULL until HUD sends first temp password.
    // pw_set  : 0 = temp password only (force-change on next login)
    //           1 = user has set a real password
    // owner_uuid : the avatar's permanent grid UUID, sent by the HUD on every
    //              checkin/heartbeat. Effectively immutable for a given avatar.
    //              Used as a hard-match security check on backup restore.
    // ALTER TABLE is safe to call on every boot — we swallow the
    // "duplicate column" error that fires once the column exists.
    // hud_locked : 1 = wearer has an active RLV restriction preventing HUD detach.
    //              Sent by the HUD on every checkin/heartbeat. 0 = unlocked/unknown.
    // default_removal_points : JSON array of attachment point integers to clear
    //              before wearing an outfit when "remove before wearing" is enabled.
    //              Empty string = not yet configured (UI will offer defaults).
    // core_version  : version string of the Core script last seen (e.g. "0.24").
    //              Empty string for HUDs predating v0.24.
    // relay_version : version string of the WebRelay script last seen (e.g. "0.11").
    //              Empty string for HUDs predating v0.11 / Core v0.24.
    //              Both updated on every checkin/heartbeat.
    // theme : the name of the user's chosen UI theme (matches a folder under themes/).
    //         Empty string / 'default' both resolve to the default theme.
    //         Added in Phase 10 — existing rows silently default to the default theme.
    foreach (['pw_hash TEXT', 'pw_set INTEGER NOT NULL DEFAULT 0', 'owner_uuid TEXT NOT NULL DEFAULT \'\'', 'region_name TEXT NOT NULL DEFAULT \'\'', 'hud_locked INTEGER NOT NULL DEFAULT 0', "default_removal_points TEXT NOT NULL DEFAULT ''", "core_version TEXT NOT NULL DEFAULT ''", "relay_version TEXT NOT NULL DEFAULT ''", "theme TEXT NOT NULL DEFAULT ''"] as $col) {
        try {
            $pdo->exec("ALTER TABLE users ADD COLUMN $col");
        } catch (Exception $e) {
            // Column already exists — ignore
        }
    }

    // ── Outfits table ────────────────────────────────────────
    // folder_path : RLV-relative path, e.g. .ensemble/outfits/PinkDress
    // outfit_name : human-readable display name, derived from path on save,
    //               editable on web panel
    // attachments : JSON array of {point, item} objects sent by HUD
    // has_space_warning : 1 if folder_path contains spaces (RLV hazard)
    // image_filename : uploaded image, null until owner provides one
    // tags, notes, creator : all editable on web panel only
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS outfits (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            user_uuid         TEXT NOT NULL,
            folder_path       TEXT NOT NULL,
            outfit_name       TEXT NOT NULL DEFAULT '',
            attachments       TEXT NOT NULL DEFAULT '[]',
            has_space_warning INTEGER NOT NULL DEFAULT 0,
            image_filename    TEXT,
            tags              TEXT NOT NULL DEFAULT '',
            notes             TEXT NOT NULL DEFAULT '',
            creator           TEXT NOT NULL DEFAULT '',
            is_public         INTEGER NOT NULL DEFAULT 1,
            created_at        INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_uuid) REFERENCES users(access_uuid),
            UNIQUE (user_uuid, folder_path)
        )
    ");

    // ── Remember-me tokens ───────────────────────────────────
    // One row per active "remember me" session.
    // token_hash : SHA-256 of the random token stored in the cookie.
    //              Never store the plaintext — if the DB leaks, tokens
    //              cannot be used without also cracking the hash.
    // expires_at : Unix timestamp; tokens older than 30 days are ignored
    //              and cleaned up on login.
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS remember_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_uuid   TEXT NOT NULL,
            token_hash  TEXT NOT NULL UNIQUE,
            expires_at  INTEGER NOT NULL,
            FOREIGN KEY (user_uuid) REFERENCES users(access_uuid)
        )
    ");

    // ── Phase 2: additional outfit columns ──────────────────────
    // locked : 1 = outfit is locked in-world via @detachthis RLV restriction.
    //          HUD re-issues the restriction on every heartbeat so lock
    //          survives relog and region crossing.
    //          0 = unlocked (default).
    // comments and access_level added in earlier phases; same pattern.
    foreach ([
                'locked INTEGER NOT NULL DEFAULT 0',
                "comments TEXT NOT NULL DEFAULT ''",
                "access_level TEXT NOT NULL DEFAULT 'public'",
                "wear_mode TEXT NOT NULL DEFAULT 'subfolders_replace'",
                "base_outfits TEXT NOT NULL DEFAULT ''",
                "additional_items TEXT NOT NULL DEFAULT ''",
                // Removal-before-wear: 0 = disabled, 1 = enabled
                'remove_before_wear INTEGER NOT NULL DEFAULT 0',
                // removal_points: JSON int array of attachment points to clear.
                // Empty string = use user's default_removal_points.
                // Non-empty = custom list for this outfit only.
                "removal_points TEXT NOT NULL DEFAULT ''",
                // wear_after_remove: JSON array of outfit IDs to wear automatically
                // after this outfit is removed via the Remove button on the web panel.
                // Only fires when the Remove button is used — not for in-world or
                // sequence-based removal. Same wear logic as base_outfits/additional_items.
                "wear_after_remove TEXT NOT NULL DEFAULT ''",
             ] as $col) {
        try {
            $pdo->exec("ALTER TABLE outfits ADD COLUMN $col");
        } catch (Exception $e) {
            // Column already exists — ignore
        }
    }

    // ── Phase 3: links table ─────────────────────────────────
    // One row per shareable link created by a wearer.
    // link_uuid      : random UUID generated on creation — appears in the URL
    // user_uuid      : FK → users.access_uuid — the link owner
    // link_name      : optional human label, e.g. "Bob's Link"
    // can_wear       : 0 = view only, 1 = Wear/Remove buttons enabled
    // include_private: 0 = public outfits only, 1 = all outfits
    // created_at     : Unix timestamp
    //
    // Two boolean columns rather than a single mode integer — each is
    // self-documenting and independently queryable.
    // Cap enforced in code: maximum 20 links per user.
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS links (
            link_uuid        TEXT PRIMARY KEY,
            user_uuid        TEXT NOT NULL,
            link_name        TEXT NOT NULL DEFAULT '',
            can_wear         INTEGER NOT NULL DEFAULT 0,
            include_private  INTEGER NOT NULL DEFAULT 0,
            created_at       INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_uuid) REFERENCES users(access_uuid)
        )
    ");
}
