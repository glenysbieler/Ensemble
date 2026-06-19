<?php
// ============================================================
// Ensemble - Configuration
// ============================================================
// This is the only file you should need to edit when setting
// up Ensemble on your own server. All user-configurable
// constants live here.
// ============================================================

// ── Database & uploads paths ──────────────────────────────
// DB_PATH is where the SQLite database file will be created.
// The default puts it in /data/ one level above this file
// (outside the web root on a typical shared hosting layout).
//
// If your host requires a different location, change this to
// an absolute path, e.g.:
//   define('DB_PATH', '/home/yourusername/ensemble_data/ensemble.db');
define('DB_PATH',     __DIR__ . '/../data/ensemble.db');

// UPLOADS_DIR is where outfit images are stored.
// Like DB_PATH, the default sits outside the web root.
define('UPLOADS_DIR', __DIR__ . '/../uploads/');

// ── Image link limit ──────────────────────────────────────
// Maximum number of image URLs that can be associated with
// a single outfit. Raise or lower to taste.
define('LINKS_MAX', 20);

// ── Access code gate ──────────────────────────────────────
// Set ACCESS_CODE to a non-empty string to restrict which HUDs
// can connect. Only HUDs whose wearer has entered the matching
// code in Settings -> Access Code will be accepted on checkin
// and heartbeat. Leave empty (default) to allow any HUD to
// connect.
define('ACCESS_CODE', '');
