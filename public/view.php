<?php
// ============================================================
// Ensemble - Third-Party Link View
// ============================================================
// Handles shareable link requests. No login required.
//
// URL format: view.php?id=<link_uuid>
//
// The link controls:
//   include_private — whether private outfits are visible
//   can_wear        — whether Wear/Remove buttons are shown
//
// Wear/Remove buttons are disabled (greyed out) when the HUD
// is offline or the outfit is RLV-locked, matching the
// behaviour of the owner's own dashboard.
//
// Visitors can never alter settings, outfit metadata, or
// anything else — read (and optionally wear) only.
// ============================================================

define('ENSEMBLE_THEME', 'default');

require_once __DIR__ . '/db.php';

// ── Resolve link ──────────────────────────────────────────────
$linkUUID = trim($_GET['id'] ?? '');

$notFound = false;
$link     = null;
$owner    = null;
$outfits  = [];
$allTags  = [];

if (!preg_match('/^[0-9a-f]{32}$/', $linkUUID)) {
    $notFound = true;
}

if (!$notFound) {
    try {
        $pdo  = db_connect();

        $stmt = $pdo->prepare('
            SELECT l.link_uuid, l.link_name, l.can_wear, l.include_private,
                   u.username, u.sim_url, u.last_seen
            FROM links l
            JOIN users u ON u.access_uuid = l.user_uuid
            WHERE l.link_uuid = ?
        ');
        $stmt->execute([$linkUUID]);
        $link = $stmt->fetch();

        if (!$link) {
            $notFound = true;
        } else {
            // ── Load outfits ──────────────────────────────────
            // If include_private=0, only public outfits are returned.
            if ($link['include_private']) {
                $stmtOutfits = $pdo->prepare('
                    SELECT id, outfit_name, folder_path, attachments,
                           has_space_warning, image_filename, created_at,
                           tags, access_level, wear_mode, locked
                    FROM outfits
                    WHERE user_uuid = (
                        SELECT user_uuid FROM links WHERE link_uuid = ?
                    )
                    ORDER BY created_at DESC
                ');
            } else {
                $stmtOutfits = $pdo->prepare('
                    SELECT id, outfit_name, folder_path, attachments,
                           has_space_warning, image_filename, created_at,
                           tags, access_level, wear_mode, locked
                    FROM outfits
                    WHERE user_uuid = (
                        SELECT user_uuid FROM links WHERE link_uuid = ?
                    )
                    AND access_level != \'private\'
                    ORDER BY created_at DESC
                ');
            }
            $stmtOutfits->execute([$linkUUID]);
            $outfits = $stmtOutfits->fetchAll();

            // ── Collect tags ──────────────────────────────────
            $allTagsRaw = [];
            foreach ($outfits as $o) {
                $t = trim($o['tags'] ?? '');
                if ($t !== '') {
                    foreach (array_map('trim', explode(',', $t)) as $tag) {
                        if ($tag !== '') $allTagsRaw[] = $tag;
                    }
                }
            }
            $allTagsMap = [];
            foreach ($allTagsRaw as $tag) {
                $allTagsMap[strtolower($tag)] = $tag;
            }
            ksort($allTagsMap);
            $allTags = array_values($allTagsMap);
        }
    } catch (Exception $e) {
        error_log('Ensemble view.php error: ' . $e->getMessage());
        $notFound = true;
    }
}

// ── HUD status ────────────────────────────────────────────────
// Returns the same three-state status used by the owner dashboard:
//   Online  — last_seen < 3 min  (HUD is actively heartbeating)
//   Stale   — last_seen < 10 min (HUD may still be reachable)
//   Offline — everything else
// For can_wear links, buttons are disabled when status is Offline.
// Stale is treated as still-reachable (command is queued by WebRelay).
function view_hud_status(array $link): array
{
    if (empty($link['sim_url']) || empty($link['last_seen'])) {
        return ['label' => 'Offline', 'class' => 'status-offline', 'online' => false];
    }
    $age = time() - (int)$link['last_seen'];
    if ($age < 180) {
        return ['label' => 'Online', 'class' => 'status-online', 'online' => true];
    }
    if ($age < 600) {
        return ['label' => 'Stale',  'class' => 'status-stale',  'online' => true];
    }
    return ['label' => 'Offline', 'class' => 'status-offline', 'online' => false];
}

?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php
        if ($notFound) {
            echo 'Link not found — Ensemble';
        } elseif ($link['link_name'] !== '') {
            echo htmlspecialchars($link['link_name']) . ' — Ensemble';
        } else {
            echo htmlspecialchars($link['username']) . '\'s Outfits — Ensemble';
        }
    ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,600;1,400&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="themes/<?= htmlspecialchars(ENSEMBLE_THEME) ?>/style.css">
</head>
<body>

<div class="page-wrap">

    <!-- ── Header ──────────────────────────────────────────── -->
    <!-- header-inner uses grid-template-columns: 1fr auto 1fr
         Col 1 (left): spacer keeps logo visually centred.
         Col 2 (centre): logo.
         Col 3 (right): username + HUD status badge (can_wear links only). -->
    <header class="site-header">
        <div class="header-inner">
            <!-- Left spacer mirrors right nav width so the logo stays centred -->
            <div></div>
            <div class="logo-wrap">
                <img src="themes/<?= htmlspecialchars(ENSEMBLE_THEME) ?>/ensemblelogo.png"
                     alt="Ensemble"
                     class="logo-img">
            </div>
            <?php if (!$notFound): ?>
            <?php
                // Compute status now — used by both the header badge and card button logic below.
                $hudStatus = view_hud_status($link);
                $hudOnline = $hudStatus['online'];
                $canWear   = (bool)$link['can_wear'];
                $inclPriv  = (bool)$link['include_private'];
            ?>
            <nav class="header-nav">
                <?php if ($canWear): ?>
                <!-- Status badge — only shown on wear-capable links so visitors know
                     whether wear/remove commands will actually reach the wearer's HUD. -->
                <span class="status-badge <?= $hudStatus['class'] ?>">
                    <span class="status-dot"></span>
                    <?= htmlspecialchars($hudStatus['label']) ?>
                </span>
                <?php endif; ?>
                <span class="nav-username"><?= htmlspecialchars($link['username']) ?>'s outfits</span>
            </nav>
            <?php endif; ?>
        </div>
    </header>

    <main class="main-content">

    <?php if ($notFound): ?>
    <!-- ════════════════════════════════════════════════════════
         LINK NOT FOUND
         ════════════════════════════════════════════════════════ -->
    <div class="login-wrap">
        <div class="login-card">
            <h1 class="login-heading">Link not found</h1>
            <p class="login-subtext">This link doesn't exist or may have been removed by its owner.</p>
            <p class="login-subtext" style="margin-top:0.5rem">
                <a href="index.php">Sign in to Ensemble</a>
            </p>
        </div>
    </div>

    <?php else: ?>
    <!-- ════════════════════════════════════════════════════════
         OUTFIT VIEW
         ════════════════════════════════════════════════════════ -->


    <div class="dashboard-wrap">
        <section class="card card-outfits">
            <div class="card-body">
                <div class="outfits-header">
                    <h2 class="card-title">
                        <?= $link['link_name'] !== '' ? htmlspecialchars($link['link_name']) : htmlspecialchars($link['username']) . '\'s Outfits' ?>
                    </h2>
                    <span class="outfit-count" id="outfitCount"><?= count($outfits) ?> outfits</span>
                </div>

                <?php if (empty($outfits)): ?>
                <div class="outfits-empty">
                    <div class="placeholder-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                            <path d="M20.38 3.46L16 2a4 4 0 01-8 0L3.62 3.46a2 2 0 00-1.34 2.23l.58 3.57a1 1 0 00.99.84H6v10c0 1.1.9 2 2 2h8a2 2 0 002-2V10h2.15a1 1 0 00.99-.84l.58-3.57a2 2 0 00-1.34-2.23z"/>
                        </svg>
                    </div>
                    <p class="placeholder-text">No outfits to display.</p>
                </div>

                <?php else: ?>

                <!-- ── Filter bar ──────────────────────────────────── -->
                <div class="filter-bar" id="filterBar">
                    <div class="filter-bar-row">

                        <?php if ($inclPriv): ?>
                        <!-- Hide private checkbox — only shown when link can see private outfits -->
                        <label class="filter-private-label" title="Hide outfits marked as Private">
                            <input type="checkbox" id="filterHidePrivate" onchange="applyFilters()">
                            <span>Hide Private</span>
                        </label>
                        <div class="filter-bar-divider"></div>
                        <?php endif; ?>

                        <!-- Tag pills (collapsed) — populated dynamically by updateCollapsedPills() -->
                        <div class="filter-tags-collapsed" id="filterTagsCollapsed">
                            <span class="filter-no-tags">Not filtered</span>
                        </div>

                        <!-- Clear button (collapsed state) -->
                        <button class="filter-clear-btn" id="filterClearCollapsed" onclick="clearAllTagFilters()" hidden>Clear</button>

                        <!-- Expand toggle -->
                        <?php if (!empty($allTags)): ?>
                        <button class="filter-expand-btn" id="filterExpandBtn" onclick="toggleFilterExpand()" title="Filter by tags">
                            <svg class="filter-chevron" id="filterChevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" width="15" height="15"><polyline points="6 9 12 15 18 9"/></svg>
                            <span id="filterExpandLabel">Filter</span>
                        </button>
                        <?php endif; ?>

                    </div><!-- /.filter-bar-row -->

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
                                       ? 'image.php?file=' . urlencode($outfit['image_filename']) . '&link_uuid=' . urlencode($linkUUID)
                                       : 'themes/' . ENSEMBLE_THEME . '/placeholder.png';
                        $isLocked    = !empty($outfit['locked']);
                        $isPrivate   = ($outfit['access_level'] === 'private');

                        $rawMode  = $outfit['wear_mode'] ?? '';
                        $wearMode = in_array($rawMode, ['folder_add','folder_replace','subfolders_add','subfolders_replace'], true)
                                    ? $rawMode : 'subfolders_replace';

                        $cardClasses = 'outfit-card';
                        if ($outfit['has_space_warning']) $cardClasses .= ' outfit-card--warning';
                        if ($isLocked)  $cardClasses .= ' outfit-card--locked';
                        if ($isPrivate) $cardClasses .= ' outfit-card--private';

                        $cardTagList = '';
                        if (trim($outfit['tags'] ?? '') !== '') {
                            $cardTagList = implode('|', array_map('strtolower', array_map('trim', explode(',', $outfit['tags']))));
                        }

                        // Wear/Remove buttons are shown only when can_wear=1.
                        // They are greyed out (disabled) if HUD is offline or outfit is locked.
                        $btnDisabled = (!$hudOnline || $isLocked) ? ' disabled' : '';
                        $btnTitle    = $isLocked  ? ' title="Outfit is locked"'
                                     : (!$hudOnline ? ' title="HUD is offline"' : '');
                    ?>
                    <div class="<?= $cardClasses ?>"
                         data-access="<?= htmlspecialchars($outfit['access_level'] ?? 'public') ?>"
                         data-tags="<?= htmlspecialchars($cardTagList) ?>">

                        <div class="outfit-image-wrap outfit-image-wrap--clickable"
                             onclick="openLightbox(<?= (int)$outfit['id'] ?>, <?= htmlspecialchars(json_encode($imageSrc), ENT_QUOTES) ?>, <?= htmlspecialchars(json_encode($outfit['outfit_name']), ENT_QUOTES) ?>)"
                             style="cursor:pointer"
                             title="Click to view"
                        >
                            <img
                                src="<?= $imageSrc ?>"
                                alt="<?= htmlspecialchars($outfit['outfit_name']) ?>"
                                class="outfit-image"
                                onerror="this.src='themes/<?= ENSEMBLE_THEME ?>/placeholder.png'; this.onerror=null;"
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
                        </div>

                        <div class="outfit-details">
                            <h3 class="outfit-name"><?= htmlspecialchars($outfit['outfit_name']) ?></h3>
                            <?php
                                $cardTags = trim($outfit['tags'] ?? '');
                                if ($cardTags !== '') {
                                    // Render tags as comma-separated text, matching the owner dashboard.
                                    echo '<p class="outfit-tags">' . htmlspecialchars($cardTags) . '</p>';
                                } else {
                                    echo '<p class="outfit-path" title="' . htmlspecialchars($outfit['folder_path']) . '">'
                                       . htmlspecialchars($outfit['folder_path']) . '</p>';
                                }
                            ?>
                        </div>

                        <?php if ($canWear):
                            // Use the same btn-wear/btn-remove classes as the owner dashboard so
                            // layout, colour, disabled styling, and the shirt icon all match exactly.
                            $wearClass   = 'btn btn-wear'   . (!$hudOnline || $isLocked ? ' btn-wear--offline'   : '');
                            $removeClass = 'btn btn-remove' . (!$hudOnline || $isLocked ? ' btn-remove--offline' : '');
                        ?>
                        <div class="outfit-actions">
                            <button
                                class="<?= $wearClass ?>"
                                data-outfit-id="<?= (int)$outfit['id'] ?>"
                                data-wear-mode="<?= htmlspecialchars($wearMode) ?>"
                                onclick="linkWear(this)"
                                <?= $btnDisabled ?>
                                <?= $btnTitle ?>
                            >
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M20.38 3.46L16 2a4 4 0 01-8 0L3.62 3.46a2 2 0 00-1.34 2.23l.58 3.57a1 1 0 00.99.84H6v10c0 1.1.9 2 2 2h8a2 2 0 002-2V10h2.15a1 1 0 00.99-.84l.58-3.57a2 2 0 00-1.34-2.23z"/>
                                </svg>
                                Wear
                            </button>
                            <button
                                class="<?= $removeClass ?>"
                                data-outfit-id="<?= (int)$outfit['id'] ?>"
                                onclick="linkRemove(this)"
                                <?= $btnDisabled ?>
                                <?= $btnTitle ?>
                            >Remove</button>
                        </div>
                        <?php endif; ?>

                    </div>
                    <?php endforeach; ?>
                </div><!-- /.outfit-grid -->

                <?php endif; ?>

            </div><!-- /.card-body -->
        </section>
    </div><!-- /.dashboard-wrap -->

    <!-- Toast notification -->
    <div class="toast-container" id="toastContainer" aria-live="polite"></div>

    <?php endif; // not found ?>

    </main>
</div><!-- /.page-wrap -->

<?php if (!$notFound): ?>
<script>
var VIEW_LINK_UUID = <?= json_encode($linkUUID) ?>;

// ── Toast notifications ──────────────────────────────────────
function showToast(message, type) {
    var container = document.getElementById('toastContainer');
    var toast = document.createElement('div');
    toast.className = 'toast toast--' + (type || 'info');
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(function() { toast.classList.add('toast--visible'); }, 10);
    setTimeout(function() {
        toast.classList.remove('toast--visible');
        setTimeout(function() { toast.remove(); }, 300);
    }, 3500);
}

// ── Wear via link ────────────────────────────────────────────
function linkWear(btn) {
    btn.disabled = true;
    var outfitId = btn.getAttribute('data-outfit-id');
    var wearMode = btn.getAttribute('data-wear-mode') || 'subfolders_replace';
    var fd = new FormData();
    fd.append('link_uuid',  VIEW_LINK_UUID);
    fd.append('outfit_id',  outfitId);
    fd.append('wear_mode',  wearMode);
    fetch('api.php?action=link_wear', { method: 'POST', body: fd })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'ok') {
            showToast('Wear command sent.', 'success');
        } else if (data.error === 'hud_offline') {
            showToast('HUD is offline.', 'error');
        } else if (data.error === 'outfit_locked') {
            showToast('Outfit is locked.', 'error');
        } else {
            showToast('Could not send wear command.', 'error');
        }
    })
    .catch(function() { showToast('Could not reach the server.', 'error'); })
    .finally(function() { btn.disabled = false; });
}

// ── Remove via link ──────────────────────────────────────────
function linkRemove(btn) {
    btn.disabled = true;
    var outfitId = btn.getAttribute('data-outfit-id');
    var fd = new FormData();
    fd.append('link_uuid', VIEW_LINK_UUID);
    fd.append('outfit_id', outfitId);
    fetch('api.php?action=link_remove', { method: 'POST', body: fd })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'ok') {
            showToast('Remove command sent.', 'success');
        } else if (data.error === 'hud_offline') {
            showToast('HUD is offline.', 'error');
        } else if (data.error === 'outfit_locked') {
            showToast('Outfit is locked.', 'error');
        } else {
            showToast('Could not send remove command.', 'error');
        }
    })
    .catch(function() { showToast('Could not reach the server.', 'error'); })
    .finally(function() { btn.disabled = false; });
}

// ── Filter bar ──────────────────────────────────────────────
var _filterExpanded = false;
var _totalOutfits   = document.querySelectorAll('.outfit-card').length;

function toggleFilterExpand() {
    _filterExpanded = !_filterExpanded;
    var panel   = document.getElementById('filterBarExpanded');
    var chevron = document.getElementById('filterChevron');
    var label   = document.getElementById('filterExpandLabel');
    if (panel)   panel.hidden = !_filterExpanded;
    if (chevron) chevron.classList.toggle('rotated', _filterExpanded);
    if (label)   label.textContent = _filterExpanded ? 'Done' : 'Filter';
}

function clearAllTagFilters() {
    document.querySelectorAll('.filter-tag-cb').forEach(function(cb) { cb.checked = false; });
    applyFilters();
}

function applyFilters() {
    var hidePrivateEl = document.getElementById('filterHidePrivate');
    var doHidePrivate = hidePrivateEl ? hidePrivateEl.checked : false;

    var activeTags = [];
    document.querySelectorAll('.filter-tag-cb:checked').forEach(function(cb) {
        activeTags.push(cb.value);
    });

    var visible = 0;
    document.querySelectorAll('.outfit-card').forEach(function(card) {
        var access   = card.getAttribute('data-access') || 'public';
        var cardTags = card.getAttribute('data-tags')   || '';
        var show     = true;

        if (doHidePrivate && access === 'private') show = false;

        if (show && activeTags.length > 0) {
            var cardTagArr = cardTags ? cardTags.split('|') : [];
            // OR logic — card must match ANY active tag
            var matches = activeTags.some(function(t) { return cardTagArr.indexOf(t) !== -1; });
            if (!matches) show = false;
        }

        // Use style.display — card.hidden unreliable with display:flex
        card.style.display = show ? '' : 'none';
        if (show) visible++;
    });

    // Update count
    var countEl = document.getElementById('outfitCount');
    if (countEl) {
        countEl.textContent = (visible === _totalOutfits)
            ? _totalOutfits + ' outfits'
            : visible + ' of ' + _totalOutfits + ' showing';
    }

    // Update collapsed pills to reflect active tags
    updateCollapsedPills(activeTags);
}

function updateCollapsedPills(activeTags) {
    var container = document.getElementById('filterTagsCollapsed');
    if (!container) return;
    container.innerHTML = '';

    if (activeTags.length === 0) {
        var hint = document.createElement('span');
        hint.className = 'filter-no-tags';
        hint.textContent = 'Not filtered';
        container.appendChild(hint);
    } else {
        activeTags.forEach(function(tagKey) {
            var cb    = document.querySelector('.filter-tag-cb[value="' + tagKey + '"]');
            var label = cb ? cb.parentElement.querySelector('span').textContent : tagKey;
            var pill  = document.createElement('span');
            pill.className = 'filter-tag-pill filter-tag-pill--active';
            pill.textContent = label;
            container.appendChild(pill);
        });
    }

    var clearBtn = document.getElementById('filterClearCollapsed');
    if (clearBtn) clearBtn.hidden = (activeTags.length === 0);
}
</script>
<?php endif; ?>


<!-- ── Read-only outfit lightbox ─────────────────────────── -->
<div class="lightbox-backdrop" id="view-lightbox" hidden onclick="closeLightbox()">
    <button class="lightbox-close" onclick="closeLightbox()" aria-label="Close">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" width="22" height="22">
            <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
    </button>
    <div class="lightbox-inner" onclick="event.stopPropagation()">
        <img id="view-lightbox-img" src="" alt="" class="lightbox-img">
        <p id="view-lightbox-name" class="lightbox-caption"></p>
    </div>
</div>

<script>
function openLightbox(id, src, name) {
    var lb = document.getElementById('view-lightbox');
    document.getElementById('view-lightbox-img').src  = src;
    document.getElementById('view-lightbox-img').alt  = name;
    document.getElementById('view-lightbox-name').textContent = name;
    lb.hidden = false;
    document.body.style.overflow = 'hidden';
}
function closeLightbox() {
    document.getElementById('view-lightbox').hidden = true;
    document.body.style.overflow = '';
}
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeLightbox();
});
</script>
</body>
</html>
