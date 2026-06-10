/**
 * RemoraHQ - Terminal Bridge MeshCentral plugin.
 *
 * Server-side validator + correlation issuer for RemoraHQ terminal sessions.
 * Pairs with the Terminal UI in RC-12.1+ that opens the actual meshrelay
 * WebSocket using the {sessionId, relayUrl, protocol} this plugin issues.
 *
 * Responsibilities:
 *   1. Validate input — shell choice against an allow-list, context value,
 *      nodeId shape.
 *   2. For context='system' — verify the supplied TOTP token against the
 *      calling user's `otpsecret` via `otplib` (same scheme Mesh uses for
 *      login 2FA). Rejection surfaces as result:'error', error:'2fa-failed'.
 *   3. Map (shell, context) → Mesh native terminal protocol number
 *      (see PROTOCOL_MAP below). Build a relayUrl pointing at Mesh's native
 *      meshrelay.ashx using the proper `browser=1&p=<N>&nodeid&id` shape.
 *      The browser session cookie carries `auth` — Mesh's relay handler
 *      pairs the browser-side WS with the agent tunnel by `id`.
 *   4. Dispatch an audit event so security/compliance can trace every
 *      terminal-open.
 *
 * Wire protocol:
 *   client → server: {
 *     action: 'plugin', plugin: 'remoraTerminalBridge',
 *     pluginaction: 'open',
 *     nodeId: '<node//...>',
 *     shell: 'cmd' | 'powershell' | 'bash' | 'zsh',
 *     context: 'user' | 'system',
 *     totpToken?: '<6-digit-string>',
 *     tag, responseid
 *   }
 *   server → client (ok): {
 *     result: 'ok',
 *     sessionId, relayUrl, protocol,
 *     agentTunnel: { nodeId, value, remoraOperator? }
 *   }
 *   server → client (err): { result:'error', error:'<slug>' }
 *
 * Changelog:
 *   0.9.0 (2026-06-10) - Disconnect device session (N.1 #12 part-2):
 *     - New serveraction endDeviceSession: force-disconnect another user's live
 *       session (kvm/terminal/files) on a node. Gated by the RemoraHQ flag
 *       canManageDeviceSessions (resolveRemoraFlag, fail-closed; super-admin
 *       implicit, grantable to e.g. department heads). RBAC defense-in-depth via
 *       GetNodeWithRights (caller must SEE the node — no cross-group reach).
 *     - The agent self-gates endtunnel: it only closes ANOTHER user's tunnel
 *       when rights==0xFFFFFFFF (meshcore.js). After the flag check this handler
 *       legitimately sends full rights, so a non-full-admin grantee can act while
 *       a raw operator (real rights) cannot. Mirrors the native endtunnel wire
 *       (action='msg' -> type='endtunnel'). Audited (status denied/success).
 *     - Also syncs PLUGIN_VERSION (was 0.7.0, lagged config 0.8.0) to 0.9.0.
 *   0.8.0 (2026-06-10) - Duplicate-agent install guard (RINST-1 #14):
 *     - riFindExistingNode scans ALL nodes (db.GetAllType('node'), cross-group —
 *       NOT gated by the operator's visible groups, since the duplicate may sit
 *       in a group they cannot see, which is the incident) and matches the typed
 *       host (hostname → name/rname/host ignoring domain; IP → host/ip exact).
 *     - remoteInstall.run now hard-blocks a redundant push with error
 *       'agent_exists' (fail-closed: scan failure → 'dup_check_failed', refuse).
 *       Audit status 'blocked'. The foreign group name is NEVER leaked — it is
 *       returned only when the operator can already see that group (existingGroup
 *       set only if visible).
 *     - remoteInstall.reachability returns an advisory { existing, existingVisible,
 *       existingGroup } so the UI can warn before a TOTP is spent (non-fatal).
 *     - replyError gains an optional meta object (merged into the error frame).
 *   0.7.0 (2026-06-04) - Role-default + per-user override enforce (RC-15.M.2):
 *     - hasSystemTerminalPermission / hasRemoteInstallPermission now resolve the
 *       effective flag as override (grants[user][flag], tri-state) ?? roleDefault
 *       [role][flag] ?? false, instead of reading grants[user._id] only. Mirrors
 *       remoraCore 0.13.0 (M.1) which stores the roleDefaults map.
 *     - Server-side RemoraHQ role derivation (deriveRemoraRole): siteadmin bits
 *       + marker-usergroup membership (RemoraHQ Operators/Viewers, resolved by
 *       NAME via webserver.userGroups). Mirrors siteadminToRole in
 *       src/lib/contracts|utils/role.ts. auditor is treated as viewer here (it
 *       never carries these flags by default; an explicit per-user override
 *       always wins regardless). Super-admin implicit-all, fail-closed.
 *     - No behavioural change until a super-admin sets a role default (no setter
 *       UI before slot M.5): with empty roleDefaults, effective == override ==
 *       prior behaviour.
 *   0.6.1 (2026-06-04) - Remote Install authz hardening (RC-15.N SECURITY):
 *     - Per-mesh authz on the target Machine Group. remoteInstall.run and
 *       remoteInstall.reachability now require MESHRIGHT_EDITMESH (bit 1) on
 *       the groupId via webserver.GetMeshRights — the same right the native
 *       /meshagents installer download enforces. Super-admin implicit,
 *       fail-closed. Closes a cross-mesh privilege-escalation: previously any
 *       holder of canRemoteInstall could push an agent into ANY group (the
 *       "only visible groups" rule was client-side only).
 *     - remoteInstall.reachability now also requires groupId and is rate-limited
 *       (separate per-actor bucket) — closes the free-form WinRM-Negotiate
 *       credential-relay sink that ran with no authz / no throttle.
 *   0.6.0 (2026-06-03) - Remote Install reachability + push (RC-15.14):
 *     - New pluginactions remoteInstall.reachability (ICMP Test-Connection +
 *       WinRM Negotiate bind with the stored push cred) and remoteInstall.run
 *       (the actual WAC-style push). Both gated by canRemoteInstall
 *       (hasRemoteInstallPermission, super-admin implicit, fail-closed); run
 *       additionally requires a TOTP step-up (fresh token or a valid grant for
 *       actor+host, 15-min TTL) and is per-actor rate-limited (20/min).
 *     - run generates the per-group MeshAgent installer SERVER-SIDE via
 *       meshServer.exeHandler.streamExeWithMeshPolicy into a temp file under
 *       datapath (no HTTP, so nginx/TLSOffload is irrelevant), then over ONE
 *       WinRM PSSession copies it to the target (Copy-Item -ToSession) and runs
 *       `<agent>.exe -fullinstall`, cleaning up both ends. The .msh policy
 *       mirrors the native /meshagents path for the connectivity-critical
 *       fields (MeshName/Type/ID, ServerID, MeshServer wss URL, InstallFlags);
 *       optional domain agentcustomization branding is not replicated yet.
 *     - All push events audited (etype 'remote-install') with host/group/exit.
 *   0.5.1 (2026-06-03) - fix: testAccount reply field collision (RC-15.13):
 *     - handleRiTestAccount returned the test outcome under `result`, which
 *       collided with the protocol envelope `result:'ok'` set by reply() —
 *       Object.assign let the payload clobber the 'ok' marker, so a client
 *       checking `data.result === 'ok'` saw 'winrm-ok'/'decrypt-ok' instead and
 *       treated success as failure. Renamed the payload field to `testResult`.
 *   0.5.0 (2026-06-03) - Remote Install cred vault (RC-15.13):
 *     - New super-admin-only pluginactions remoteInstall.setAccount /
 *       .accountStatus / .testAccount manage the per-server push service
 *       account used by the upcoming Remote Install (WAC-style WinRM push,
 *       RC-15.14). The password is encrypted with Windows DPAPI
 *       (DataProtectionScope.LocalMachine) via a spawned powershell.exe and
 *       stored as a base64 blob in a LOCAL file under meshServer.datapath
 *       (remora-remoteinstall.json) — never in the (Mongo-replicated) DB, so a
 *       blob cannot leak to a peer region server (DPAPI is machine-bound
 *       anyway). Plaintext never touches disk, logs, or the wire: set reads it
 *       from powershell stdin; test decrypts + builds the PSCredential inside
 *       the same powershell process. testAccount optionally runs a Negotiate
 *       Invoke-Command against a host to validate the credential end-to-end.
 *       Gated by isSuperAdmin (fail-closed). The canRemoteInstall flag that
 *       gates operator USE of the push lives in remoraCore REMORA_PERMISSION_FLAGS
 *       (v0.12.6) and is enforced in RC-15.14.
 *   0.4.0 (2026-06-02) - server-side RBAC enforcement of SYSTEM terminal (RC-15.A.1):
 *     - context='system' now verifies `canUseSystemTerminal` from the
 *       `remoraPermissions` site-doc (super-admins implicit) BEFORE issuing the
 *       rauth cookie. Until now this was UI-only (TerminalToolbar hid the menu);
 *       a raw `context=system` command sent past the UI still got a cookie. The
 *       open flow moved into a hoisted proceedOpen() so the async grant lookup
 *       gates it. Denied opens dispatch an audit event (status:'denied',
 *       error:'permission_denied'). Fail-closed on missing DB access.
 *       user/operator contexts unchanged.
 *   0.3.3 (2026-06-01) - drop signed operator grant + meshuser.js patch:
 *     - The operator UPN is no longer resolved or carried by the plugin. The
 *       agent derives the identity from the server-authenticated tunnel
 *       `username` (Mesh sets command.username = user.name natively in
 *       meshrelay.js; the browser cannot forge it) as `<sam>@<USERDNSDOMAIN>`,
 *       relying on the LDAP `ldapUserName` = sAMAccountName mapping. The plugin
 *       now only flags `agentTunnel.remoraOperator` and keeps the TOTP gate.
 *       Removes resolveOperatorUpn + the signed `remoraOperatorGrant` cookie and
 *       the companion meshuser.js patch. See meshcore.js mod 1.1.5.
 *   0.3.2 (2026-06-01) - signed operator UPN grant (SUPERSEDED by 0.3.3):
 *     - Included the server-resolved operator UPN inside a signed grant for a
 *       meshuser.js injector. Abandoned — the native tunnel username is enough.
 *   0.3.1 (2026-06-01) - operator identity source hardening (SUPERSEDED):
 *     - Added `agentTunnel.remoraOperator` + a signed grant for a meshuser.js
 *       injector. Abandoned in 0.3.3 (patch was fragile and crashed meshuser.js).
 *   0.3.0 (2026-06-01) - operator terminal context (RC-14.27):
 *     - ALLOWED_CONTEXTS gains 'operator'; PROTOCOL_MAP maps cmd|operator→1
 *       and powershell|operator→6 (Windows admin shell, same as 'system').
 *     - 'operator' is TOTP-gated identically to 'system'. The shell runs under
 *       the calling operator's AD identity via S4U2Self — the agent derives the
 *       identity from the server-injected `remoraOperatorUpn` field (added by
 *       meshuser.js from the authenticated user object after rights checks) and
 *       only checks the browser `xoptions.remoraOperator` flag to SELECT the
 *       mode, so the browser cannot choose the identity. See meshcore.js mod
 *       1.1.4.
 *   0.1.2 (2026-05-17) - wake the agent via tunnel msg:
 *     - Compute `rauth` cookie via meshServer.encodeCookie({ruserid:user._id}
 *       , loginCookieEncryptionKey). Mesh's relay handler validates it with
 *       decodeCookie(..., 240) (4-hour TTL).
 *     - Return `agentTunnel` payload so the transport layer can dispatch
 *       `{action:'msg',type:'tunnel',nodeid,value,usage:1}` via control.ashx
 *       — without this, the agent never connects to the relay, the browser
 *       side waits alone and Mesh drops it after ~30 s (code 1005).
 *     - Reject unauthenticated callers (rcookie requires user._id).
 *   0.1.1 (2026-05-17) - real Mesh terminal protocol:
 *     - PROTOCOL_MAP for shell+context → Mesh protocol number (1/6/8/9)
 *     - relayUrl now uses `browser=1&p=<N>&nodeid&id` (no junk shell/context
 *       params, no `p=2` which is desktop). Same-origin session cookie
 *       carries auth automatically.
 *     - response payload extended with `protocol` so the frontend can
 *       send the matching {protocol,cols,rows,type:'options'} handshake.
 *   0.1.0 (2026-05-16) - initial release, mock relay URL.
 */

'use strict';

var crypto = require('crypto');
var fs = require('fs');
var path = require('path');

var PLUGIN_SHORT_NAME = 'remoraTerminalBridge';
var PLUGIN_VERSION = '0.9.0';
var ALLOWED_SHELLS = ['cmd', 'powershell', 'bash', 'zsh'];
// 'operator' (RC-14.27) is a Windows admin shell (protocol 1/6) that the agent
// re-launches under the calling operator's AD identity via S4U2Self. Server-side
// it is gated exactly like 'system' (TOTP). The agent decides operator-vs-SYSTEM
// from the browser `xoptions.remoraOperator` flag + the server-trusted username.
var ALLOWED_CONTEXTS = ['user', 'system', 'operator'];

// RC-15.A.1 — server-side RBAC enforcement of the SYSTEM terminal.
// The `remoraPermissions` site-wide doc (owned by remoraCore) stores grants as
// `{ <userid>: { canUseSystemTerminal: true } }`. Super-admins implicitly hold
// every flag and are never stored. Until now `canUseSystemTerminal` was a UI-only
// gate (TerminalToolbar hid the option) — a raw `context=system` command sent past
// the UI still reached here and was issued an rauth cookie. We now verify the flag
// server-side BEFORE issuing the cookie, so the UI is no longer the authority.
var REMORA_PERMISSIONS_DOC_ID = 'remoraPermissions';
var PERMISSION_SYSTEM_TERMINAL = 'canUseSystemTerminal';
function isSuperAdmin(user) { return !!user && user.siteadmin === 0xFFFFFFFF; }

// RC-15.M.2 — server-side RemoraHQ role derivation for role-default flag
// resolution. Marker usergroup NAMES must match src/lib/utils/role.ts
// REMORA_MARKER_UGRP_NAMES (Mesh assigns random ugrp ids, so we resolve by name
// against webserver.userGroups). Siteadmin-bit subset mirrors role.ts.
var REMORA_MARKER_OPERATOR = 'RemoraHQ Operators';
var REMORA_MARKER_VIEWER = 'RemoraHQ Viewers';
var SITERIGHT_LOCKED = 32;
var SITERIGHT_MANAGEUSERS = 2;
var SITERIGHT_USERGROUPS = 256;

// RC-15.13 — Remote Install push-account vault.
// The push service account password is encrypted with Windows DPAPI
// (LocalMachine scope) and kept in a LOCAL file under meshServer.datapath, NOT
// in the Mongo-replicated DB — so on a multi-server (rs0) deployment a region
// server's blob never reaches a peer and, being machine-bound, could not be
// decrypted there anyway. The entropy below is a static application constant
// (a second DPAPI layer, not a secret); the real protection is the machine
// binding. Cred management is super-admin-only (RC-15.13); the canRemoteInstall
// flag that gates operator USE of the push is enforced in RC-15.14.
var REMORA_RI_CRED_FILE = 'remora-remoteinstall.json';
var REMORA_RI_ENTROPY = 'RemoraHQ.RemoteInstall.v1.dpapi.entropy';
// Conservative input charsets — these values are interpolated into a PowerShell
// script, so anything outside the set is rejected before the spawn.
var RI_USERNAME_RE = /^[A-Za-z0-9._\-\\@]{1,256}$/;
var RI_HOST_RE = /^[A-Za-z0-9.\-]{1,255}$/;
var RI_BLOB_RE = /^[A-Za-z0-9+/=]{1,8192}$/;
// RC-15.14 — push execution. Machine Group id form `mesh/<domain>/<seg>`
// (default domain → `mesh//<seg>`); seg is url-safe base64 (+/ as @ $).
var RI_GROUP_RE = /^mesh\/[A-Za-z0-9.\-]*\/[A-Za-z0-9@$_\-]{1,128}$/;
var RI_INSTALL_AGENTID = 4; // MeshService64.exe — signed Windows x86-64 service.
var PERMISSION_REMOTE_INSTALL = 'canRemoteInstall';
// N.1 (#12) — gates the operator "disconnect another user's session" action.
var PERMISSION_MANAGE_SESSIONS = 'canManageDeviceSessions';
// Native /meshagents installer download requires this right on the target
// device group (webserver.js handleMeshAgentRequest: GetMeshRights & 1).
// Remote Install mirrors it so canRemoteInstall cannot cross into groups the
// operator has no install rights on (RC-15.N).
var MESHRIGHT_EDITMESH = 0x00000001;
// Per-actor rate limit on the privileged push (sliding window).
var RI_RUN_MAX = 20;
var RI_RUN_WINDOW_MS = 60 * 1000;
var riRunTimes = Object.create(null);
// Reachability is lighter and UI-driven (ping refresh) — separate bucket so
// it cannot starve the real push budget, but still throttled (RC-15.N).
var RI_REACH_MAX = 30;
var riReachTimes = Object.create(null);

// v0.2.0 (RC-13.19.1) — server-side TOTP grant cache.
//
// The frontend caches a "TOTP accepted" flag per agent for 15 min so the
// user is not re-prompted for an authenticator code on every reconnect
// to the same admin shell within that window. Before v0.2.0 the server
// always required a fresh totpToken regardless, which meant every
// post-cache reconnect failed with `2fa-failed`. We now keep a parallel
// grant Map here so the server-side check honours the same TTL.
//
// Key: '<actor>|<nodeId>'  (e.g. 'user//abc|node//xyz')
// Value: epoch-ms when TOTP was last verified for that pair.
//
// In-memory only — restarting Mesh clears all grants, which is the
// safer default for a security gate.
var totpGrantCache = Object.create(null);
var TOTP_GRANT_TTL_MS = 15 * 60 * 1000;

function totpGrantKey(actor, nodeId) { return String(actor) + '|' + String(nodeId); }

function hasValidTotpGrant(actor, nodeId) {
    var k = totpGrantKey(actor, nodeId);
    var ts = totpGrantCache[k];
    if (!ts) return false;
    if (Date.now() - ts >= TOTP_GRANT_TTL_MS) { delete totpGrantCache[k]; return false; }
    return true;
}

function markTotpGrant(actor, nodeId) {
    totpGrantCache[totpGrantKey(actor, nodeId)] = Date.now();
}

// Mesh native terminal protocol numbers — see meshcore.js around lines
// 2642 (PowerShell dispatch), 2675-2734 (cmd/sh dispatch by uid), and the
// terminal protocol allow-list in meshrelay.js:584 (msgid 14, the "Started
// terminal session" audit family covers [1,6,8,9]).
//
//   1 = admin shell        (Windows cmd as SYSTEM     | Linux sh as root)
//   6 = admin PowerShell   (Windows PowerShell as SYSTEM — Windows only)
//   8 = user shell         (Windows cmd as console user| Linux sh as console user via consoleUid)
//   9 = user PowerShell    (Windows PowerShell as console user — Windows only)
//
// Linux note: Mesh does not differentiate bash vs zsh — it uses the user's
// default $SHELL. We accept bash|zsh in the API for forward-compat and UX
// parity, but they map to the same protocol numbers as a generic shell.
var PROTOCOL_MAP = {
    'cmd|user':         8,
    'cmd|system':       1,
    'cmd|operator':     1,
    'powershell|user':  9,
    'powershell|system': 6,
    'powershell|operator': 6,
    'bash|user':        8,
    'bash|system':      1,
    'zsh|user':         8,
    'zsh|system':       1
};

module.exports.remoraTerminalBridge = function (parent) {
    var obj = {};
    obj.parent = parent;
    obj.meshServer = parent.parent;

    obj.exports = ['serveraction'];

    obj.server_startup = function () {
        console.log('[remoraTerminalBridge] v' + PLUGIN_VERSION + ' loaded.');
    };

    function reply(session, command, payload) {
        var body = Object.assign({
            action: 'plugin',
            plugin: PLUGIN_SHORT_NAME,
            pluginaction: command.pluginaction,
            tag: command.tag,
            responseid: command.responseid || command.tag,
            result: 'ok'
        }, payload || {});
        try { session.send(body); } catch (e) { /* ignore */ }
    }

    function replyError(session, command, error, meta) {
        try {
            session.send(Object.assign({
                action: 'plugin',
                plugin: PLUGIN_SHORT_NAME,
                pluginaction: command.pluginaction || 'unknown',
                tag: command.tag,
                responseid: command.responseid || command.tag,
                result: 'error',
                error: String(error || 'remora_terminal_bridge_failed')
            }, meta || {}));
        } catch (e) { /* ignore */ }
    }

    function newSessionId() {
        // 16-byte random → 32-char hex. Plenty for a relay correlation token.
        return crypto.randomBytes(16).toString('hex');
    }

    function verifyTotp(user, token) {
        if (!user || !user.otpsecret) return false;
        if (typeof token !== 'string' || token.length !== 6) return false;
        try {
            var otplib = require('otplib');
            otplib.authenticator.options = { window: 2 }; // ±1 min, same as Mesh login
            return otplib.authenticator.check(token, user.otpsecret) === true;
        } catch (e) {
            console.log('[remoraTerminalBridge] otplib unavailable:', e.message);
            return false;
        }
    }

    // RC-15.M.2 — derive a user's RemoraHQ role server-side (super_admin handled
    // by callers). Mirrors siteadminToRole() in src/lib/utils/role.ts. auditor is
    // collapsed to viewer (never carries these flags by default; a per-user
    // override wins anyway). Fail-safe default = viewer (least privilege).
    function deriveRemoraRole(user) {
        if (isSuperAdmin(user)) return 'super_admin';
        var sa = (typeof user.siteadmin === 'number') ? user.siteadmin : 0;
        if (sa !== 0) {
            var cleared = (sa & ~SITERIGHT_LOCKED) >>> 0;
            if ((cleared & (SITERIGHT_MANAGEUSERS | SITERIGHT_USERGROUPS)) !== 0) return 'administrator';
        }
        var ws = obj.meshServer && obj.meshServer.webserver;
        var ugs = ws && ws.userGroups;
        if (ugs && user.links) {
            // operator takes priority over viewer when both markers present.
            var isViewer = false;
            for (var lk in user.links) {
                if (lk.indexOf('ugrp/') !== 0) continue;
                var g = ugs[lk];
                if (!g) continue;
                if (g.name === REMORA_MARKER_OPERATOR) return 'operator';
                if (g.name === REMORA_MARKER_VIEWER) isViewer = true;
            }
            if (isViewer) return 'viewer';
        }
        return 'viewer';
    }

    // RC-15.M.2 — resolve the effective value of a RemoraHQ flag:
    //   override (grants[user][flag], tri-state) ?? roleDefault[role][flag] ?? false
    // Super-admins pass implicitly. Fail-closed: any missing DB access denies.
    function resolveRemoraFlag(user, flag, cb) {
        if (isSuperAdmin(user)) return cb(true);
        if (!obj.meshServer || !obj.meshServer.db || typeof obj.meshServer.db.Get !== 'function') {
            return cb(false);
        }
        obj.meshServer.db.Get(REMORA_PERMISSIONS_DOC_ID, function (err, docs) {
            var doc0 = (!err && docs && docs.length > 0) ? docs[0] : null;
            var grants = (doc0 && doc0.grants && typeof doc0.grants === 'object') ? doc0.grants : {};
            var mine = grants[user._id] || {};
            if (typeof mine[flag] === 'boolean') return cb(mine[flag]); // explicit override wins
            var roleDefaults = (doc0 && doc0.roleDefaults && typeof doc0.roleDefaults === 'object') ? doc0.roleDefaults : {};
            var rd = roleDefaults[deriveRemoraRole(user)] || {};
            return cb(rd[flag] === true);
        });
    }

    // RC-15.A.1 — SYSTEM-terminal gate; now resolves role-default + override (M.2).
    function hasSystemTerminalPermission(user, cb) {
        resolveRemoraFlag(user, PERMISSION_SYSTEM_TERMINAL, cb);
    }

    function dispatchAudit(actor, payload) {
        try {
            if (!obj.meshServer || typeof obj.meshServer.DispatchEvent !== 'function') return;
            var targets = ['*', 'server-users'];
            if (actor) targets.push(actor);
            obj.meshServer.DispatchEvent(targets, obj, Object.assign({
                etype: 'terminal-open',
                action: 'plugin.terminal.open'
            }, payload));
        } catch (e) {
            console.log('[remoraTerminalBridge] audit dispatch failed:', e.message);
        }
    }

    // RC-15.13/.14 — audit for Remote Install (cred management + push). Distinct
    // action so compliance can filter these separately from terminal opens.
    function dispatchRiAudit(actor, payload) {
        try {
            if (!obj.meshServer || typeof obj.meshServer.DispatchEvent !== 'function') return;
            var targets = ['*', 'server-users'];
            if (actor) targets.push(actor);
            obj.meshServer.DispatchEvent(targets, obj, Object.assign({
                etype: 'remote-install',
                action: 'plugin.remoteinstall'
            }, payload));
        } catch (e) {
            console.log('[remoraTerminalBridge] RI audit dispatch failed:', e.message);
        }
    }

    // ---- RC-15.13: Remote Install push-account vault --------------------------

    function riCredFilePath() {
        var dp = obj.meshServer && obj.meshServer.datapath;
        if (!dp || typeof dp !== 'string') return null;
        return path.join(dp, REMORA_RI_CRED_FILE);
    }

    function riReadCredMeta() {
        try {
            var p = riCredFilePath();
            if (!p) return null;
            var j = JSON.parse(fs.readFileSync(p, 'utf8'));
            return (j && typeof j === 'object') ? j : null;
        } catch (e) { return null; }
    }

    function riWriteCredMeta(meta) {
        var p = riCredFilePath();
        if (!p) throw new Error('no_datapath');
        fs.writeFileSync(p, JSON.stringify(meta, null, 2), { encoding: 'utf8', mode: 0o600 });
    }

    // PowerShell -EncodedCommand wants base64 of UTF-16LE.
    function psEncode(script) { return Buffer.from(script, 'utf16le').toString('base64'); }

    // Spawn Windows PowerShell (5.1, always present on the Windows Mesh host and
    // the only runtime guaranteed to ship the DPAPI ProtectedData API). The
    // script is passed via -EncodedCommand so stdin stays free for the secret.
    function runPowerShell(script, stdinText, cb, timeoutMs) {
        var cp = require('child_process');
        var done = false, out = '', err = '', timer = null, ps;
        function finish(e, res) {
            if (done) return; done = true;
            if (timer) clearTimeout(timer);
            cb(e, res);
        }
        try {
            ps = cp.spawn('powershell.exe', [
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                '-EncodedCommand', psEncode(script)
            ], { windowsHide: true });
        } catch (e) { return finish(e); }
        timer = setTimeout(function () { try { ps.kill(); } catch (x) { /* ignore */ } finish(new Error('powershell_timeout')); }, timeoutMs || 30000);
        ps.stdout.on('data', function (d) { out += d.toString('utf8'); });
        ps.stderr.on('data', function (d) { err += d.toString('utf8'); });
        ps.on('error', function (e) { finish(e); });
        ps.on('close', function (code) { finish(null, { code: code, stdout: out.trim(), stderr: err.trim() }); });
        try { if (stdinText != null) ps.stdin.write(String(stdinText) + '\n'); ps.stdin.end(); } catch (e) { /* ignore */ }
    }

    // Encrypt: password arrives on stdin, never on the command line.
    function riProtectScript() {
        return [
            "$ErrorActionPreference='Stop'",
            "try {",
            "  Add-Type -AssemblyName System.Security",
            "  $pw = [Console]::In.ReadLine()",
            "  $b = [Text.Encoding]::UTF8.GetBytes($pw)",
            "  $e = [Text.Encoding]::UTF8.GetBytes('" + REMORA_RI_ENTROPY + "')",
            "  $p = [Security.Cryptography.ProtectedData]::Protect($b, $e, [Security.Cryptography.DataProtectionScope]::LocalMachine)",
            "  Write-Output ([Convert]::ToBase64String($p))",
            "} catch { Write-Error $_.Exception.Message; exit 1 }"
        ].join("\n");
    }

    // Decrypt + (optionally) validate against a host. blob/user/host are
    // pre-validated against RI_*_RE before interpolation. Plaintext lives only
    // inside this PowerShell process.
    function riTestScript(blob, username, host) {
        var lines = [
            "$ErrorActionPreference='Stop'",
            "try {",
            "  Add-Type -AssemblyName System.Security",
            "  $enc = [Convert]::FromBase64String('" + blob + "')",
            "  $e = [Text.Encoding]::UTF8.GetBytes('" + REMORA_RI_ENTROPY + "')",
            "  $dec = [Security.Cryptography.ProtectedData]::Unprotect($enc, $e, [Security.Cryptography.DataProtectionScope]::LocalMachine)",
            "  $pw = [Text.Encoding]::UTF8.GetString($dec)",
            "  $sec = ConvertTo-SecureString $pw -AsPlainText -Force",
            "  $pw = $null",
            "  $cred = New-Object System.Management.Automation.PSCredential('" + username + "', $sec)"
        ];
        if (host) {
            lines.push("  $r = Invoke-Command -ComputerName '" + host + "' -Authentication Negotiate -Credential $cred -ScriptBlock { 'ok' } -ErrorAction Stop");
            lines.push("  if ($r -eq 'ok') { Write-Output 'winrm-ok' } else { Write-Output 'winrm-unexpected' }");
        } else {
            lines.push("  if ($cred) { Write-Output 'decrypt-ok' }");
        }
        lines.push("} catch { Write-Error $_.Exception.Message; exit 1 }");
        return lines.join("\n");
    }

    function handleRiAccountStatus(command, dbGet, session) {
        var user = dbGet && dbGet.user;
        if (!isSuperAdmin(user)) return replyError(session, command, 'forbidden');
        var meta = riReadCredMeta();
        reply(session, command, {
            configured: !!(meta && meta.blob),
            username: (meta && meta.username) || null,
            createdBy: (meta && meta.createdBy) || null,
            createdAt: (meta && meta.createdAt) || null,
            lastTestAt: (meta && meta.lastTestAt) || null,
            lastTestResult: (meta && meta.lastTestResult) || null
        });
    }

    function handleRiSetAccount(command, dbGet, session) {
        var user = dbGet && dbGet.user;
        if (!isSuperAdmin(user)) return replyError(session, command, 'forbidden');
        var actor = user._id;
        var username = String(command.username || '');
        var password = String(command.password || '');
        if (!RI_USERNAME_RE.test(username) || password.length === 0 || password.length > 1024) {
            return replyError(session, command, 'invalid_input');
        }
        if (!riCredFilePath()) return replyError(session, command, 'no_datapath');
        runPowerShell(riProtectScript(), password, function (err, res) {
            if (err || !res || res.code !== 0 || !RI_BLOB_RE.test(res.stdout || '')) {
                dispatchRiAudit(actor, { msg: 'Remote Install account set failed', actor: actor, username: username, status: 'error' });
                return replyError(session, command, 'protect_failed');
            }
            try {
                riWriteCredMeta({
                    username: username,
                    blob: res.stdout,
                    createdBy: actor,
                    createdAt: new Date().toISOString(),
                    lastTestAt: null,
                    lastTestResult: null
                });
            } catch (e) {
                return replyError(session, command, 'write_failed');
            }
            dispatchRiAudit(actor, { msg: 'Remote Install push account configured', actor: actor, username: username, status: 'success' });
            reply(session, command, { configured: true, username: username });
        });
    }

    function handleRiTestAccount(command, dbGet, session) {
        var user = dbGet && dbGet.user;
        if (!isSuperAdmin(user)) return replyError(session, command, 'forbidden');
        var actor = user._id;
        var meta = riReadCredMeta();
        if (!meta || !meta.blob) return replyError(session, command, 'not_configured');
        if (!RI_BLOB_RE.test(meta.blob) || !RI_USERNAME_RE.test(meta.username || '')) {
            return replyError(session, command, 'corrupt_cred');
        }
        var host = (command.testHost != null) ? String(command.testHost) : '';
        if (host && !RI_HOST_RE.test(host)) return replyError(session, command, 'invalid_host');
        runPowerShell(riTestScript(meta.blob, meta.username, host || null), null, function (err, res) {
            var ok = !err && res && res.code === 0 && /^(winrm-ok|decrypt-ok)$/.test(res.stdout || '');
            var result = ok ? (host ? 'winrm-ok' : 'decrypt-ok') : 'failed';
            try {
                meta.lastTestAt = new Date().toISOString();
                meta.lastTestResult = result;
                riWriteCredMeta(meta);
            } catch (e) { /* non-fatal */ }
            dispatchRiAudit(actor, { msg: 'Remote Install account test', actor: actor, username: meta.username, host: host || null, status: ok ? 'success' : 'denied' });
            // NOTE: use `testResult`, NOT `result` — `result` is the protocol
            // envelope field ('ok'|'error') set by reply(); a `result` key in the
            // payload would clobber the 'ok' marker the client checks.
            if (ok) return reply(session, command, { ok: true, testResult: result });
            return replyError(session, command, host ? 'winrm_failed' : 'decrypt_failed');
        });
    }

    // ---- RC-15.14: Remote Install reachability + push --------------------------

    // canRemoteInstall gate; resolves role-default + override (M.2).
    function hasRemoteInstallPermission(user, cb) {
        resolveRemoraFlag(user, PERMISSION_REMOTE_INSTALL, cb);
    }

    function riRateLimitOk(actor, bucket, max) {
        bucket = bucket || riRunTimes;
        max = max || RI_RUN_MAX;
        var now = Date.now();
        var arr = (bucket[actor] || []).filter(function (t) { return now - t < RI_RUN_WINDOW_MS; });
        if (arr.length >= max) { bucket[actor] = arr; return false; }
        arr.push(now); bucket[actor] = arr; return true;
    }

    // Per-mesh authz for Remote Install: the caller must hold MESHRIGHT_EDITMESH
    // on the target group (super-admin implicit). Mirrors the native installer
    // download check; fail-closed on any missing server API.
    function hasGroupInstallRight(user, groupId) {
        if (isSuperAdmin(user)) return true;
        var ws = obj.meshServer && obj.meshServer.webserver;
        if (!ws || typeof ws.GetMeshRights !== 'function' || !ws.meshes || !ws.meshes[groupId]) return false;
        return (ws.GetMeshRights(user, groupId) & MESHRIGHT_EDITMESH) !== 0;
    }

    // RC-15.RINST-1 (#14) — does the typed install target already correspond to
    // a registered node? Hostname targets match node.name / node.rname / node.host
    // ignoring any domain suffix; IP targets match node.host / node.ip exactly.
    function riTargetMatchesNode(target, node) {
        var t = String(target || '').toLowerCase().trim();
        if (!t || !node) return false;
        var isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(t);
        var fields = isIp ? [node.host, node.ip] : [node.name, node.rname, node.host];
        var tShort = t.split('.')[0];
        for (var i = 0; i < fields.length; i++) {
            var c = fields[i];
            if (!c) continue;
            var cl = String(c).toLowerCase().trim();
            if (!cl) continue;
            if (cl === t) return true;
            if (!isIp && cl.split('.')[0] === tShort && tShort.length > 0) return true;
        }
        return false;
    }

    // Scan ALL nodes (cross-group, NOT gated by the operator's visible groups —
    // the duplicate may live in a group the operator cannot see, which is exactly
    // the incident this guards) for an agent already registered for `target`.
    // cb(err, match | null) where match = { node, visible, groupName }.
    function riFindExistingNode(user, target, cb) {
        var db = obj.meshServer && obj.meshServer.db;
        if (!db || typeof db.GetAllType !== 'function') return cb(new Error('db_unavailable'));
        db.GetAllType('node', function (err, nodes) {
            if (err || !Array.isArray(nodes)) return cb(err || new Error('db_scan_failed'));
            for (var i = 0; i < nodes.length; i++) {
                var n = nodes[i];
                if (!n || n.type !== 'node') continue;
                if (!riTargetMatchesNode(target, n)) continue;
                var ws = obj.meshServer && obj.meshServer.webserver;
                var visible = isSuperAdmin(user) ||
                    (ws && typeof ws.GetMeshRights === 'function' && n.meshid && (ws.GetMeshRights(user, n.meshid) !== 0));
                // Only expose the group name when the operator may already see it;
                // never leak a foreign group's name.
                var groupName = (visible && ws && ws.meshes && ws.meshes[n.meshid] && ws.meshes[n.meshid].name) || null;
                return cb(null, { node: n, visible: !!visible, groupName: groupName });
            }
            return cb(null, null);
        });
    }

    // Build the .msh policy + stream the per-group agent into a temp file.
    // Mirrors webserver.js handleAgentRequest (the native /meshagents path) for
    // the connectivity-critical fields. Optional domain agentcustomization
    // (displayName/serviceName/etc.) is NOT replicated — the agent still connects;
    // branding parity can be added later if needed. cb(err, localExePath).
    function riGenerateInstaller(groupId, installFlags, cb) {
        try {
            var ws = obj.meshServer.webserver;
            if (!ws || !ws.meshes || !obj.meshServer.exeHandler || !obj.meshServer.meshAgentBinaries) return cb(new Error('server_api_unavailable'));
            var mesh = ws.meshes[groupId];
            if (!mesh) return cb(new Error('invalid_group'));

            var parts = groupId.split('/');           // ['mesh', '<domain>', '<seg>']
            var domainId = parts[1] || '';
            var seg = parts[2] || '';
            var domain = (obj.meshServer.config && obj.meshServer.config.domains && obj.meshServer.config.domains[domainId]) || { id: domainId, dns: null };

            var meshidhex = Buffer.from(seg.replace(/@/g, '+').replace(/\$/g, '/'), 'base64').toString('hex').toUpperCase();
            var serveridhex = String(ws.agentCertificateHashHex || '').toUpperCase();
            if (!meshidhex || !serveridhex) return cb(new Error('id_resolve_failed'));

            var args = obj.meshServer.args || {};
            var httpsPort = (args.aliasport == null) ? args.port : args.aliasport;
            if (args.agentport != null) httpsPort = args.agentport;
            if (args.agentaliasport != null) httpsPort = args.agentaliasport;

            var serverName = (typeof ws.getWebServerName === 'function') ? ws.getWebServerName(domain, null) : (obj.meshServer.certificates && obj.meshServer.certificates.CommonName);
            if (!serverName || serverName === 'un-configured') return cb(new Error('servername_unresolved'));
            var xdomain = (domainId === '') ? '' : (domainId + '/');

            var msh = '\r\nMeshName=' + mesh.name + '\r\nMeshType=' + mesh.mtype + '\r\nMeshID=0x' + meshidhex + '\r\nServerID=' + serveridhex + '\r\n';
            if (args.lanonly === true) { msh += 'MeshServer=local\r\n'; }
            else { msh += 'MeshServer=wss://' + serverName + ':' + httpsPort + '/' + xdomain + 'agent.ashx\r\n'; }
            if (installFlags && parseInt(installFlags, 10) === installFlags) { msh += 'InstallFlags=' + parseInt(installFlags, 10) + '\r\n'; }

            var binId = RI_INSTALL_AGENTID;
            var bin = (domain.meshAgentBinaries && domain.meshAgentBinaries[binId]) || obj.meshServer.meshAgentBinaries[binId];
            if (!bin || !bin.path) return cb(new Error('agent_binary_missing'));

            var tmpDir = path.join(obj.meshServer.datapath, 'remora-ri-tmp');
            try { fs.mkdirSync(tmpDir, { recursive: true }); } catch (e) { /* exists */ }
            var localExe = path.join(tmpDir, 'ra-' + crypto.randomBytes(8).toString('hex') + '.exe');

            var outStream = fs.createWriteStream(localExe);
            var settled = false;
            function done(err) { if (settled) return; settled = true; cb(err, err ? null : localExe); }
            outStream.on('error', function (e) { done(e); });
            outStream.on('close', function () { done(null); });
            try {
                obj.meshServer.exeHandler.streamExeWithMeshPolicy({
                    platform: 'win32', sourceFileName: bin.path, destinationStream: outStream, msh: msh, peinfo: bin.pe
                });
            } catch (e) { done(e); }
        } catch (e) { cb(e); }
    }

    function riCleanup(localExe) { if (localExe) { try { fs.unlinkSync(localExe); } catch (e) { /* ignore */ } } }

    // Reachability precheck: ICMP + WinRM bind with the stored push cred.
    function riReachabilityScript(blob, username, host) {
        return [
            "$ErrorActionPreference='Stop'",
            "$ping=$false; $winrm=$false",
            "try { $ping = Test-Connection -ComputerName '" + host + "' -Count 1 -Quiet } catch {}",
            "try {",
            "  Add-Type -AssemblyName System.Security",
            "  $enc=[Convert]::FromBase64String('" + blob + "')",
            "  $e=[Text.Encoding]::UTF8.GetBytes('" + REMORA_RI_ENTROPY + "')",
            "  $dec=[Security.Cryptography.ProtectedData]::Unprotect($enc,$e,[Security.Cryptography.DataProtectionScope]::LocalMachine)",
            "  $pw=[Text.Encoding]::UTF8.GetString($dec); $sec=ConvertTo-SecureString $pw -AsPlainText -Force; $pw=$null",
            "  $cred=New-Object System.Management.Automation.PSCredential('" + username + "',$sec)",
            "  $r=Invoke-Command -ComputerName '" + host + "' -Authentication Negotiate -Credential $cred -ScriptBlock { 'ok' } -ErrorAction Stop",
            "  if ($r -eq 'ok') { $winrm=$true }",
            "} catch {}",
            "Write-Output ('ping=' + $ping + ';winrm=' + $winrm)"
        ].join("\n");
    }

    // Push: open one PSSession, copy the generated agent, run -fullinstall, clean up.
    function riRunScript(blob, username, host, localExe) {
        return [
            "$ErrorActionPreference='Stop'",
            "try {",
            "  Add-Type -AssemblyName System.Security",
            "  $enc=[Convert]::FromBase64String('" + blob + "')",
            "  $e=[Text.Encoding]::UTF8.GetBytes('" + REMORA_RI_ENTROPY + "')",
            "  $dec=[Security.Cryptography.ProtectedData]::Unprotect($enc,$e,[Security.Cryptography.DataProtectionScope]::LocalMachine)",
            "  $pw=[Text.Encoding]::UTF8.GetString($dec); $sec=ConvertTo-SecureString $pw -AsPlainText -Force; $pw=$null",
            "  $cred=New-Object System.Management.Automation.PSCredential('" + username + "',$sec)",
            "  $s=New-PSSession -ComputerName '" + host + "' -Authentication Negotiate -Credential $cred -ErrorAction Stop",
            "  try {",
            "    $rt = Invoke-Command -Session $s -ScriptBlock { Join-Path $env:TEMP ('ra-' + [guid]::NewGuid().ToString('N') + '.exe') }",
            "    Copy-Item -ToSession $s -Path '" + localExe.replace(/'/g, "''") + "' -Destination $rt -Force",
            "    $code = Invoke-Command -Session $s -ScriptBlock { param($p) & $p -fullinstall | Out-Null; $c=$LASTEXITCODE; Start-Sleep -Seconds 1; Remove-Item $p -Force -ErrorAction SilentlyContinue; $c } -ArgumentList $rt",
            "    Write-Output ('install-exit:' + $code)",
            "  } finally { Remove-PSSession $s }",
            "} catch { Write-Error $_.Exception.Message; exit 1 }"
        ].join("\n");
    }

    function handleRiReachability(command, dbGet, session) {
        var user = dbGet && dbGet.user;
        hasRemoteInstallPermission(user, function (allowed) {
            if (!allowed) {
                dispatchRiAudit(user && user._id, { msg: 'Remote Install reachability denied', actor: user && user._id, status: 'denied' });
                return replyError(session, command, 'permission_denied');
            }
            var host = String(command.host || '');
            var groupId = String(command.groupId || '');
            if (!RI_HOST_RE.test(host)) return replyError(session, command, 'invalid_host');
            if (!RI_GROUP_RE.test(groupId)) return replyError(session, command, 'invalid_group');
            if (!hasGroupInstallRight(user, groupId)) {
                dispatchRiAudit(user && user._id, { msg: 'Remote Install reachability denied (no rights on group)', actor: user && user._id, host: host, group: groupId, status: 'denied' });
                return replyError(session, command, 'permission_denied');
            }
            if (!riRateLimitOk(user && user._id, riReachTimes, RI_REACH_MAX)) {
                dispatchRiAudit(user && user._id, { msg: 'Remote Install reachability rate-limited', actor: user && user._id, host: host, status: 'denied' });
                return replyError(session, command, 'rate_limited');
            }
            var meta = riReadCredMeta();
            if (!meta || !meta.blob || !RI_BLOB_RE.test(meta.blob) || !RI_USERNAME_RE.test(meta.username || '')) {
                return replyError(session, command, 'not_configured');
            }
            runPowerShell(riReachabilityScript(meta.blob, meta.username, host), null, function (err, res) {
                if (err || !res) return replyError(session, command, 'reachability_failed');
                var out = res.stdout || '';
                var ping = /ping=True/i.test(out);
                var winrm = /winrm=True/i.test(out);
                // RC-15.RINST-1 (#14) — advisory only: warn the operator a node is
                // already registered for this host before they spend a TOTP. A
                // scan error here is non-fatal (the run path hard-blocks anyway).
                riFindExistingNode(user, host, function (scanErr, match) {
                    reply(session, command, {
                        reachable: ping, winrm: winrm,
                        existing: !!(match && !scanErr),
                        existingVisible: match ? match.visible : undefined,
                        existingGroup: (match && match.groupName) || undefined
                    });
                });
            });
        });
    }

    function handleRiRun(command, dbGet, session) {
        var user = dbGet && dbGet.user;
        hasRemoteInstallPermission(user, function (allowed) {
            var actor = user && user._id;
            if (!allowed) {
                dispatchRiAudit(actor, { msg: 'Remote Install push denied (missing canRemoteInstall)', actor: actor, status: 'denied' });
                return replyError(session, command, 'permission_denied');
            }
            var host = String(command.host || '');
            var groupId = String(command.groupId || '');
            var installFlags = (typeof command.installFlags === 'number') ? command.installFlags : 0;
            var totpToken = command.totpToken;
            if (!RI_HOST_RE.test(host)) return replyError(session, command, 'invalid_host');
            if (!RI_GROUP_RE.test(groupId)) return replyError(session, command, 'invalid_group');

            // Per-mesh authz: caller must hold install rights on the target group
            // (cross-mesh priv-esc guard — the "visible groups only" rule was
            // client-side only before RC-15.N).
            if (!hasGroupInstallRight(user, groupId)) {
                dispatchRiAudit(actor, { msg: 'Remote Install push denied (no rights on group)', actor: actor, host: host, group: groupId, status: 'denied' });
                return replyError(session, command, 'permission_denied');
            }

            // TOTP step-up (fresh token or a still-valid grant for this actor+host).
            if (!hasValidTotpGrant(actor, host)) {
                if (!verifyTotp(user, totpToken)) {
                    dispatchRiAudit(actor, { msg: 'Remote Install push denied (TOTP)', actor: actor, host: host, group: groupId, status: 'denied' });
                    return replyError(session, command, '2fa-failed');
                }
                markTotpGrant(actor, host);
            }
            if (!riRateLimitOk(actor)) {
                dispatchRiAudit(actor, { msg: 'Remote Install push rate-limited', actor: actor, host: host, status: 'denied' });
                return replyError(session, command, 'rate_limited');
            }
            var meta = riReadCredMeta();
            if (!meta || !meta.blob || !RI_BLOB_RE.test(meta.blob) || !RI_USERNAME_RE.test(meta.username || '')) {
                return replyError(session, command, 'not_configured');
            }

            // RC-15.RINST-1 (#14) — block a redundant push if an agent is already
            // registered for this host (possibly in a group the operator cannot
            // see). Fail-closed: if the scan cannot complete, refuse rather than
            // risk a duplicate install.
            riFindExistingNode(user, host, function (scanErr, match) {
                if (scanErr) {
                    dispatchRiAudit(actor, { msg: 'Remote Install dup-check failed', actor: actor, host: host, group: groupId, status: 'error', detail: scanErr.message });
                    return replyError(session, command, 'dup_check_failed');
                }
                if (match) {
                    dispatchRiAudit(actor, { msg: 'Remote Install push blocked (agent already present)', actor: actor, host: host, group: groupId, status: 'blocked', existingVisible: match.visible });
                    return replyError(session, command, 'agent_exists', { existingVisible: match.visible, existingGroup: match.groupName || undefined });
                }
                proceedInstall();
            });

            function proceedInstall() {
            riGenerateInstaller(groupId, installFlags, function (genErr, localExe) {
                if (genErr || !localExe) {
                    dispatchRiAudit(actor, { msg: 'Remote Install installer-gen failed', actor: actor, host: host, group: groupId, status: 'error', detail: genErr && genErr.message });
                    return replyError(session, command, 'installer_gen_failed');
                }
                runPowerShell(riRunScript(meta.blob, meta.username, host, localExe), null, function (err, res) {
                    riCleanup(localExe);
                    var m = res && /install-exit:(-?\d+)/.exec(res.stdout || '');
                    var exitCode = m ? parseInt(m[1], 10) : null;
                    var ok = !err && res && res.code === 0 && exitCode === 0;
                    dispatchRiAudit(actor, {
                        msg: ok ? 'Remote Install push succeeded' : 'Remote Install push failed',
                        actor: actor, host: host, group: groupId, exitCode: exitCode, status: ok ? 'success' : 'error'
                    });
                    if (ok) return reply(session, command, { ok: true, host: host, group: groupId });
                    return replyError(session, command, 'install_failed');
                }, 180000); // push can take a while: download already local, copy + -fullinstall
            });
            } // proceedInstall
        });
    }

    // N.1 (#12) part-2 — disconnect another user's live session on a node.
    // Gated by the RemoraHQ flag canManageDeviceSessions (super-admin implicit,
    // grantable to e.g. department heads). The agent itself only force-closes
    // ANOTHER user's tunnel when rights == 0xFFFFFFFF (meshcore endtunnel), so a
    // raw operator cannot bypass this — only this handler, AFTER verifying the
    // flag, sends the elevated rights that authorise the disconnect.
    function handleEndDeviceSession(command, dbGet, session) {
        var user = dbGet && dbGet.user;
        var actor = user ? user._id : null;
        if (!actor) return replyError(session, command, 'auth_required');

        var nodeId = String(command.nodeId || '');
        var protocol = String(command.protocol || '');
        var xuserid = String(command.xuserid || '');
        if (!nodeId || nodeId.indexOf('node//') !== 0) return replyError(session, command, 'invalid_nodeId');
        if (['kvm', 'terminal', 'files'].indexOf(protocol) === -1) return replyError(session, command, 'invalid_protocol');
        if (!xuserid || xuserid.indexOf('user/') !== 0) return replyError(session, command, 'invalid_target');

        resolveRemoraFlag(user, PERMISSION_MANAGE_SESSIONS, function (allowed) {
            if (!allowed) {
                dispatchAudit(actor, { msg: 'Disconnect session denied: missing canManageDeviceSessions', nodeid: nodeId, target: xuserid, protocol: protocol, actor: actor, status: 'denied' });
                return replyError(session, command, 'permission_denied');
            }
            var web = obj.meshServer && obj.meshServer.webserver;
            if (!web || typeof web.GetNodeWithRights !== 'function' || !web.wsagents) {
                return replyError(session, command, 'server_api_unavailable');
            }
            // RBAC defense-in-depth: the caller must be able to SEE the target
            // node. The flag does not grant cross-group reach (discipline of #14).
            var domainid = actor.split('/')[1] || '';
            var domain = (obj.meshServer.config && obj.meshServer.config.domains &&
                (obj.meshServer.config.domains[domainid] || obj.meshServer.config.domains[''])) || { id: domainid };
            web.GetNodeWithRights(domain, user, nodeId, function (node, rights, visible) {
                if (node == null || !visible) {
                    dispatchAudit(actor, { msg: 'Disconnect session denied: node not visible', nodeid: nodeId, target: xuserid, actor: actor, status: 'denied' });
                    return replyError(session, command, 'permission_denied');
                }
                var agent = web.wsagents[nodeId];
                if (!agent || typeof agent.send !== 'function') {
                    return replyError(session, command, 'agent_offline');
                }
                try {
                    // Mirrors the native endtunnel command (meshcore switch
                    // action='msg' -> type='endtunnel'); nodeid is implied by the
                    // agent connection. rights=0xFFFFFFFF authorises closing
                    // another user's tunnel — justified by the flag check above.
                    agent.send(JSON.stringify({
                        action: 'msg', type: 'endtunnel',
                        xuserid: xuserid, protocol: protocol, guestname: null,
                        userid: actor, rights: 0xFFFFFFFF
                    }));
                } catch (e) {
                    return replyError(session, command, 'route_failed');
                }
                dispatchAudit(actor, { msg: 'Disconnected device session', nodeid: nodeId, target: xuserid, protocol: protocol, actor: actor, status: 'success' });
                return reply(session, command, { ok: true });
            });
        });
    }

    obj.serveraction = function (command, dbGet, ws) {
        var session = dbGet || ws;
        if (!session || typeof session.send !== 'function') return;

        var action = String(command.pluginaction || '');
        if (action === 'endDeviceSession') return handleEndDeviceSession(command, dbGet, session);
        // RC-15.13 — Remote Install cred-vault actions (super-admin-only, gated
        // inside each handler). Kept ahead of the terminal 'open' path so the
        // existing flow below is untouched.
        if (action === 'remoteInstall.accountStatus') return handleRiAccountStatus(command, dbGet, session);
        if (action === 'remoteInstall.setAccount') return handleRiSetAccount(command, dbGet, session);
        if (action === 'remoteInstall.testAccount') return handleRiTestAccount(command, dbGet, session);
        if (action === 'remoteInstall.reachability') return handleRiReachability(command, dbGet, session);
        if (action === 'remoteInstall.run') return handleRiRun(command, dbGet, session);
        if (action !== 'open') return replyError(session, command, 'unknown_pluginaction');

        var nodeId = (command.nodeId != null) ? String(command.nodeId) : '';
        var shell = String(command.shell || '');
        var context = String(command.context || 'user');
        var totpToken = command.totpToken;

        if (!nodeId || nodeId.indexOf('node//') !== 0) {
            return replyError(session, command, 'invalid_nodeId');
        }
        if (ALLOWED_SHELLS.indexOf(shell) === -1) {
            return replyError(session, command, 'invalid_shell');
        }
        if (ALLOWED_CONTEXTS.indexOf(context) === -1) {
            return replyError(session, command, 'invalid_context');
        }

        var protocol = PROTOCOL_MAP[shell + '|' + context];
        if (typeof protocol !== 'number') {
            return replyError(session, command, 'unsupported_shell_context');
        }

        // Resolve the calling user — meshuser session attaches it as `dbGet.user`.
        var user = dbGet && dbGet.user;
        var actor = user ? user._id : null;
        if (!actor) {
            return replyError(session, command, 'auth_required');
        }

        // RC-15.A.1 — server-enforce the SYSTEM terminal BEFORE issuing the
        // rauth cookie. context='system' requires canUseSystemTerminal (or
        // super-admin); without it a raw command past the UI is denied here.
        // user/operator are unaffected (operator keeps its own TOTP tier).
        // The rest of the open flow runs in proceedOpen() so it can wait on the
        // async grant lookup; the function is hoisted so it's callable above.
        if (context === 'system') {
            hasSystemTerminalPermission(user, function (allowed) {
                if (!allowed) {
                    dispatchAudit(actor, {
                        msg: 'Terminal open denied: missing canUseSystemTerminal',
                        nodeid: nodeId,
                        shell: shell,
                        context: context,
                        protocol: protocol,
                        actor: actor,
                        status: 'denied'
                    });
                    return replyError(session, command, 'permission_denied');
                }
                proceedOpen();
            });
        } else {
            proceedOpen();
        }
        return;

        function proceedOpen() {
        // SYSTEM context requires either a fresh TOTP token OR a still-valid
        // grant from a prior successful TOTP for this (actor, nodeId). The
        // grant TTL mirrors the frontend cache so the UI's "skip prompt"
        // assumption no longer leads to a server-side rejection
        // (RC-13.19.1 fix; before v0.2.0 every reconnect failed with
        // 2fa-failed because the client cached the grant but the server
        // demanded a fresh code each time).
        if (context === 'system' || context === 'operator') {
            var grantOk = hasValidTotpGrant(actor, nodeId);
            if (!grantOk) {
                if (!verifyTotp(user, totpToken)) {
                    dispatchAudit(actor, {
                        msg: 'Terminal open denied: invalid TOTP for SYSTEM context',
                        nodeid: nodeId,
                        shell: shell,
                        context: context,
                        protocol: protocol,
                        actor: actor,
                        status: 'denied'
                    });
                    return replyError(session, command, '2fa-failed');
                }
                markTotpGrant(actor, nodeId);
            }
            // else: grant still valid — TOTP not requested, audit-flag below
            // distinguishes the two paths so compliance reviews can see how
            // each system-context open was authorised.
        }

        // Mesh agent-side rauth cookie. Mesh's relay handler validates the
        // browser-issued `?rauth=<cookie>` query via
        //   meshServer.decodeCookie(rauth, loginCookieEncryptionKey, 240)
        // and accepts the agent side if `rcookie.ruserid` is set. The 240
        // means the cookie expires in 4 hours, same as Mesh native.
        var rcookie = null;
        try {
            if (obj.meshServer
                && typeof obj.meshServer.encodeCookie === 'function'
                && obj.meshServer.loginCookieEncryptionKey) {
                rcookie = obj.meshServer.encodeCookie(
                    { ruserid: actor },
                    obj.meshServer.loginCookieEncryptionKey
                );
            }
        } catch (e) {
            console.log('[remoraTerminalBridge] encodeCookie failed:', e.message);
        }
        if (!rcookie) {
            return replyError(session, command, 'rcookie_encode_failed');
        }

        var sessionId = newSessionId();
        // RC-14.27 (v0.3.3): the operator identity is NOT carried by the plugin.
        // The agent derives it from the server-authenticated `httprequest.username`
        // (Mesh sets command.username = user.name natively in meshrelay.js). The
        // plugin only flags operator mode below; it cannot and must not choose WHO.
        // Browser-side relay URL. `browser=1` flags this as the user end of a
        // tunnel pair; auth comes from the same-origin session cookie. The
        // agent end is opened only after the caller dispatches the tunnel msg
        // built below into control.ashx.
        var relayUrl = '/meshrelay.ashx?browser=1&p=' + protocol
            + '&nodeid=' + encodeURIComponent(nodeId)
            + '&id=' + sessionId;

        // Tunnel msg `value` the FRONTEND/transport must dispatch via
        // control.ashx: `{action:'msg',type:'tunnel',nodeid,value,usage:1}`.
        // Mesh forwards it to the agent, which then opens its meshrelay side
        // with `rauth=<rcookie>` to authenticate. Format matches meshctrl.js
        // :2150 and the working terminal HAR (nodeid is NOT URL-encoded in
        // the value string — agent parses it as a literal substring).
        var agentTunnelValue = '*/meshrelay.ashx?p=' + protocol
            + '&nodeid=' + nodeId
            + '&id=' + sessionId
            + '&rauth=' + rcookie;

        dispatchAudit(actor, {
            msg: 'Terminal session opened',
            nodeid: nodeId,
            shell: shell,
            context: context,
            protocol: protocol,
            actor: actor,
            sessionId: sessionId,
            status: 'success'
        });

        reply(session, command, {
            sessionId: sessionId,
            relayUrl: relayUrl,
            protocol: protocol,
            agentTunnel: {
                nodeId: nodeId,
                value: agentTunnelValue,
                remoraOperator: context === 'operator'
            }
        });
        } // proceedOpen
    };

    return obj;
};
