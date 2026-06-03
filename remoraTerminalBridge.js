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
var PLUGIN_VERSION = '0.6.0';
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
// Per-actor rate limit on the privileged push (sliding window).
var RI_RUN_MAX = 20;
var RI_RUN_WINDOW_MS = 60 * 1000;
var riRunTimes = Object.create(null);

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

    function replyError(session, command, error) {
        try {
            session.send({
                action: 'plugin',
                plugin: PLUGIN_SHORT_NAME,
                pluginaction: command.pluginaction || 'unknown',
                tag: command.tag,
                responseid: command.responseid || command.tag,
                result: 'error',
                error: String(error || 'remora_terminal_bridge_failed')
            });
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

    // RC-15.A.1 — async check of the SYSTEM-terminal grant. Super-admins pass
    // implicitly. Fail-closed: any missing DB access or absent grant denies.
    function hasSystemTerminalPermission(user, cb) {
        if (isSuperAdmin(user)) return cb(true);
        if (!obj.meshServer || !obj.meshServer.db || typeof obj.meshServer.db.Get !== 'function') {
            return cb(false);
        }
        obj.meshServer.db.Get(REMORA_PERMISSIONS_DOC_ID, function (err, docs) {
            var grants = (!err && docs && docs.length > 0 && docs[0].grants && typeof docs[0].grants === 'object') ? docs[0].grants : {};
            var mine = grants[user._id] || {};
            cb(mine[PERMISSION_SYSTEM_TERMINAL] === true);
        });
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

    // Async check of canRemoteInstall (clone of hasSystemTerminalPermission).
    // Super-admin implicit, fail-closed.
    function hasRemoteInstallPermission(user, cb) {
        if (isSuperAdmin(user)) return cb(true);
        if (!obj.meshServer || !obj.meshServer.db || typeof obj.meshServer.db.Get !== 'function') return cb(false);
        obj.meshServer.db.Get(REMORA_PERMISSIONS_DOC_ID, function (err, docs) {
            var grants = (!err && docs && docs.length > 0 && docs[0].grants && typeof docs[0].grants === 'object') ? docs[0].grants : {};
            var mine = grants[user._id] || {};
            cb(mine[PERMISSION_REMOTE_INSTALL] === true);
        });
    }

    function riRateLimitOk(actor) {
        var now = Date.now();
        var arr = (riRunTimes[actor] || []).filter(function (t) { return now - t < RI_RUN_WINDOW_MS; });
        if (arr.length >= RI_RUN_MAX) { riRunTimes[actor] = arr; return false; }
        arr.push(now); riRunTimes[actor] = arr; return true;
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
            if (!RI_HOST_RE.test(host)) return replyError(session, command, 'invalid_host');
            var meta = riReadCredMeta();
            if (!meta || !meta.blob || !RI_BLOB_RE.test(meta.blob) || !RI_USERNAME_RE.test(meta.username || '')) {
                return replyError(session, command, 'not_configured');
            }
            runPowerShell(riReachabilityScript(meta.blob, meta.username, host), null, function (err, res) {
                if (err || !res) return replyError(session, command, 'reachability_failed');
                var out = res.stdout || '';
                var ping = /ping=True/i.test(out);
                var winrm = /winrm=True/i.test(out);
                reply(session, command, { reachable: ping, winrm: winrm });
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
        });
    }

    obj.serveraction = function (command, dbGet, ws) {
        var session = dbGet || ws;
        if (!session || typeof session.send !== 'function') return;

        var action = String(command.pluginaction || '');
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
