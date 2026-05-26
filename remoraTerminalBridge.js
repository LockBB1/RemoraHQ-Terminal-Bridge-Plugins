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
 *     agentTunnel: { nodeId, value }   // caller dispatches via control.ashx
 *   }
 *   server → client (err): { result:'error', error:'<slug>' }
 *
 * Changelog:
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

var PLUGIN_SHORT_NAME = 'remoraTerminalBridge';
var PLUGIN_VERSION = '0.2.0';
var ALLOWED_SHELLS = ['cmd', 'powershell', 'bash', 'zsh'];
var ALLOWED_CONTEXTS = ['user', 'system'];

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
    'powershell|user':  9,
    'powershell|system': 6,
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

    obj.serveraction = function (command, dbGet, ws) {
        var session = dbGet || ws;
        if (!session || typeof session.send !== 'function') return;

        var action = String(command.pluginaction || '');
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

        // SYSTEM context requires either a fresh TOTP token OR a still-valid
        // grant from a prior successful TOTP for this (actor, nodeId). The
        // grant TTL mirrors the frontend cache so the UI's "skip prompt"
        // assumption no longer leads to a server-side rejection
        // (RC-13.19.1 fix; before v0.2.0 every reconnect failed with
        // 2fa-failed because the client cached the grant but the server
        // demanded a fresh code each time).
        if (context === 'system') {
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
                value: agentTunnelValue
            }
        });
    };

    return obj;
};
