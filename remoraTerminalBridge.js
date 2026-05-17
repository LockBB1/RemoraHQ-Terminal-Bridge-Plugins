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
 *   server → client (ok): { result:'ok', sessionId, relayUrl, protocol }
 *   server → client (err): { result:'error', error:'<slug>' }
 *
 * Changelog:
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
var PLUGIN_VERSION = '0.1.1';
var ALLOWED_SHELLS = ['cmd', 'powershell', 'bash', 'zsh'];
var ALLOWED_CONTEXTS = ['user', 'system'];

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

        // SYSTEM context requires a fresh TOTP token. User context is gated only
        // by the active Mesh session (caller already authenticated).
        if (context === 'system') {
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
        }

        var sessionId = newSessionId();
        // Mesh-native relay URL. `browser=1` tells the relay handler this is
        // the browser side of a tunnel pair; the server auto-spawns the agent
        // side by sending a tunnel command with the matching `id`. The user's
        // session cookie carries auth same-origin — no `auth=` query needed.
        var relayUrl = '/meshrelay.ashx?browser=1&p=' + protocol
            + '&nodeid=' + encodeURIComponent(nodeId)
            + '&id=' + sessionId;

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
            protocol: protocol
        });
    };

    return obj;
};
