/**
 * RemoraHQ - Terminal Bridge MeshCentral plugin.
 *
 * Server-side validator + correlation issuer for RemoraHQ terminal sessions.
 * Pairs with the Terminal UI in RC-12.1+ that opens the actual meshrelay
 * WebSocket using the {sessionId, relayUrl} this plugin issues.
 *
 * Responsibilities:
 *   1. Validate input — shell choice against an allow-list, context value,
 *      nodeId shape.
 *   2. For context='system' — verify the supplied TOTP token against the
 *      calling user's `otpsecret` via `otplib` (same scheme Mesh uses for
 *      login 2FA). Rejection surfaces as result:'error', error:'2fa-failed'.
 *   3. Issue a correlation `sessionId` (random) + a `relayUrl` pointing at
 *      Mesh's native `meshrelay.ashx` with the nodeid + shell parameters.
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
 *   server → client (ok): { result:'ok', sessionId, relayUrl }
 *   server → client (err): { result:'error', error:'<slug>' }
 *
 * Audit events:
 *   { etype:'terminal-open', action:'plugin.terminal.open', context, shell,
 *     nodeid, actor, sessionId } via parent.parent.DispatchEvent.
 */

'use strict';

var crypto = require('crypto');

var PLUGIN_SHORT_NAME = 'remoraTerminalBridge';
var PLUGIN_VERSION = '0.1.0';
var ALLOWED_SHELLS = ['cmd', 'powershell', 'bash', 'zsh'];
var ALLOWED_CONTEXTS = ['user', 'system'];

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
                    actor: actor,
                    status: 'denied'
                });
                return replyError(session, command, '2fa-failed');
            }
        }

        var sessionId = newSessionId();
        // Build relay URL pointing at Mesh's native meshrelay.ashx. The Terminal
        // UI (RC-12.1) opens this URL as a binary WebSocket and proxies xterm.js
        // I/O through it. The `auth` cookie that Mesh requires is already on the
        // browser from the main session — same-origin lets it ride.
        var relayUrl = '/meshrelay.ashx?id=' + sessionId
            + '&nodeid=' + encodeURIComponent(nodeId)
            + '&p=2' // p=2 = terminal feature per Mesh convention
            + '&shell=' + encodeURIComponent(shell)
            + '&context=' + encodeURIComponent(context);

        dispatchAudit(actor, {
            msg: 'Terminal session opened',
            nodeid: nodeId,
            shell: shell,
            context: context,
            actor: actor,
            sessionId: sessionId,
            status: 'success'
        });

        reply(session, command, { sessionId: sessionId, relayUrl: relayUrl });
    };

    return obj;
};
