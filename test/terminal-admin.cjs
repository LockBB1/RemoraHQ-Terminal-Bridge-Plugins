'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../remoraTerminalBridge.js'), 'utf8');
const actor = 'user//fixture', nodeId = 'node//fixture';

function fixture(options = {}) {
    const audits = [], cookies = [], bindings = [];
    const user = { _id: actor, domain: '', siteadmin: 0, links: { 'ugrp//operator': {} }, ...options.user };
    const module = { exports: {} };
    const fakeRequire = name => {
        if (name === 'crypto' || name === 'path') return require('node:' + name);
        if (name === 'fs') return new Proxy({}, { get() { throw new Error('No filesystem effects'); } });
        throw new Error('Unexpected dependency');
    };
    fakeRequire.resolve = () => { throw new Error('No authenticator available'); };
    vm.runInNewContext(source, { module, require: fakeRequire, Buffer, setTimeout, clearTimeout, console: { log() {} } });
    let finishAuth;
    const webserver = {
        users: { [actor]: user }, userGroups: { 'ugrp//operator': { name: 'RemoraHQ Operators' } },
        GetNodeWithRights(_domain, _user, id, cb) { cb(id === nodeId ? { _id: nodeId, meshid: 'mesh//fixture' } : null, options.rights ?? 8, options.visible !== false); },
        authenticate(name, password, domain, cb) {
            bindings.push({ name, password, domain });
            finishAuth = () => cb(options.authError ? new Error('Fixture authentication failed') : null, options.returnedId ?? (password === 'fixture-password' ? actor : null));
            if (!options.deferAuth) finishAuth();
        },
    };
    if (options.noAuthenticate) delete webserver.authenticate;
    const engine = {
        webserver, config: { domains: { '': { id: '', ...options.domain } } },
        loginCookieEncryptionKey: 'fixture', encodeCookie(data) { cookies.push(data); return 'fixture-cookie'; },
        db: { Get(_id, cb) { cb(null, [{ grants: { [actor]: { canUseSystemTerminal: true } } }]); } },
        DispatchEvent(_targets, _source, event) { audits.push(event); },
        pluginHandler: { plugins: { remoraAuditor: { serveraction(_command, session) { session.send({ auditorUserIds: options.auditor ? [actor] : [] }); } } } },
    };
    const plugin = module.exports.remoraTerminalBridge({ parent: engine });
    let session;
    function request(command = {}, who = user) {
        return new Promise(resolve => {
            session = { user: who, send(value) { resolve(JSON.parse(JSON.stringify(value))); } };
            plugin.serveraction({ pluginaction: 'openAdmin', nodeId, shell: 'cmd', context: 'operator', password: 'fixture-password', ...command }, session);
        });
    }
    return { request, audits, cookies, bindings, webserver, user, finish: () => finishAuth(), retire: () => { session.user = null; } };
}

for (const shell of ['cmd', 'powershell']) test('Admin ' + shell + ' verifies this account before issuing the unchanged operator context', async () => {
    const f = fixture({ deferAuth: true });
    const opening = f.request({ shell });
    assert.equal(f.bindings.length, 1); assert.equal(f.cookies.length, 0);
    f.finish(); const result = await opening;
    assert.equal(result.result, 'ok'); assert.equal(result.protocol, shell === 'cmd' ? 1 : 6);
    assert.equal(result.agentTunnel.remoraOperator, true); assert.equal(f.cookies.length, 1);
    assert.equal(f.bindings[0].name, 'fixture');
    assert.equal(JSON.stringify(result).includes('fixture-password'), false);
    assert.equal(JSON.stringify(f.audits).includes('fixture-password'), false);
});

for (const [label, options, command, error] of [
    ['missing password', {}, { password: undefined }, 'password_required'],
    ['wrong password', {}, { password: 'wrong' }, 'password_failed'],
    ['another account', { returnedId: 'user//other' }, {}, 'password_failed'],
    ['auth failure', { authError: true }, {}, 'password_failed'],
    ['no verifier', { noAuthenticate: true }, {}, 'password_unavailable'],
    ['viewer', { user: { links: {} } }, {}, 'permission_denied'],
    ['auditor override', { auditor: true }, {}, 'permission_denied'],
    ['locked account', { user: { siteadmin: 32 } }, {}, 'permission_denied'],
    ['no control rights', { rights: 0 }, {}, 'permission_denied'],
    ['terminal prohibited', { rights: 8 | 512 }, {}, 'permission_denied'],
    ['view-only restriction', { rights: 8 | 256 }, {}, 'permission_denied'],
    ['hidden device', { visible: false }, {}, 'permission_denied'],
    ['cross-domain device', {}, { nodeId: 'node/other/fixture' }, 'invalid_nodeId'],
    ['device query injection', {}, { nodeId: 'node//fixture&p=1' }, 'invalid_nodeId'],
    ['oversized password', {}, { password: 'x'.repeat(1025) }, 'password_required'],
    ['system context', {}, { context: 'system' }, 'invalid_context'],
    ['unsupported shell', {}, { shell: 'bash' }, 'unsupported_shell_context'],
    ['SSPI domain', { domain: { auth: 'sspi' } }, {}, 'password_unavailable'],
]) test('direct Admin API refuses ' + label + ' without issuing a relay cookie', async () => {
    const f = fixture(options); const result = await f.request(command);
    assert.equal(result.error, error); assert.equal(f.cookies.length, 0);
});

test('requires an authenticated caller', async () => {
    const f = fixture(); assert.equal((await f.request({}, null)).error, 'auth_required'); assert.equal(f.bindings.length, 0);
});
test('uses the configured LDAP account handle and requires the same returned account', async () => {
    const f = fixture({ domain: { auth: 'ldap' }, user: { email: 'fixture@example.invalid' } });
    assert.equal((await f.request()).result, 'ok'); assert.equal(f.bindings[0].name, 'fixture');
});
test('limits password checks to five per actor per minute, including successes', async () => {
    const f = fixture(); for (let n = 0; n < 5; n++) assert.equal((await f.request()).result, 'ok');
    assert.equal((await f.request()).error, 'rate_limited'); assert.equal(f.bindings.length, 5);
});
for (const revoke of ['session', 'rights', 'lock']) test('rechecks ' + revoke + ' after async password verification', async () => {
    const f = fixture({ deferAuth: true }); const opening = f.request();
    if (revoke === 'session') f.retire();
    if (revoke === 'rights') f.webserver.GetNodeWithRights = (_domain, _user, _id, cb) => cb(null, 0, false);
    if (revoke === 'lock') f.user.siteadmin = 32;
    f.finish(); assert.notEqual((await opening).result, 'ok'); assert.equal(f.cookies.length, 0);
});
test('Admin password never grants the existing Operator or SYSTEM TOTP cache', async () => {
    const f = fixture(); assert.equal((await f.request()).result, 'ok');
    for (const context of ['operator', 'system']) assert.equal((await f.request({ pluginaction: 'open', context, requirePassword: true })).error, '2fa-failed');
});
