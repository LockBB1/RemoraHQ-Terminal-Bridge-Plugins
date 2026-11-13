'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');
const source = fs.readFileSync(path.join(__dirname, '../remoraTerminalBridge.js'), 'utf8');
const actor = 'user//fixture', groupId = 'mesh//QUJD';

// All external effects stay in memory; no subprocess, filesystem write, DB or network is used.
function fixture(options = {}) {
    const audits = [], spawns = [], installers = [], removed = [], files = new Map(), scratchRemoved = [], killed = [];
    const secret = Buffer.from('synthetic password');
    let reads = 0;
    const user = { _id: actor, siteadmin: 0, domain: '' };
    const metadata = options.metadata === undefined ? { blob: 'Zml4dHVyZQ==', username: 'EXAMPLE\\fixture' } : options.metadata;
    const fakeFs = {
        readFileSync(file) {
            if (file.endsWith('lifecycle.ps1')) return fs.readFileSync(file, 'utf8');
            if (file.includes('remora-ri-operations')) { if (!files.has(file)) throw Object.assign(new Error('Not found'), { code: 'ENOENT' }); return files.get(file); }
            reads++; if (!metadata) throw new Error('Not configured'); return JSON.stringify(metadata);
        },
        writeFileSync(file, content, writeOptions) {
            if (file.endsWith('remora-remoteinstall.json') && options.encodingProbe) { files.set(file, content); return; }
            if (!file.includes('remora-ri-operations')) throw new Error('Unexpected credential write');
            if (writeOptions.flag === 'wx' && files.has(file)) throw new Error('Exists'); files.set(file, content);
        },
        mkdirSync() {}, createWriteStream() { return new EventEmitter(); },
        mkdtempSync(prefix) { return prefix + 'fixture'; }, chmodSync() {},
        rmSync(file) { if (options.scratchCleanupFailure) throw new Error('private cleanup failure'); scratchRemoved.push(file); },
        unlinkSync(file) { if (options.unlinkFailure && file.endsWith('.exe')) throw new Error('fixture cleanup failure'); removed.push(file); files.delete(file); },
        renameSync(from, to) { files.set(to, files.get(from)); files.delete(from); },
    };
    const fakeRequire = name => {
        if (name === 'fs') return fakeFs;
        if (name === 'child_process') return { spawn(executable, args, settings) {
            spawns.push({ executable, args, settings });
            if (options.encodingProbe) {
                // Preserve the real launcher's initialization; replace only the DPAPI job body.
                const script = Buffer.from(args.at(-1), 'base64').toString('utf16le');
                const jobStart = script.indexOf("$ErrorActionPreference='Stop'");
                assert.ok(jobStart >= 0);
                const harmless = script.slice(0, jobStart) + "$value=[Console]::In.ReadLine(); [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($value))";
                return require('node:child_process').spawn(executable, [...args.slice(0, -1), Buffer.from(harmless, 'utf16le').toString('base64')], settings);
            }
            const child = new EventEmitter();
            child.stdout = new EventEmitter(); child.stderr = new EventEmitter();
            child.pid = 12345;
            child.stdin = { on() {}, write(body) { spawns.at(-1).stdin = JSON.parse(body); }, end(body) { if (body) spawns.at(-1).stdin = JSON.parse(body); } };
            child.kill = () => {};
            if (!options.hold) queueMicrotask(() => { child.stdout.emit('data', Buffer.from(options.diagnosticMarker || ('ri-result:' + (options.outcome || (options.installError ? 'install_failed' : 'installer_completed'))))); child.emit('close', 0); });
            child.release = outcome => { child.stdout.emit('data', Buffer.from('ri-result:' + outcome)); child.emit('close', 0); };
            spawns.at(-1).child = child;
            return child;
        } };
        if (name === 'crypto' || name === 'path' || name === 'os') return require('node:' + name);
        if (name === './remote-install/linux-vault.cjs' && options.linux) return { read: () => metadata, open: () => secret };
        throw new Error('Unexpected fixture dependency: ' + name);
    };
    fakeRequire.resolve = () => { throw new Error('No authenticator is available in this fixture'); };
    const module = { exports: {} };
    vm.runInNewContext(source, { module, require: fakeRequire, Buffer, process: { platform: options.linux ? 'linux' : 'win32', env: {}, kill(pid) { killed.push(pid); } }, __dirname: path.join(__dirname, '..'), setTimeout: (fn, ms) => { if (options.timeout && ms === 180000) { queueMicrotask(fn); return null; } return setTimeout(fn, ms); }, clearTimeout, console: { log() {} } });
    const flags = options.flags ?? { canRemoteInstall: true };
    const meshServer = {
        datapath: path.join(path.parse(process.cwd()).root, 'fictional-fixture'),
        db: {
            Get(_id, cb) { cb(options.policyError ? new Error('Policy unavailable') : null, [{ grants: { [actor]: flags } }]); },
            GetAllType(_type, cb) { cb(options.scanError ? new Error('Scan unavailable') : null, options.nodes ?? []); },
        },
        webserver: {
            meshes: { [groupId]: { name: 'Fixture group', mtype: 2 }, 'mesh//hidden': { name: 'Hidden fixture group' } },
            GetMeshRights(_user, id) { return id === groupId ? (options.rights ?? 1) : 0; },
            agentCertificateHashHex: 'aabbcc', getWebServerName: () => 'example.invalid',
        },
        config: { domains: { '': { id: '' } } }, args: { port: 443 },
        meshAgentBinaries: { 4: { path: 'fixture-agent.exe' } },
        exeHandler: { streamExeWithMeshPolicy(input) { installers.push(input); if (options.generatorError) throw new Error('Fixture generator failed'); input.destinationStream.emit('close'); } },
        DispatchEvent(_targets, _source, event) { audits.push(event); },
    };
    const plugin = module.exports.remoraTerminalBridge({ parent: meshServer });
    function request(command = {}, who = user) {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error('No plugin response')), options.encodingProbe ? 20000 : 2000);
            try {
                plugin.serveraction({ pluginaction: 'remoteInstall.run', host: 'host.example.invalid', groupId, tag: 'fixture', ...command }, {
                    user: who, send(value) { clearTimeout(timer); resolve(JSON.parse(JSON.stringify(value))); },
                });
            } catch (error) { clearTimeout(timer); reject(error); }
        });
    }
    return { request, audits, spawns, installers, removed, files, scratchRemoved, killed, secret, reads: () => reads };
}

test('diagnostic requires permission and returns only bounded verification results', async () => {
    const options = { linux: true, metadata: { blob: 'Zml4dHVyZQ==', username: 'fixture@EXAMPLE.INVALID' }, diagnosticMarker: 'ri-diagnostic:mismatch:unknown_error:present:confirmed' };
    const denied = fixture({ ...options, flags: { canRemoteInstall: false } });
    assert.equal((await denied.request({ pluginaction: 'remoteInstall.diagnostic' })).error, 'permission_denied');
    assert.equal(denied.installers.length, 0);
    const deniedGroup = fixture({ ...options, rights: 0 });
    assert.equal((await deniedGroup.request({ pluginaction: 'remoteInstall.diagnostic' })).error, 'permission_denied');
    assert.equal(deniedGroup.installers.length, 0);
    const f = fixture(options);
    const result = await f.request({ pluginaction: 'remoteInstall.diagnostic' });
    assert.equal(result.result, 'ok');
    assert.deepEqual([result.hash, result.signature, result.signer, result.cleanup], ['mismatch', 'unknown_error', 'present', 'confirmed']);
    assert.equal(f.spawns.length, 1);
    assert.equal(f.spawns[0].stdin.mode, 'diagnostic');
    assert.equal(JSON.stringify(result).includes('fixture@'), false);
    assert.equal(f.audits.at(-1).status, 'success');
    const failedCleanup = fixture({ ...options, unlinkFailure: true });
    assert.equal((await failedCleanup.request({ pluginaction: 'remoteInstall.diagnostic' })).error, 'diagnostic_inconclusive');
    assert.equal(failedCleanup.audits.at(-1).status, 'unknown');
    const malformed = fixture({ ...options, diagnosticMarker: 'ri-diagnostic:match:valid:present:confirmed PRIVATE' });
    assert.equal((await malformed.request({ pluginaction: 'remoteInstall.diagnostic' })).error, 'diagnostic_inconclusive');
    const windows = fixture({ diagnosticMarker: 'ri-diagnostic:match:valid:present:confirmed' });
    assert.equal((await windows.request({ pluginaction: 'remoteInstall.diagnostic' })).result, 'ok');
    assert.equal(windows.spawns.length, 1);
});

test('diagnostic rate limit refuses generation before launching another job', async () => {
    const f = fixture({ linux: true, metadata: { blob: 'Zml4dHVyZQ==', username: 'fixture@EXAMPLE.INVALID' }, diagnosticMarker: 'ri-diagnostic:match:valid:present:confirmed' });
    for (let i = 0; i < 30; i++) assert.equal((await f.request({ pluginaction: 'remoteInstall.diagnostic' })).result, 'ok');
    assert.equal((await f.request({ pluginaction: 'remoteInstall.diagnostic' })).error, 'rate_limited');
    assert.equal(f.installers.length, 30);
    assert.equal(f.spawns.length, 30);
});

test('an authorized operator without TOTP can install, with audit and cleanup', async () => {
    const f = fixture(); const result = await f.request({ installFlags: 2 });
    assert.equal(result.result, 'ok'); assert.equal(result.ok, true);
    assert.equal(result.host, 'host.example.invalid'); assert.equal(result.group, groupId); assert.equal(result.tag, 'fixture');
    assert.equal(f.installers.length, 1); assert.match(f.installers[0].msh, /InstallFlags=2/);
    assert.equal(f.spawns.length, 1); assert.equal(f.spawns[0].settings.windowsHide, true);
    assert.equal(f.removed.filter(file => file.endsWith('.exe')).length, 1); assert.equal(f.audits.at(-1).status, 'success');
    assert.equal(JSON.stringify(result).includes('Zml4dHVyZQ=='), false);
});

for (const [label, options, command, error] of [
    ['missing grant', { flags: {} }, {}, 'permission_denied'],
    ['explicit deny', { flags: { canRemoteInstall: false } }, {}, 'permission_denied'],
    ['policy unavailable', { policyError: true }, {}, 'permission_denied'],
    ['no group rights', { rights: 0 }, {}, 'permission_denied'],
    ['unrecognized group', {}, { groupId: 'mesh//other' }, 'permission_denied'],
    ['host injection', {}, { host: "host';exit" }, 'invalid_host'],
    ['group injection', {}, { groupId: 'mesh//group;exit' }, 'invalid_group'],
    ['missing credential', { metadata: null }, {}, 'not_configured'],
    ['invalid sealed credential', { metadata: { blob: 'bad;blob', username: 'EXAMPLE\\fixture' } }, {}, 'not_configured'],
    ['failed duplicate scan', { scanError: true }, {}, 'dup_check_failed'],
    ['existing hidden agent', { nodes: [{ type: 'node', name: 'host', meshid: 'mesh//hidden' }] }, {}, 'agent_exists'],
]) {
    test('direct run refuses ' + label + ' before any push', async () => {
        const f = fixture(options); const result = await f.request(command);
        assert.equal(result.error, error); assert.equal(f.spawns.length, 0); assert.equal(f.installers.length, 0);
        if (error === 'permission_denied' || error === 'invalid_host' || error === 'invalid_group') assert.equal(f.reads(), 0);
        if (error === 'agent_exists') { assert.equal(result.existingGroup, undefined); assert.equal(f.audits.at(-1).status, 'error'); }
    });
}

test('an unauthenticated direct run is rejected', async () => {
    const f = fixture(); assert.equal((await f.request({}, null)).error, 'auth_required'); assert.equal(f.spawns.length, 0);
});
test('the per-actor push limit still refuses the twenty-first request', async () => {
    const f = fixture();
    for (let count = 0; count < 20; count++) assert.equal((await f.request()).result, 'ok');
    assert.equal((await f.request()).error, 'rate_limited'); assert.equal(f.spawns.length, 20);
    assert.equal(f.audits.at(-1).status, 'denied');
});
test('installer and remote failures retain failure audit and cleanup', async () => {
    const generation = fixture({ generatorError: true });
    assert.equal((await generation.request()).error, 'installer_gen_failed'); assert.equal(generation.spawns.length, 0);
    const push = fixture({ installError: true });
    assert.equal((await push.request()).error, 'install_failed'); assert.equal(push.removed.filter(file => file.endsWith('.exe')).length, 1); assert.equal(push.audits.at(-1).status, 'error');
});
test('install permission does not grant Push Account administration', async () => {
    const f = fixture();
    for (const action of ['setAccount', 'testAccount', 'accountStatus']) assert.equal((await f.request({ pluginaction: 'remoteInstall.' + action })).error, 'forbidden');
    assert.equal(f.reads(), 0); assert.equal(f.spawns.length, 0);
});
test('retired terminal modes are disabled independently of Remote Install', async () => {
    const f = fixture({ flags: { canUseSystemTerminal: true } });
    for (const context of ['operator', 'system']) {
        assert.equal((await f.request({ pluginaction: 'open', nodeId: 'node//fixture', shell: 'cmd', context })).error, 'terminal_mode_disabled');
    }
});

for (const mode of ['reinstall', 'remove']) {
    test(mode + ' requires both grants and exact target confirmation', async () => {
        for (const options of [{ flags: {} }, { rights: 0 }]) {
            const f = fixture(options);
            assert.equal((await f.request({ mode, confirmedHost: 'host.example.invalid' })).error, 'permission_denied');
            assert.equal(f.spawns.length, 0);
        }
        const f = fixture();
        assert.equal((await f.request({ mode })).error, 'confirmation_required');
        assert.equal((await f.request({ mode, confirmedHost: 'other.example.invalid' })).error, 'confirmation_required');
        assert.equal(f.spawns.length, 0);
    });
    test(mode + ' can explicitly act on a previous-server host while preserving records', async () => {
        const f = fixture({ nodes: [{ type: 'node', name: 'host', meshid: 'mesh//hidden' }], outcome: mode === 'remove' ? 'removed' : 'installer_completed' });
        const result = await f.request({ mode, confirmedHost: 'host.example.invalid' });
        assert.equal(result.ok, true); assert.equal(result.mode, mode);
        assert.equal(f.spawns.length, 1); assert.equal(f.audits.at(-1).mode, mode);
        assert.equal(result.existingGroup, undefined);
    });
}

test('an unknown outcome persists, blocks another run and can be read without another push', async () => {
    const f = fixture({ outcome: 'outcome_unknown' });
    const first = await f.request({ mode: 'remove', confirmedHost: 'host.example.invalid' });
    assert.equal(first.error, 'outcome_unknown');
    assert.equal((await f.request()).error, 'target_busy_or_unknown');
    const state = await f.request({ pluginaction: 'remoteInstall.status' });
    assert.equal(state.state, 'unknown'); assert.equal(state.operationId, first.operationId);
    assert.equal(f.spawns.length, 1); assert.equal(f.audits.at(-1).status, 'unknown');
    assert.equal((await f.request({ pluginaction: 'remoteInstall.status', groupId: 'mesh//hidden' })).error, 'permission_denied');
});

test('confirmed removal and uncertain cleanup remain distinct in replies, replay, status and audit', async () => {
    for (const options of [
        { diagnosticMarker: 'ri-result:removed\nri-cleanup:unknown' },
        { diagnosticMarker: 'ri-result:removed\nri-cleanup:confirmed', unlinkFailure: true },
        { diagnosticMarker: 'ri-result:removed\nri-cleanup:confirmed', linux: true, scratchCleanupFailure: true },
        { diagnosticMarker: 'ri-result:removed\nri-cleanup:confirmed' },
    ]) {
        const f = fixture(options), operationId = 'c'.repeat(32);
        const command = { mode: 'remove', confirmedHost: 'host.example.invalid', operationId };
        const result = await f.request(command);
        const expected = options.unlinkFailure || options.scratchCleanupFailure || options.diagnosticMarker.endsWith('unknown') ? 'unknown' : 'confirmed';
        assert.equal(result.ok, true); assert.equal(result.outcome, 'removed'); assert.equal(result.cleanup, expected);
        const status = await f.request({ pluginaction: 'remoteInstall.status' });
        assert.equal(status.state, 'completed'); assert.equal(status.outcome, 'removed'); assert.equal(status.cleanup, expected);
        assert.equal((await f.request(command)).cleanup, expected);
        assert.equal(f.audits.at(-1).cleanup, expected);
        assert.equal(f.spawns.length, 1);
    }
});

test('concurrent runs cannot share a target and completion is replayed for the same intent', async () => {
    const f = fixture({ hold: true }), operationId = 'a'.repeat(32);
    const pending = f.request({ operationId });
    assert.equal(f.spawns.length, 1);
    assert.equal((await f.request()).error, 'target_busy_or_unknown');
    assert.equal((await f.request({ pluginaction: 'remoteInstall.status' })).state, 'running');
    f.spawns[0].child.release('installer_completed');
    assert.equal((await pending).ok, true);
    assert.equal((await f.request({ operationId })).ok, true);
    assert.equal(f.spawns.length, 1);
    assert.equal((await f.request({ operationId, mode: 'remove', confirmedHost: 'host.example.invalid' })).error, 'invalid_input');
});

test('unrecognized or absent remote markers mean unknown, never ordinary installation failure', async () => {
    for (const outcome of ['garbled', '']) {
        const f = fixture({ outcome: outcome || 'unrecognized' });
        assert.equal((await f.request()).error, 'outcome_unknown');
        assert.equal((await f.request()).error, 'target_busy_or_unknown');
    }
});

test('Linux jobs pass secrets only through stdin and clean their private Kerberos directory', async () => {
    const f = fixture({ linux: true });
    assert.equal((await f.request()).ok, true);
    const job = f.spawns[0];
    assert.equal(job.executable, '/usr/bin/ruby');
    assert.equal(job.settings.detached, true);
    assert.equal(job.stdin.password, 'synthetic password');
    assert.equal(JSON.stringify(job.args).includes('synthetic password'), false);
    assert.equal(JSON.stringify(job.settings).includes('synthetic password'), false);
    assert.deepEqual(f.scratchRemoved, [job.stdin.cacheDirectory]);
    assert.equal(f.secret.every(byte => byte === 0), true);
});

test('Linux timeout kills the whole process group, clears tickets and retains unknown state', async () => {
    const f = fixture({ linux: true, hold: true, timeout: true });
    assert.equal((await f.request()).error, 'outcome_unknown');
    assert.deepEqual(f.killed, [-12345]);
    assert.equal(f.scratchRemoved.length, 1);
    assert.equal(f.secret.every(byte => byte === 0), true);
    assert.equal((await f.request()).error, 'target_busy_or_unknown');
});

test('Windows push keeps the command line bounded with maximum metadata and transports lifecycle by stdin', async () => {
    const f = fixture({ metadata: { blob: 'A'.repeat(8192), username: 'a'.repeat(256) } });
    assert.equal((await f.request({ host: 'a'.repeat(255) })).ok, true);
    const push = f.spawns[0];
    assert.ok(push.args.join(' ').length < 10000);
    assert.equal(push.stdin.blob.length, 8192);
    assert.equal(push.stdin.password, undefined);
    assert.match(push.stdin.script, /param\(/);
    assert.match(push.stdin.installerSha256, /^[a-f0-9]{64}$/);
});

test('Windows PowerShell preserves Unicode stdin through the real launcher without DPAPI or network', { skip: process.platform !== 'win32' }, async () => {
    const f = fixture({ encodingProbe: true });
    const synthetic = 'Синтетический пароль — C:\\данные\\агент.exe 漢字';
    const result = await f.request({ pluginaction: 'remoteInstall.setAccount', username: 'EXAMPLE\\fixture', password: synthetic }, { _id: actor, siteadmin: 0xFFFFFFFF });
    assert.equal(result.configured, true);
    const credential = [...f.files.entries()].find(([file]) => file.endsWith('remora-remoteinstall.json'));
    assert.ok(credential);
    assert.equal(Buffer.from(JSON.parse(credential[1]).blob, 'base64').toString('utf8'), synthetic);
    assert.equal(f.spawns.length, 1);
});
