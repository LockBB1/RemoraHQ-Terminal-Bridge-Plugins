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
    const audits = [], spawns = [], installers = [], removed = [];
    let reads = 0;
    const user = { _id: actor, siteadmin: 0, domain: '' };
    const metadata = options.metadata === undefined ? { blob: 'Zml4dHVyZQ==', username: 'EXAMPLE\\fixture' } : options.metadata;
    const fakeFs = {
        readFileSync() { reads++; if (!metadata) throw new Error('Not configured'); return JSON.stringify(metadata); },
        writeFileSync() { throw new Error('Unexpected credential write'); },
        mkdirSync() {}, createWriteStream() { return new EventEmitter(); },
        unlinkSync(file) { removed.push(file); },
    };
    const fakeRequire = name => {
        if (name === 'fs') return fakeFs;
        if (name === 'child_process') return { spawn(executable, args, settings) {
            spawns.push({ executable, args, settings });
            const child = new EventEmitter();
            child.stdout = new EventEmitter(); child.stderr = new EventEmitter();
            child.stdin = { write() { throw new Error('Push must not carry plaintext stdin'); }, end() {} };
            child.kill = () => {};
            queueMicrotask(() => { child.stdout.emit('data', Buffer.from('install-exit:' + (options.installError ? 1 : 0))); child.emit('close', 0); });
            return child;
        } };
        if (name === 'crypto' || name === 'path') return require('node:' + name);
        throw new Error('Unexpected fixture dependency: ' + name);
    };
    fakeRequire.resolve = () => { throw new Error('No authenticator is available in this fixture'); };
    const module = { exports: {} };
    vm.runInNewContext(source, { module, require: fakeRequire, Buffer, setTimeout, clearTimeout, console: { log() {} } });
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
            const timer = setTimeout(() => reject(new Error('No plugin response')), 2000);
            try {
                plugin.serveraction({ pluginaction: 'remoteInstall.run', host: 'host.example.invalid', groupId, tag: 'fixture', ...command }, {
                    user: who, send(value) { clearTimeout(timer); resolve(JSON.parse(JSON.stringify(value))); },
                });
            } catch (error) { clearTimeout(timer); reject(error); }
        });
    }
    return { request, audits, spawns, installers, removed, reads: () => reads };
}

test('an authorized operator without TOTP can install, with audit and cleanup', async () => {
    const f = fixture(); const result = await f.request({ installFlags: 2 });
    assert.equal(result.result, 'ok'); assert.equal(result.ok, true);
    assert.equal(result.host, 'host.example.invalid'); assert.equal(result.group, groupId); assert.equal(result.tag, 'fixture');
    assert.equal(f.installers.length, 1); assert.match(f.installers[0].msh, /InstallFlags=2/);
    assert.equal(f.spawns.length, 1); assert.equal(f.spawns[0].settings.windowsHide, true);
    assert.equal(f.removed.length, 1); assert.equal(f.audits.at(-1).status, 'success');
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
        if (error === 'agent_exists') { assert.equal(result.existingVisible, false); assert.equal(result.existingGroup, undefined); assert.equal(f.audits.at(-1).status, 'blocked'); }
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
    assert.equal((await push.request()).error, 'install_failed'); assert.equal(push.removed.length, 1); assert.equal(push.audits.at(-1).status, 'error');
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
