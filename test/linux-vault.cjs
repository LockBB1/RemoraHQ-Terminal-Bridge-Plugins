'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const source = fs.readFileSync(path.join(__dirname, '../remote-install/linux-vault.cjs'), 'utf8');

// Synthetic POSIX metadata permits permission checks on a Windows development host.
function fixture() {
    const key = crypto.randomBytes(32);
    const state = { mode: 0o100400, uid: 123, symlink: false, keyFile: '/keys/push.key' };
    const mockFs = {
        realpathSync: file => file,
        lstatSync: file => file === state.keyFile ? ({ ...state, isFile: () => true, isSymbolicLink: () => state.symlink }) : ({ uid: 0, mode: 0o40755, isDirectory: () => true, isSymbolicLink: () => false }),
        readFileSync: () => Buffer.from(key),
    };
    const module = { exports: {} };
    vm.runInNewContext(source, { module, exports: module.exports, Buffer, process: { getuid: () => 123, env: { get REMORA_RI_KEY_FILE() { return state.keyFile; } } }, require: name => name === 'node:fs' ? mockFs : name === 'node:path' ? path.posix : require(name) });
    return { vault: module.exports, state, key };
}

test('Linux sealing authenticates the ciphertext, username and external key', () => {
    const f = fixture(), username = 'fixture@EXAMPLE.INVALID', password = 'synthetic fixture only';
    const record = { ...f.vault.seal('/data', username, password), username };
    assert.equal(f.vault.open('/data', record).toString(), password);
    assert.equal(JSON.stringify(record).includes(password), false);
    assert.throws(() => f.vault.open('/data', { ...record, username: 'other@EXAMPLE.INVALID' }));
    const blob = Buffer.from(record.blob, 'base64'); blob[0] ^= 1;
    assert.throws(() => f.vault.open('/data', { ...record, blob: blob.toString('base64') }));
    f.key.fill(0);
    assert.throws(() => f.vault.open('/data', record));
});

test('Linux vault refuses world-readable, foreign-owned, linked and colocated keys', () => {
    for (const changes of [{ mode: 0o100644 }, { uid: 456 }, { symlink: true }, { keyFile: '/data/key' }]) {
        const f = fixture(); Object.assign(f.state, changes);
        assert.throws(() => f.vault.seal('/data', 'fixture@EXAMPLE.INVALID', 'synthetic'));
    }
});
