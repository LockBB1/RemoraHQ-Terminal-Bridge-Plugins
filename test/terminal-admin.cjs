'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../remoraTerminalBridge.js'), 'utf8');
const actor = 'user//fixture', nodeId = 'node//fixture';
function fixture(superAdmin = false) {
 const cookies = [], checks = [];
 const user = { _id: actor, domain: '', siteadmin: superAdmin ? 0xFFFFFFFF : 0, otpsecret: 'fixture', links: { 'ugrp//fixture': {} } };
 const fakeRequire = name => {
  if (name === 'crypto' || name === 'path') return require('node:' + name);
  if (name === 'fs') return new Proxy({}, { get() { throw Error('No filesystem effects'); } });
  if (name === 'fixture-otplib') return { verifySync() { checks.push('totp'); return { valid: true }; } };
  throw Error('Unexpected dependency');
 };
 fakeRequire.resolve = () => 'fixture-otplib';
 const module = { exports: {} };
 vm.runInNewContext(source, { module, require: fakeRequire, Buffer, setTimeout, clearTimeout, console: { log() {} } });
 const engine = {
  webPublicPath: 'fixture', loginCookieEncryptionKey: 'fixture', encodeCookie(data) { cookies.push(data); return 'fixture-cookie'; },
  db: { Get(_id, cb) { cb(null, [{ grants: { [actor]: { canUseSystemTerminal: true } }, roleDefaults: { operator: { canUseSystemTerminal: true } } }]); } },
  config: { domains: { '': { id: '' } } }, DispatchEvent() {},
  webserver: { users: { [actor]: user }, userGroups: { 'ugrp//fixture': { name: 'RemoraHQ Operators' } },
   GetNodeWithRights(_d, _u, id, cb) { cb({ _id: id }, 8, true); },
   authenticate(_name, _password, _domain, cb) { checks.push('password'); cb(null, actor); } },
 };
 const plugin = module.exports.remoraTerminalBridge({ parent: engine });
 function request(command = {}, who = user) {
  let response; plugin.serveraction({ pluginaction: 'open', nodeId, shell: 'cmd', context: 'user', ...command }, { user: who, send(value) { response = value; } });
  assert(response); return response;
 }
 return { request, cookies, checks };
}
for (const superAdmin of [false, true]) {
 for (const command of [
  { context: 'system', totpToken: '123456' }, { context: 'operator', totpToken: '123456' }, { context: 'admin' },
  { requirePassword: true }, { password: 'fixture-password' }, { protocol: 6 }, { remoraOperator: true },
 ]) test('legacy terminal input is disabled even with old grants, superAdmin=' + superAdmin + ' input=' + Object.keys(command).join(','), () => {
  const f = fixture(superAdmin); const result = f.request(command);
  assert.equal(result.error, 'terminal_mode_disabled'); assert.equal(f.cookies.length, 0); assert.equal(f.checks.length, 0);
 });
 test('Admin API is unavailable before any password verification, superAdmin=' + superAdmin, () => {
  const f = fixture(superAdmin); const result = f.request({ pluginaction: 'openAdmin', context: 'operator', password: 'fixture-password' });
  assert.equal(result.error, 'terminal_admin_unavailable'); assert.equal(f.cookies.length, 0); assert.equal(f.checks.length, 0);
 });
}
for (const shell of ['cmd', 'powershell']) test('User ' + shell + ' retains native user protocol only', () => {
 const f = fixture(); const result = f.request({ shell });
 assert.equal(result.result, 'ok'); assert.equal(result.protocol, shell === 'powershell' ? 9 : 8);
 assert.equal(result.agentTunnel.remoraOperator, undefined); assert.equal(f.cookies.length, 1); assert.equal(f.checks.length, 0);
});
test('User still requires an authenticated session', () => {
 const f = fixture(); assert.equal(f.request({}, null).error, 'auth_required'); assert.equal(f.cookies.length, 0);
});