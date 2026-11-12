'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function privateFile(file) {
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid()) throw new Error('unsafe_secret_permissions');
    return fs.readFileSync(file);
}

function key(dataPath) {
    const file = process.env.REMORA_RI_KEY_FILE;
    if (!file || !path.isAbsolute(file)) throw new Error('key_unavailable');
    const resolved = fs.realpathSync(file);
    const relative = path.relative(fs.realpathSync(dataPath), resolved);
    if (!relative || (!relative.startsWith('..' + path.sep) && !path.isAbsolute(relative))) throw new Error('key_must_be_separate');
    let directory = path.dirname(file);
    while (true) {
        const stat = fs.lstatSync(directory);
        if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0 || (stat.uid !== 0 && stat.uid !== process.getuid())) throw new Error('unsafe_key_directory');
        const parent = path.dirname(directory);
        if (parent === directory) break;
        directory = parent;
    }
    const bytes = privateFile(file);
    if (bytes.length !== 32) throw new Error('invalid_key');
    return bytes;
}

exports.seal = function (dataPath, username, password) {
    const secretKey = key(dataPath), iv = crypto.randomBytes(12);
    try {
        const cipher = crypto.createCipheriv('aes-256-gcm', secretKey, iv);
        cipher.setAAD(Buffer.from('RemoraHQ.RemoteInstall.v1:' + username));
        const blob = Buffer.concat([cipher.update(password, 'utf8'), cipher.final()]).toString('base64');
        return { format: 'aes-256-gcm-v1', iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), blob };
    } finally { secretKey.fill(0); }
};

exports.open = function (dataPath, meta) {
    if (meta.format !== 'aes-256-gcm-v1') throw new Error('wrong_credential_platform');
    const secretKey = key(dataPath);
    try {
        const iv = Buffer.from(meta.iv, 'base64'), tag = Buffer.from(meta.tag, 'base64');
        if (iv.length !== 12 || tag.length !== 16) throw new Error('corrupt_credential');
        const cipher = crypto.createDecipheriv('aes-256-gcm', secretKey, iv);
        cipher.setAAD(Buffer.from('RemoraHQ.RemoteInstall.v1:' + meta.username));
        cipher.setAuthTag(tag);
        return Buffer.concat([cipher.update(Buffer.from(meta.blob, 'base64')), cipher.final()]);
    } finally { secretKey.fill(0); }
};

exports.read = file => JSON.parse(privateFile(file).toString('utf8'));
exports.write = function (file, meta) {
    const temporary = file + '.' + crypto.randomBytes(8).toString('hex');
    try {
        fs.writeFileSync(temporary, JSON.stringify(meta), { mode: 0o600, flag: 'wx' });
        fs.renameSync(temporary, file);
    } finally { try { fs.unlinkSync(temporary); } catch (_) { /* already renamed */ } }
};
