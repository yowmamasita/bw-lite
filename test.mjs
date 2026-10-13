// End-to-end check of bw.js against a throwaway Vaultwarden:
//   docker run -d --name bwlite-vw -p 127.0.0.1:8099:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true vaultwarden/server
//   node test.mjs
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import * as bw from './bw.js';

globalThis.hashwasm = createRequire(import.meta.url)('./vendor/argon2.umd.min.js');
const SERVER = process.env.SERVER || 'http://localhost:8099';
const PASSWORD = 'correct horse battery staple';

// Offline checks
assert.equal((await bw.totp('otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8', 59e3)).code, '94287082'); // RFC 6238
assert.equal((await bw.totp('GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ', 1111111109e3)).code, '081804');
const k = crypto.getRandomValues(new Uint8Array(64));
assert.equal(new TextDecoder().decode(await bw.decrypt(await bw.encrypt('héllo', k), k)), 'héllo');
await assert.rejects(bw.decrypt(await bw.encrypt('x', k), crypto.getRandomValues(new Uint8Array(64))), /MAC mismatch/);
const item = (uris) => ({ uris });
assert.ok(bw.matches(item(['https://accounts.google.com/login']), 'mail.google.com'));
assert.ok(bw.matches(item(['github.com']), 'github.com'));
assert.ok(!bw.matches(item(['https://a.co.uk']), 'b.co.uk'));
assert.ok(!bw.matches(item(['http://192.168.1.10']), '10.0.1.10'));
assert.ok(!bw.matches(item(['androidapp://com.foo']), 'evil.com'));
console.log('offline checks ok');

// Registration is not part of the extension; done here with the same primitives.
async function register(email, kdf) {
  const mk = await bw.makeMasterKey(PASSWORD, email, kdf);
  const userKey = crypto.getRandomValues(new Uint8Array(64));
  const rsa = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' }, true, ['encrypt', 'decrypt']);
  const pub = new Uint8Array(await crypto.subtle.exportKey('spki', rsa.publicKey));
  const json = { method: 'POST', headers: { 'Content-Type': 'application/json' } };
  const token = await (await fetch(`${SERVER}/identity/accounts/register/send-verification-email`, { ...json, body: JSON.stringify({ email, name: 'test' }) })).text();
  const r = await fetch(`${SERVER}/identity/accounts/register/finish`, {
    ...json,
    body: JSON.stringify({
      email, emailVerificationToken: token, masterPasswordHash: await bw.passwordHash(mk, PASSWORD), masterPasswordHint: null, ...kdf,
      userSymmetricKey: await bw.encrypt(userKey, await bw.stretch(mk)),
      userAsymmetricKeys: { publicKey: bw.b64(pub), encryptedPrivateKey: await bw.encrypt(new Uint8Array(await crypto.subtle.exportKey('pkcs8', rsa.privateKey)), userKey) },
    }),
  });
  assert.ok(r.ok, `register: ${r.status} ${await r.text()}`);
  return { userKey, publicKey: rsa.publicKey };
}

const run = Date.now();
const email = `pbkdf-${run}@example.com`;
const reg = await register(email, { kdf: 0, kdfIterations: 600000 });
const deviceId = crypto.randomUUID();

await assert.rejects(bw.login(SERVER, email, 'wrong', deviceId), /Username or password is incorrect|invalid/i);
const r = await bw.login(SERVER, email, PASSWORD, deviceId);
assert.deepEqual(r.userKey, reg.userKey);
assert.deepEqual(await bw.unlock(PASSWORD, email, r.kdf, r.protectedKey), reg.userKey);
await assert.rejects(bw.unlock('nope', email, r.kdf, r.protectedKey), /Wrong master password/);
const s = { server: SERVER, tokens: r.tokens };
const me = (await bw.api(s, '/sync')).profile.id;
console.log('pbkdf2 login + unlock ok');

// Create, then edit a personal login
await bw.saveCipher(s, r.userKey, null, { name: 'Example', username: 'ben', password: 'pw1', totp: 'JBSWY3DPEHPK3PXP', notes: 'n', uris: ['https://example.com'] });
let vault = await bw.decryptVault(await bw.api(s, '/sync'), r.userKey);
assert.equal(vault.length, 1);
assert.deepEqual([vault[0].name, vault[0].username, vault[0].password, vault[0].uris], ['Example', 'ben', 'pw1', ['https://example.com']]);
// add a custom field the extension doesn't show, to make sure edits keep it
const raw = vault[0].raw;
await bw.api(s, `/ciphers/${raw.id}`, 'PUT', { ...raw, encryptedFor: me, attachments: undefined, fields: [{ type: 0, name: await bw.encrypt('pin', r.userKey), value: await bw.encrypt('1234', r.userKey) }] });
vault = await bw.decryptVault(await bw.api(s, '/sync'), r.userKey);
await bw.saveCipher(s, r.userKey, vault[0], { ...vault[0], password: 'pw2', uris: ['https://example.com', 'https://login.example.org'] });
const sync = await bw.api(s, '/sync');
vault = await bw.decryptVault(sync, r.userKey);
assert.equal(vault[0].password, 'pw2');
assert.deepEqual(vault[0].uris, ['https://example.com', 'https://login.example.org']);
const c = sync.ciphers[0];
assert.equal(c.fields.length, 1, 'custom field kept');
assert.equal(new TextDecoder().decode(await bw.decrypt(c.passwordHistory[0].password, r.userKey)), 'pw1');
assert.equal(new TextDecoder().decode(await bw.decrypt(c.login.uris[1].uriChecksum, r.userKey)),
  bw.b64(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('https://login.example.org'))));
console.log('create + edit ok (custom field kept, password history, uri checksum)');

// Incremental decrypt: unchanged items come back as the same object, changed ones are decrypted fresh
const prev = new Map(vault.map((i) => [i.id, i]));
assert.equal((await bw.decryptVault(sync, r.userKey, prev))[0], vault[0]);
const stale = new Map([[vault[0].id, { ...vault[0], rev: 'old', password: 'stale' }]]);
assert.equal((await bw.decryptVault(sync, r.userKey, stale))[0].password, 'pw2');
assert.deepEqual(vault[0].d, ['example.com', 'example.org']);
console.log('incremental decrypt ok');

// Item with its own cipher key
const ck = crypto.getRandomValues(new Uint8Array(64));
await bw.api(s, '/ciphers', 'POST', { type: 1, encryptedFor: me, key: await bw.encrypt(ck, r.userKey), name: await bw.encrypt('Keyed', ck), login: { username: await bw.encrypt('u', ck) } });
vault = await bw.decryptVault(await bw.api(s, '/sync'), r.userKey);
let keyed = vault.find((i) => i.name === 'Keyed');
await bw.saveCipher(s, r.userKey, keyed, { ...keyed, password: 'kp' });
keyed = (await bw.decryptVault(await bw.api(s, '/sync'), r.userKey)).find((i) => i.name === 'Keyed');
assert.equal(keyed.password, 'kp');
console.log('per-item cipher key ok');

// Organization item
const orgKey = crypto.getRandomValues(new Uint8Array(64));
const wrapped = '4.' + bw.b64(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, reg.publicKey, orgKey));
const org = await bw.api(s, '/organizations', 'POST', { name: 'Org', billingEmail: email, key: wrapped, collectionName: await bw.encrypt('Default', orgKey), planType: 0 });
const cols = await bw.api(s, `/organizations/${org.id}/collections`);
await bw.api(s, '/ciphers/create', 'POST', {
  cipher: { type: 1, encryptedFor: me, organizationId: org.id, name: await bw.encrypt('Shared', orgKey), login: { password: await bw.encrypt('orgpw', orgKey) } },
  collectionIds: [cols.data[0].id],
});
vault = await bw.decryptVault(await bw.api(s, '/sync'), r.userKey);
let shared = vault.find((i) => i.name === 'Shared');
assert.equal(shared.password, 'orgpw');
await bw.saveCipher(s, r.userKey, shared, { ...shared, password: 'orgpw2' });
shared = (await bw.decryptVault(await bw.api(s, '/sync'), r.userKey)).find((i) => i.name === 'Shared');
assert.equal(shared.password, 'orgpw2');
console.log('organization item read + edit ok');

// Token refresh
s.tokens.expires = 0;
let refreshed;
s.onTokens = (t) => (refreshed = t);
await bw.api(s, '/sync');
assert.ok(refreshed?.access && refreshed.expires > Date.now());
console.log('token refresh ok');

// Argon2id account
const email2 = `argon-${run}@example.com`;
const reg2 = await register(email2, { kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 });
assert.deepEqual((await bw.login(SERVER, email2, PASSWORD, deviceId)).userKey, reg2.userKey);
console.log('argon2id login ok');
