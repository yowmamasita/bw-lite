// End-to-end check of bw.js against a throwaway Vaultwarden:
//   docker run -d --name bwlite-vw -p 127.0.0.1:8099:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true vaultwarden/server
//   node test.mjs
import assert from 'node:assert/strict';
import nodeCrypto from 'node:crypto';
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
const item = (uris, m) => ({ uris, m });
assert.ok(bw.matches(item(['https://accounts.google.com/login']), 'https://mail.google.com/'));
assert.ok(bw.matches(item(['github.com']), 'https://github.com/login'));
assert.ok(!bw.matches(item(['https://a.co.uk']), 'https://b.co.uk/'));
assert.ok(!bw.matches(item(['http://192.168.1.10']), 'http://10.0.1.10/'));
assert.ok(!bw.matches(item(['androidapp://com.foo']), 'https://evil.com/'));
// per-URI match types: 1 host, 2 starts with, 3 exact, 4 regex, 5 never
assert.ok(bw.matches(item(['https://a.example.com'], [1]), 'https://a.example.com/x'));
assert.ok(!bw.matches(item(['https://a.example.com'], [1]), 'https://b.example.com/'));
assert.ok(!bw.matches(item(['https://a.example.com:8443'], [1]), 'https://a.example.com/'));
assert.ok(bw.matches(item(['https://example.com/app'], [2]), 'https://example.com/app/login'));
assert.ok(!bw.matches(item(['https://example.com/app'], [2]), 'https://example.com/other'));
assert.ok(bw.matches(item(['https://example.com/login'], [3]), 'https://example.com/login'));
assert.ok(!bw.matches(item(['https://example.com/login'], [3]), 'https://example.com/login?x'));
assert.ok(bw.matches(item(['^https://(www\\.)?example\\.com/'], [4]), 'https://www.example.com/a'));
assert.ok(!bw.matches(item(['(unclosed'], [4]), 'https://example.com/'));
assert.ok(!bw.matches(item(['https://example.com'], [5]), 'https://example.com/'));
assert.ok(bw.matches(item(['https://example.com', 'https://x.org'], [5, null]), 'https://x.org/'));
// equivalent domains
const eq = bw.equivalents([['youtube.com', 'google.com', 'google.co.uk']]);
assert.ok(bw.matches(item(['https://accounts.google.com']), 'https://www.youtube.com/', eq));
assert.ok(bw.matches(item(['https://google.co.uk']), 'https://accounts.google.com/', eq));
assert.ok(!bw.matches(item(['https://accounts.google.com']), 'https://www.youtube.com/'));
// best first: last used, then vault order
const logins = [{ a: 'v2', id: '1', uris: ['x.com'] }, { a: 'v1', id: '2', uris: ['x.com'] }, { a: 'v1', id: '3', uris: ['y.com'] }];
const rank = (a) => ['v1', 'v2'].indexOf(a);
assert.deepEqual(bw.forSite(logins, 'https://x.com/', null, rank).map((i) => i.id), ['2', '1']);
assert.deepEqual(bw.forSite(logins, 'https://x.com/', null, rank, { 'v2:1': 5 }).map((i) => i.id), ['1', '2']);
console.log('offline checks ok');

// Passkeys: a credential made by passkeyCreate signs assertions its public key verifies
const fromB64u = (s) => Buffer.from(s, 'base64url');
const challenge = bw.b64u(crypto.getRandomValues(new Uint8Array(32)));
const created = await bw.passkeyCreate({ challenge, rp: { name: 'Ex' }, user: { id: 'dXNlcg', name: 'ben' } }, 'https://login.example.com', 'example.com');
const pkReg = created.result.response;
assert.deepEqual(JSON.parse(fromB64u(pkReg.clientDataJSON)), { type: 'webauthn.create', challenge, origin: 'https://login.example.com', crossOrigin: false });
const regAuth = fromB64u(pkReg.authenticatorData);
assert.deepEqual(new Uint8Array(regAuth.subarray(0, 32)), new Uint8Array(nodeCrypto.createHash('sha256').update("example.com").digest()));
assert.equal(regAuth[32], 0x5d);
assert.deepEqual(new Uint8Array(regAuth.subarray(55, 55 + 16)), bw.credIdBytes(created.passkey.credentialId));
assert.ok(fromB64u(pkReg.attestationObject).includes(regAuth), 'attestationObject embeds authData');
async function verifyGet(passkey, publicKeyB64u) {
  const as = (await bw.passkeyGet(passkey, { challenge }, 'https://example.com')).response;
  const signed = Buffer.concat([fromB64u(as.authenticatorData), nodeCrypto.createHash('sha256').update(fromB64u(as.clientDataJSON)).digest()]);
  assert.ok(nodeCrypto.verify('sha256', signed, { key: fromB64u(publicKeyB64u), format: 'der', type: 'spki' }, fromB64u(as.signature)), 'assertion verifies');
  assert.equal(as.userHandle, 'dXNlcg');
}
for (let i = 0; i < 20; i++) await verifyGet(created.passkey, pkReg.publicKey); // DER edge cases (leading zero / high bit) vary per signature
assert.deepEqual(bw.credIdBytes('b64.AAEC'), new Uint8Array([0, 1, 2]));
console.log('passkey create + sign ok');

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

// Passkey saved into the login survives the round trip through the server and still signs
await bw.saveCipher(s, r.userKey, vault[0], { ...vault[0], passkey: created.passkey });
const synced = (await bw.decryptVault(await bw.api(s, '/sync'), r.userKey))[0];
assert.equal(synced.passkeys.length, 1);
assert.equal(synced.passkeys[0].keyValue, created.passkey.keyValue);
assert.equal(synced.password, 'pw2');
await verifyGet(synced.passkeys[0], pkReg.publicKey);
console.log('passkey stored in vault ok');

// Incremental decrypt: unchanged items come back as the same object, changed ones are decrypted fresh
const prev = new Map(vault.map((i) => [i.id, i]));
assert.equal((await bw.decryptVault(sync, r.userKey, prev))[0], vault[0]);
const stale = new Map([[vault[0].id, { ...vault[0], rev: 'old', password: 'stale' }]]);
assert.equal((await bw.decryptVault(sync, r.userKey, stale))[0].password, 'pw2');
assert.deepEqual(vault[0].d, ['example.com', 'example.org']);
assert.equal(vault[0].m, undefined, 'no match types set');
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

// Delete moves to the trash
await bw.deleteCipher(s, shared.id);
const trashed = (await bw.api(s, '/sync')).ciphers.find((c) => c.id === shared.id);
assert.ok(trashed?.deletedDate, 'in the trash');
assert.ok(!(await bw.decryptVault(await bw.api(s, '/sync'), r.userKey)).some((i) => i.id === shared.id));
console.log('delete to trash ok');

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
