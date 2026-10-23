// Offline checks for bw.js; add --integration to run the optional throwaway Vaultwarden checks:
//   docker run -d --name bwlite-vw -p 127.0.0.1:8099:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true vaultwarden/server
//   node test.mjs --integration
import assert from 'node:assert/strict';
import nodeCrypto from 'node:crypto';
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import * as bw from './bw.js';
import { mutateAccounts, withStateLock } from './coord.js';
import { fillTab } from './autofill.js';

globalThis.hashwasm = createRequire(import.meta.url)('./vendor/argon2.umd.min.js');
const SERVER = process.env.SERVER || 'http://localhost:8099';
const PASSWORD = 'correct horse battery staple';

// Offline checks
assert.equal((await bw.totp('otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8', 59e3)).code, '94287082'); // RFC 6238
assert.equal((await bw.totp('GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ', 1111111109e3)).code, '081804');
await assert.rejects(bw.totp('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=7'), /digits/i);
await assert.rejects(bw.totp('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=100000'), /digits/i);
await assert.rejects(bw.totp('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=-1'), /period/i);
await assert.rejects(bw.totp('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=999999999'), /period/i);
await assert.rejects(bw.totp('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5'), /algorithm/i);
await assert.rejects(bw.totp('otpauth://totp/x?secret=&digits=6'), /secret/i);
const k = crypto.getRandomValues(new Uint8Array(64));
assert.equal(new TextDecoder().decode(await bw.decrypt(await bw.encrypt('héllo', k), k)), 'héllo');
await assert.rejects(bw.decrypt(await bw.encrypt('x', k), crypto.getRandomValues(new Uint8Array(64))), /MAC mismatch/);
const jwt = `x.${Buffer.from(JSON.stringify({ sub: 'user' })).toString('base64url')}.x`;
const oldFetch = globalThis.fetch;
let savedBody;
globalThis.fetch = async (_url, options) => (savedBody = JSON.parse(options.body), { ok: true, text: async () => JSON.stringify({ id: 'saved' }) });
const rawUnknown = { id: 'raw', revisionDate: '1', type: 1, data: { opaque: 'keep' }, login: {} };
await bw.saveCipher({ server: 'https://vault.example', tokens: { access: jwt, expires: Date.now() + 60e3 } }, k,
  { id: 'raw', raw: rawUnknown, key: k, password: 'old', uris: [] },
  { name: 'Name', username: 'u', password: 'new', totp: '', notes: '', uris: [] });
globalThis.fetch = oldFetch;
assert.deepEqual(savedBody.data, { opaque: 'keep' }, 'unknown cipher fields survive an edit');
assert.equal(savedBody.lastKnownRevisionDate, '1', 'edits keep the revision captured by the form for optimistic concurrency');
await assert.rejects(bw.saveCipher({ server: 'https://vault.example', tokens: { access: jwt, expires: Date.now() + 60e3 } }, k,
  { id: 'ro', raw: { edit: false }, key: k }, { name: 'x', username: '', password: '', totp: '', notes: '', uris: [] }), /read-only/i);
await assert.rejects(bw.saveCipher({ server: 'https://vault.example', tokens: { access: jwt, expires: Date.now() + 60e3 } }, k,
  { id: 'missing' }, { name: 'x', username: '', password: '', totp: '', notes: '', uris: [] }), /incomplete/i);
const item = (uris, m) => ({ uris, m });
assert.ok(bw.matches(item(['https://accounts.google.com/login']), 'https://mail.google.com/'));
assert.ok(bw.matches(item(['github.com']), 'https://github.com/login'));
assert.ok(!bw.matches(item(['https://a.co.uk']), 'https://b.co.uk/'));
assert.ok(!bw.matches(item(['http://192.168.1.10']), 'http://10.0.1.10/'));
assert.ok(!bw.matches(item(['androidapp://com.foo']), 'https://evil.com/'));
assert.equal(bw.baseDomain('login.github.io'), 'login.github.io');
assert.equal(bw.baseDomain('foo.pages.dev'), 'foo.pages.dev');
assert.equal(bw.baseDomain('a.co.uk'), 'a.co.uk');
assert.ok(bw.isPublicSuffix('github.io'));
assert.ok(!bw.isPublicSuffix('login.github.io'));
assert.ok(!bw.matches(item(['https://alice.github.io']), 'https://bob.github.io/'));
assert.ok(!bw.matches(item(['https://alice.pages.dev']), 'https://bob.pages.dev/'));
assert.equal(bw.baseDomain('city.kawasaki.jp'), 'city.kawasaki.jp'); // PSL exception
assert.equal(bw.baseDomain('a.b.ck'), 'a.b.ck'); // PSL wildcard
assert.equal(bw.baseDomain('BÜCHER.DE'), 'xn--bcher-kva.de'); // IDNA normalization
assert.ok(bw.matches(item(['https://BÜCHER.DE']), 'https://xn--bcher-kva.de/'));
assert.ok(bw.isPublicSuffix('公司.cn'), 'Unicode PSL rules are normalized to IDNA');
assert.equal(bw.baseDomain('alice.公司.cn'), 'alice.xn--55qx5d.cn');
assert.ok(!bw.matches(item(['https://alice.公司.cn']), 'https://bob.公司.cn/'));
assert.ok(!bw.matches({ uris: ['https://old.invalid'], d: ['example.com'] }, 'https://example.com/', null));
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
const transitive = bw.equivalents([['one.example', 'two.example'], ['two.example', 'three.example']]);
assert.ok(bw.matches(item(['https://one.example']), 'https://three.example/', transitive));
assert.ok(!bw.matches({ bad: true }, 'https://example.com/'));
// best first: last used, then vault order
const logins = [{ a: 'v2', id: '1', uris: ['x.com'] }, { a: 'v1', id: '2', uris: ['x.com'] }, { a: 'v1', id: '3', uris: ['y.com'] }];
const rank = (a) => ['v1', 'v2'].indexOf(a);
assert.deepEqual(bw.forSite(logins, 'https://x.com/', null, rank).map((i) => i.id), ['2', '1']);
assert.deepEqual(bw.forSite(logins, 'https://x.com/', null, rank, { 'v2:1': 5 }).map((i) => i.id), ['1', '2']);
const perVaultEq = new Map([
  ['v1', bw.equivalents([['one.example', 'shared.example']])],
  ['v2', bw.equivalents([['two.example', 'other.example']])],
]);
const grouped = [{ a: 'v1', id: 'one', uris: ['https://one.example'] }, { a: 'v2', id: 'two', uris: ['https://two.example'] }];
assert.deepEqual(bw.forSite(grouped, 'https://shared.example/', (i) => perVaultEq.get(i.a), rank).map((i) => i.id), ['one']);

// Two popup-like contexts must merge account patches while one is suspended;
// the second writer must never replace the first writer's latest list.
let accountRows = [{ id: 'a', label: 'A' }];
const accountStorage = {
  async get() { return { accounts: structuredClone(accountRows) }; },
  async set({ accounts }) { await new Promise((resolve) => setTimeout(resolve, 0)); accountRows = structuredClone(accounts); },
};
const oldLocks = globalThis.navigator?.locks;
Object.defineProperty(globalThis.navigator, 'locks', { configurable: true, value: {
  queue: Promise.resolve(),
  request(_name, _options, fn) { const job = this.queue.catch(() => {}).then(fn); this.queue = job.catch(() => {}); return job; },
} });
await Promise.all([
  mutateAccounts(accountStorage, async (rows) => { await new Promise((resolve) => setTimeout(resolve, 2)); return rows.map((a) => ({ ...a, label: 'renamed' })); }),
  mutateAccounts(accountStorage, (rows) => [...rows, { id: 'b', label: 'B' }]),
]);
assert.deepEqual(accountRows, [{ id: 'a', label: 'renamed' }, { id: 'b', label: 'B' }]);
await mutateAccounts(accountStorage, (rows) => rows.filter((a) => a.id !== 'a'));
await mutateAccounts(accountStorage, (rows) => rows.map((a) => a.id === 'a' ? { ...a, persistKey: 'stale' } : a));
assert.ok(!accountRows.some((a) => a.id === 'a'), 'a removed account cannot be resurrected by a stale patch');
if (oldLocks) Object.defineProperty(globalThis.navigator, 'locks', { configurable: true, value: oldLocks });
else delete globalThis.navigator.locks;
const oldChrome = globalThis.chrome;
let fillCalls = 0;
globalThis.chrome = { scripting: { executeScript: async ({ target, files, func }) => {
  fillCalls++;
  assert.ok(target.documentIds?.[0] === 'doc-1' || target.frameIds?.[0] === 0 || target.allFrames);
  if (files) return [];
  if (target.allFrames || target.documentIds) return [{ frameId: 0, result: 'https://example.com/login' }];
  return [{ result: true }];
} } };
let authorized = false;
assert.equal(await fillTab(1, { uris: ['https://example.com'] }, null, null, async () => authorized, 'doc-1'), false);
assert.equal(fillCalls, 0, 'fill does not inject before the authorization guard');
authorized = true;
assert.equal(await fillTab(1, { uris: ['https://example.com'] }, null, null, async () => authorized, 'doc-1'), true);
assert.equal(fillCalls, 3, 'fill checks the guard and targets the current document');
if (oldChrome) globalThis.chrome = oldChrome;
else delete globalThis.chrome;
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

// The page bridge forwards an allowlist, never the page's arbitrary message object.
const bridgeListeners = {}, bridgePosts = [], bridgeRuntime = [];
const bridgeWindow = {};
const bridgeContext = {
  window: bridgeWindow, location: { origin: 'https://example.com' },
  addEventListener: (name, fn) => (bridgeListeners[name] = fn),
  postMessage: (m, origin) => bridgePosts.push({ m, origin }),
  chrome: {
    runtime: {
      sendMessage: async (m) => (bridgeRuntime.push(m), { bwliteRes: m.bwliteReq, fallback: true, secret: 'discard' }),
      onMessage: { addListener: (fn) => (bridgeListeners.runtime = fn) },
    },
  },
};
vm.runInNewContext(await readFile('./bridge.js', 'utf8'), bridgeContext);
await bridgeListeners.message({ source: bridgeWindow, data: {
  bwliteReq: 'bridge-1', kind: 'get', options: { challenge: 'c', rpId: 'example.com', evil: 'discard' }, evil: 'discard',
} });
assert.equal(JSON.stringify(bridgeRuntime), JSON.stringify([{ bwliteReq: 'bridge-1', kind: 'get', options: { challenge: 'c', rpId: 'example.com' } }]));
assert.equal(JSON.stringify(bridgePosts[0]), JSON.stringify({ m: { bwliteRes: 'bridge-1', fallback: true }, origin: 'https://example.com' }));
bridgeListeners.runtime({ bwliteRes: 'bridge-1', fallback: true, secret: 'discard' });
assert.equal(bridgePosts.at(-1).m.secret, undefined);
bridgeListeners.runtime({ bwliteRes: 'bridge-1', result: {
  id: 'id', rawId: 'raw', type: 'public-key', clientExtensionResults: { credProps: { rk: true }, secret: 'discard' },
  response: { signature: 's', secret: 'discard' },
} });
assert.equal(bridgePosts.at(-1).m.result.response.secret, undefined);
assert.equal(JSON.stringify(bridgePosts.at(-1).m.result.clientExtensionResults), JSON.stringify({ credProps: { rk: true } }));
await bridgeListeners.message({ source: bridgeWindow, data: {
  bwliteReq: 'bridge-2', kind: 'get', options: { challenge: 'c', allowCredentials: [{ id: 'ok' }, { noId: true }] },
} });
assert.deepEqual(bridgeRuntime.at(-1).options.allowCredentials, [{ id: 'ok' }, { noId: true }], 'bridge does not broaden malformed credential lists');
await bridgeListeners.message({ source: bridgeWindow, data: { bwliteReq: 'bridge-3', kind: 'get', options: null } });
assert.equal(JSON.stringify(bridgePosts.at(-1)), JSON.stringify({ m: { bwliteRes: 'bridge-3', fallback: true }, origin: 'https://example.com' }), 'malformed requests fall back immediately');
await bridgeListeners.message({ source: bridgeWindow, data: {
  bwliteReq: 'bridge-4', kind: 'create', options: { challenge: 'c', authenticatorSelection: { authenticatorAttachment: 'cross-platform' }, evil: 'discard' },
} });
assert.deepEqual(bridgeRuntime.at(-1).options.authenticatorSelection, { authenticatorAttachment: 'cross-platform' }, 'unsupported requirements reach the authoritative validator');
console.log('bridge boundary checks ok');

// Minimal Chrome storage/runtime harness for service-worker regressions; no browser or Docker is needed.
const changesListeners = [], runtimeListeners = [], tabUpdates = [], sentTabs = [], createdWindows = [];
const makeArea = (area) => {
  const data = new Map();
  const keyList = (keys) => keys === null ? [...data.keys()] : Array.isArray(keys) ? keys : typeof keys === 'string' ? [keys] : Object.keys(keys || {});
  return {
    data,
    async get(keys) { const out = {}; for (const k of keyList(keys)) if (data.has(k)) out[k] = data.get(k); return out; },
    async set(values) { const changes = {}; for (const [k, v] of Object.entries(values)) { changes[k] = { oldValue: data.get(k), newValue: v }; data.set(k, v); } for (const fn of changesListeners) await fn(changes, area); },
    async remove(keys) { const changes = {}; for (const k of keyList(keys)) if (data.has(k)) { changes[k] = { oldValue: data.get(k) }; data.delete(k); } for (const fn of changesListeners) await fn(changes, area); },
    async clear() { return this.remove([...data.keys()]); },
  };
};
const localStore = makeArea('local'), sessionStore = makeArea('session');
globalThis.chrome = {
  storage: {
    local: localStore, session: sessionStore,
    onChanged: { addListener: (fn) => changesListeners.push(fn) },
  },
  action: { setBadgeBackgroundColor: () => {}, setBadgeText: async () => {}, openPopup: async () => {} },
  commands: { onCommand: { addListener: () => {} } },
  tabs: {
    query: async () => [], get: async (id) => ({ id, url: 'https://two.example/home' }),
    sendMessage: async (...args) => sentTabs.push(args),
    onUpdated: { addListener: (fn) => tabUpdates.push(fn) }, onRemoved: { addListener: () => {} },
  },
  windows: { create: async (o) => createdWindows.push(o), update: async () => {} },
  runtime: { onMessage: { addListener: (fn) => runtimeListeners.push(fn) } },
  scripting: { executeScript: async () => [] },
};
await import(`./background.js?offline=${Date.now()}`);
const sendRuntime = (message, sender = { tab: { id: 1 }, url: 'https://one.example/' }) => new Promise((resolve) => {
  for (const listener of runtimeListeners) {
    let answered = false;
    const reply = (value) => { answered = true; resolve(value); };
    const ret = listener(message, sender, reply);
    if (ret !== true && !answered) resolve(undefined);
  }
});
const accountA = { id: 'a', label: 'A' }, accountB = { id: 'b', label: 'B' };
await localStore.set({ accounts: [accountA, accountB] });
const testSessionKey = bw.b64(new Uint8Array(64));
await sessionStore.set({ 'a:key': testSessionKey, 'a:list': '{bad', 'b:key': testSessionKey, 'b:list': JSON.stringify([{ id: 'b1', name: 'B', username: 'u', password: 'p', uris: ['https://two.example'] }]) });
const warn = console.warn;
console.warn = () => {};
const menu = await sendRuntime({ bwliteMenu: true }, { tab: { id: 1 }, url: 'https://two.example/login' });
console.warn = warn;
assert.equal(menu[0].username, 'u', 'one corrupt account must not hide another account');
await localStore.set({ accounts: [accountA, accountB, { id: 'c', label: 'C' }] });
await sessionStore.set({ 'c:list': JSON.stringify([{ id: 'c1', name: 'C', username: 'leak', password: 'p', uris: ['https://two.example'] }]) });
const noStaleList = await sendRuntime({ bwliteMenu: true }, { tab: { id: 1 }, url: 'https://two.example/login' });
assert.ok(!noStaleList.some((i) => i.username === 'leak'), 'a list without its session key is never exposed');
await localStore.set({
  'a:eq': [['one.example', 'shared.example']], 'b:eq': [['two.example', 'other.example']],
});
await sessionStore.set({
  'a:key': testSessionKey,
  'a:list': JSON.stringify([{ id: 'a1', name: 'A', username: 'a', password: 'p', uris: ['https://one.example'] }]),
  'b:list': JSON.stringify([{ id: 'b1', name: 'B', username: 'b', password: 'p', uris: ['https://two.example'] }]),
});
const perAccountMenu = await sendRuntime({ bwliteMenu: true }, { tab: { id: 1 }, url: 'https://shared.example/login' });
assert.deepEqual(perAccountMenu.map((i) => i.username), ['a'], 'equivalent domains stay scoped to their account');
await sessionStore.set({ 'b:list': JSON.stringify([{ id: 'b1', name: 'B', username: 'b', password: 'p', totp: 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=7', uris: ['https://two.example'] }]) });
const badTotpFill = await sendRuntime({ bwliteFillKey: 'b:b1' }, { tab: { id: 1 }, url: 'https://two.example/login' });
assert.equal(badTotpFill.password, 'p', 'bad TOTP does not suppress password fill');
assert.equal(badTotpFill.code, null, 'bad TOTP is omitted from the clipboard payload');
await Promise.all([
  sendRuntime({ bwliteUsed: { a: 'b', id: 'b1' } }, {}),
  sendRuntime({ bwliteUsed: { a: 'b', id: 'b2' } }, {}),
]);
assert.deepEqual(Object.keys((await localStore.get('used')).used).sort(), ['b:b1', 'b:b2']);
const fallback = await sendRuntime({ bwliteReq: 'rp-1', kind: 'create', options: {
  challenge: 'c', rp: { id: 'github.io', name: 'x' }, user: { id: 'u', name: 'u' }, pubKeyCredParams: [{ alg: -7 }],
} }, { origin: 'https://login.github.io', tab: { id: 1 }, url: 'https://login.github.io/' });
assert.equal(fallback.fallback, true, 'a private public suffix cannot be an RP ID');
const pagesFallback = await sendRuntime({ bwliteReq: 'rp-pages', kind: 'create', options: {
  challenge: 'c', rp: { id: 'pages.dev', name: 'x' }, user: { id: 'u', name: 'u' }, pubKeyCredParams: [{ alg: -7 }],
} }, { origin: 'https://app.pages.dev', tab: { id: 1 }, url: 'https://app.pages.dev/' });
assert.equal(pagesFallback.fallback, true, 'a private pages.dev suffix cannot be an RP ID');
const malformedAllow = await sendRuntime({ bwliteReq: 'pk-malformed', kind: 'get', options: {
  challenge: 'c', allowCredentials: [{ id: 'ok' }, { noId: true }],
} }, { origin: 'https://app.example', tab: { id: 1 }, url: 'https://app.example/' });
assert.equal(malformedAllow.fallback, true, 'malformed allowCredentials never broaden a restricted request');
await sendRuntime({ bwliteReq: 'rp-2', kind: 'create', options: {
  challenge: 'c', rp: { id: 'login.github.io', name: 'x' }, user: { id: 'u', name: 'u' }, pubKeyCredParams: [{ alg: -7 }],
} }, { origin: 'https://login.github.io', tab: { id: 1 }, url: 'https://login.github.io/' });
assert.ok(createdWindows.length, 'a registrable private suffix may be an RP ID');
const windowsBefore = createdWindows.length;
await sendRuntime({ bwliteReq: 'rp-real', kind: 'create', options: {
  challenge: 'c'.repeat(1670), timeout: 60000, rp: { name: 'x' }, user: { id: 'u', name: 'u' }, pubKeyCredParams: [{ alg: -7 }],
  authenticatorSelection: { residentKey: 'required', userVerification: 'required' }, extensions: { appid: 'x' },
} }, { origin: 'https://login.github.io', tab: { id: 1 }, url: 'https://login.github.io/' });
assert.equal(createdWindows.length, windowsBefore + 1, 'everyday options (timeout, UV, residentKey, extensions) open BW Lite');
const securityKey = await sendRuntime({ bwliteReq: 'rp-key', kind: 'create', options: {
  challenge: 'c', rp: { name: 'x' }, user: { id: 'u', name: 'u' }, pubKeyCredParams: [{ alg: -7 }],
  authenticatorSelection: { authenticatorAttachment: 'cross-platform' },
} }, { origin: 'https://login.github.io', tab: { id: 1 }, url: 'https://login.github.io/' });
assert.equal(securityKey.fallback, true, 'a request for a security key goes to the browser');
await sendRuntime({ bwliteReq: 'rp-3', kind: 'create', options: {
  challenge: 'c', rp: { name: 'x' }, user: { id: 'u', name: 'u' }, pubKeyCredParams: [{ alg: -7 }],
} }, { origin: 'https://localhost', tab: { id: 1 }, url: 'https://localhost/' });
const before = sentTabs.length;
await sendRuntime({ bwliteSubmit: { username: 'alice', password: '' } }, { tab: { id: 7 }, url: 'https://one.example/login' });
await sessionStore.set({ 'b:list': JSON.stringify([{ id: 'b1', name: 'B', username: 'bob', password: 'old', uris: ['https://two.example'] }]) });
await sendRuntime({ bwliteSubmit: { username: '', password: 'secret' } }, { tab: { id: 7 }, url: 'https://two.example/login' });
await tabUpdates[0](7, { status: 'complete' }, { id: 7, url: 'https://two.example/home', status: 'complete' });
assert.ok(sentTabs.length > before, 'the current-origin login can create a save offer');
const offerKey = sentTabs.at(-1)[1].bwliteBar;
assert.equal((await sessionStore.get(`save:${offerKey}`))[`save:${offerKey}`].username, 'bob', 'a previous origin username must not leak into the offer');
assert.equal((await sessionStore.get(`save:${offerKey}`))[`save:${offerKey}`].tabId, 7, 'save offer is tied to its tab');
assert.equal((await sendRuntime({ bwliteSaveOpen: offerKey }, { tab: { id: 8 }, frameId: 0, url: 'https://two.example/home' })).fallback, true,
  'a different tab cannot open a save offer');
assert.equal((await sendRuntime({ bwliteSaveOpen: offerKey }, { tab: { id: 7 }, frameId: 2, url: 'https://two.example/home' })).fallback, true,
  'a child frame cannot open a top-frame save offer');
assert.equal((await sendRuntime({ bwliteSaveOpen: offerKey }, { tab: { id: 7 }, frameId: 0, url: 'https://evil.example/home' })).fallback, true,
  'a different origin cannot open a save offer');
const openedSave = await sendRuntime({ bwliteSaveOpen: offerKey }, { tab: { id: 7 }, frameId: 0, url: 'https://two.example/home' });
assert.equal(openedSave.opened, true, 'a trusted page click opens the extension save window');
assert.match(createdWindows.at(-1).url, /^popup\.html#save=/);
assert.equal((await sendRuntime({ bwliteSaveOpen: offerKey }, { tab: { id: 7 }, frameId: 0, url: 'https://two.example/home' })).fallback, true,
  'a save offer is single-use');
console.log('background cache, write, RP, and save-scope checks ok');

// Source-loaded popup harness. It evaluates the production popup code in a
// small VM DOM/storage environment, so these checks exercise the actual event
// handlers and start path instead of test-only helper exports.
const popupSource = await readFile('./popup.js', 'utf8');
const popupProgram = popupSource
  .replace(/^import[^\n]*\n/gm, '')
  .replace(/\nstart\(\)\.catch\([\s\S]*\);\s*$/, '\n')
  + `\nthis.__popup = { start, move, adoptAccounts, closeSave, getAccounts: () => accounts, getPk: () => pk, getSv: () => sv, getApp: () => app };\n`;

function popupStorage(name, initial, notify) {
  const data = new Map(Object.entries(initial || {}));
  const keys = (input) => input === null ? [...data.keys()]
    : Array.isArray(input) ? input : typeof input === 'string' ? [input] : Object.keys(input || {});
  return {
    data,
    async get(input) {
      const out = {};
      for (const key of keys(input)) if (data.has(key)) out[key] = data.get(key);
      return out;
    },
    async set(values) {
      const changes = {};
      for (const [key, value] of Object.entries(values)) {
        changes[key] = { oldValue: data.get(key), newValue: value };
        data.set(key, value);
      }
      await notify(changes, name);
    },
    async remove(input) {
      const changes = {};
      for (const key of keys(input)) if (data.has(key)) {
        changes[key] = { oldValue: data.get(key) };
        data.delete(key);
      }
      if (Object.keys(changes).length) await notify(changes, name);
    },
    async clear() { await this.remove([...data.keys()]); },
  };
}

function popupElement(tag) {
  return new class {
    constructor() {
      this.tagName = String(tag).toUpperCase(); this.children = []; this.listeners = {};
      this.style = {}; this.dataset = {}; this.textContent = ''; this.disabled = false;
      this.hidden = false; this.value = ''; this.checked = false; this.removed = false;
    }
    append(...children) {
      for (const child of children) {
        if (typeof child === 'string') this.textContent += child;
        else if (child) this.children.push(child);
      }
    }
    replaceChildren(...children) { this.children = []; this.textContent = ''; this.append(...children); }
    addEventListener(type, fn) { this.listeners[type] = fn; if (type === 'click') this.onclick = fn; }
    remove() { this.removed = true; }
    focus() { this.focused = true; }
    setAttribute(name, value) { this[name] = String(value); }
    get firstChild() { return this.children[0]; }
  }();
}

const popupKey = bw.b64(new Uint8Array(64));
const popupAccount = (id, label = id) => ({ id, server: 'https://vault.example', email: `${id}@example.com`, label });
const popupList = (id, extra = {}) => [{ id: `${id}-item`, name: 'Login', username: 'user', password: 'pass', uris: ['https://example.com'], a: id, ...extra }];

function makePopup(hash, initial = {}, options = {}) {
  const listeners = [];
  const notify = async (changes, area) => { for (const fn of [...listeners]) await fn(changes, area); };
  const local = popupStorage('local', initial.local, notify), session = popupStorage('session', initial.session, notify);
  const sent = [], runtimeMessages = [], parentMessages = [];
  const state = { closed: false };
  const app = popupElement('main');
  const document = {
    activeElement: null,
    body: { scrollHeight: 0 },
    documentElement: { dataset: {}, append(...children) { this.children ||= []; this.children.push(...children); } },
    createElement: (tag) => popupElement(tag),
    addEventListener: () => {},
    querySelectorAll: () => [],
    getElementById(id) {
      const walk = (node) => {
        if (!node) return null;
        if (node.id === id) return node;
        for (const child of node.children || []) { const found = walk(child); if (found) return found; }
        return null;
      };
      return id === 'app' ? app : walk(app);
    },
  };
  const window = {
    close: () => { state.closed = true; },
    postMessage: (message, origin) => parentMessages.push({ message, origin }),
  };
  window.top = options.framed ? {} : window;
  window.parent = window;
  const bwHarness = { ...bw, ...(options.bw || {}) };
  const chrome = {
    storage: { local, session, onChanged: { addListener: (fn) => listeners.push(fn) } },
    tabs: {
      query: async () => options.tabs || [{ id: 9, url: 'https://example.com/login' }],
      sendMessage: async (...args) => { sent.push(args); },
      get: async (id) => ({ id, windowId: 1 }),
    },
    runtime: {
      sendMessage: async (message) => {
        runtimeMessages.push(message);
        return options.onRuntime ? options.onRuntime(message) : {};
      },
    },
    windows: { update: async () => {} },
  };
  const context = {
    window, top: window.top, parent: window.parent, location: { hash }, document, chrome,
    bw: bwHarness, fillTab: options.fillTab || (async () => false), withStateLock, mutateAccounts,
    navigator: { clipboard: { writeText: async () => {} } }, localStorage: {},
    crypto: globalThis.crypto || nodeCrypto.webcrypto, TextDecoder, URL, Intl, structuredClone,
    console, setTimeout, clearTimeout, setInterval: () => 0, clearInterval: () => {},
    addEventListener: () => {},
  };
  vm.runInNewContext(popupProgram, context, { filename: 'popup-harness-popup.js' });
  return { local, session, sent, runtimeMessages, parentMessages, app, context, api: context.__popup,
    get closed() { return state.closed; } };
}

const pkRequest = { id: 'request', kind: 'get', options: { challenge: 'c', rpId: 'example.com' },
  origin: 'https://example.com', rpId: 'example.com', tabId: 9 };
const listenerPopup = makePopup('#pk=handoff', { session: { 'pk:handoff': pkRequest } });
await listenerPopup.api.start();
await listenerPopup.session.set({ 'unrelated:key': 'still-open' });
assert.equal(listenerPopup.closed, false, 'unrelated session writes do not cancel a passkey window');
assert.ok(listenerPopup.api.getPk(), 'passkey hand-off survives an unrelated storage event');
await listenerPopup.session.remove('pk:handoff');
assert.equal(listenerPopup.closed, true, 'deleting the passkey hand-off cancels the window');
assert.equal(listenerPopup.sent.at(-1)[1].bwliteRes, 'request');

let passkeyCalls = 0;
const passkeyAccount = popupAccount('acct', 'Vault');
const passkeyItem = popupList('acct', { id: 'cipher', passkeys: [{ rpId: 'example.com', credentialId: 'b64.AAEC', userName: 'user' }] });
const passkeyPopup = makePopup('#pk=use', {
  local: { accounts: [passkeyAccount] },
  session: {
    'acct:key': popupKey, 'acct:list': JSON.stringify(passkeyItem), 'pk:use': { ...pkRequest, id: 'use-request' },
  },
}, { bw: { passkeyGet: async () => (passkeyCalls++, { id: 'credential-result' }) } });
await passkeyPopup.api.start();
const findButton = (node, text) => {
  if (node?.tagName === 'BUTTON' && node.textContent === text) return node;
  for (const child of node?.children || []) { const found = findButton(child, text); if (found) return found; }
  return null;
};
const useButton = findButton(passkeyPopup.app, 'Use');
assert.ok(useButton?.onclick, 'passkey view renders the real Use handler');
await useButton.onclick({ isTrusted: true });
assert.equal(passkeyCalls, 1, 'Use invokes passkey signing');
assert.equal(passkeyPopup.sent.at(-1)[1].bwliteRes, 'use-request', 'passkey Use answers the originating request');
assert.deepEqual(passkeyPopup.sent.at(-1)[1].result, { id: 'credential-result' });

// Opening the popup syncs a vault last synced over 5 minutes ago in the background; a recent one is left alone.
const textOf = (node) => `${node?.textContent || ''} ${(node?.children || []).map(textOf).join(' ')}`;
const findById = (node, id) => node?.id === id ? node : (node?.children || []).reduce((f, c) => f || findById(c, id), null);
for (const [lastSync, expectSync] of [[Date.now() - 6 * 60e3, true], [Date.now() - 60e3, false]]) {
  let syncCalls = 0;
  const fresh = [{ id: 'fresh-item', name: 'Login', username: 'fresh-user', password: 'p', uris: ['https://example.com'] }];
  const popup = makePopup('', {
    local: { accounts: [{ ...popupAccount('acct', 'Vault'), lastSync }] },
    session: { 'acct:key': popupKey, 'acct:list': JSON.stringify(popupList('acct')) },
  }, { bw: { api: async (_, path) => (path === '/sync' && syncCalls++, { ciphers: [], profile: {}, domains: {} }), decryptVault: async () => fresh } });
  await popup.api.start();
  const search = findById(popup.app, 'search');
  search.value = 'fresh'; search.listeners.input(); // typing while the sync runs
  popup.context.document.activeElement = search;
  for (let i = 0; i < 20 && !textOf(popup.app).includes('fresh-user'); i++) await new Promise((r) => setTimeout(r, 5));
  assert.equal(syncCalls, expectSync ? 1 : 0, expectSync ? 'a stale vault syncs when the popup opens' : 'a recent vault does not sync on open');
  assert.equal(textOf(popup.app).includes('fresh-user'), expectSync, 'the list shows what the background sync brought');
  if (expectSync) {
    const redrawn = findById(popup.app, 'search');
    assert.ok(redrawn !== search && redrawn.focused && redrawn.value === 'fresh', 'the redraw keeps the search text and focus');
  }
}

const staleAccount = popupAccount('stale');
const adoptPopup = makePopup('', { local: { accounts: [staleAccount] } });
adoptPopup.api.adoptAccounts([{ ...staleAccount, persistKey: popupKey }]);
adoptPopup.api.adoptAccounts([{ ...staleAccount }]);
assert.equal(adoptPopup.api.getAccounts()[0].persistKey, undefined, 'an omitted persisted key is removed from the existing account object');
await adoptPopup.api.start();
assert.equal(adoptPopup.api.getAccounts()[0].persistKey, undefined, 'adopting current storage removes a stale persisted key');

const moveA = popupAccount('move-a'), moveB = popupAccount('move-b'), moveC = popupAccount('move-c');
const movePopup = makePopup('', { local: { accounts: [moveA, moveB, moveC] } });
movePopup.api.adoptAccounts([moveA, moveB]);
await movePopup.api.move(0, 1);
assert.equal(JSON.stringify((await movePopup.local.get('accounts')).accounts.map((a) => a.id)), JSON.stringify(['move-b', 'move-a', 'move-c']),
  'moving a stale account snapshot preserves a concurrently added account');

const saveBase = {
  kind: 'add', username: 'user', password: 'new', origin: 'https://example.com', tabId: 9,
};
const listenerSave = makePopup('#save=listener', {
  local: { accounts: [popupAccount('save')] },
  session: { 'save:listener': { ...saveBase, expires: Date.now() + 10_000 }, 'save:key': popupKey,
    'save:list': JSON.stringify(popupList('save')) },
}, { tabs: [{ id: 99, url: 'chrome-extension://other/popup.html' }] });
await listenerSave.api.start();
await listenerSave.session.set({ 'unrelated:key': 'still-open' });
assert.ok(listenerSave.api.getSv() && !listenerSave.closed, 'unrelated session writes preserve a save window');
await listenerSave.session.remove('save:listener');
assert.equal(listenerSave.closed, true, 'deleting a save hand-off closes the save window');
assert.equal(listenerSave.parentMessages.length, 0, 'save windows never use page postMessage');

const expirySave = makePopup('#save=expiry', {
  local: { accounts: [popupAccount('expiry')] },
  session: { 'save:expiry': { ...saveBase, tabId: 9, expires: Date.now() + 15 }, 'expiry:key': popupKey,
    'expiry:list': JSON.stringify(popupList('expiry')) },
}, { tabs: [{ id: 99, url: 'chrome-extension://other/popup.html' }] });
await expirySave.api.start();
await new Promise((resolve) => setTimeout(resolve, 35));
assert.equal(expirySave.closed, true, 'an open save offer closes when its expiry timer fires');
assert.equal(expirySave.app.children.length, 0, 'expired save UI is cleared');

const framedSave = makePopup('#save=framed', {
  session: { 'save:framed': { ...saveBase, expires: Date.now() + 10_000 } },
}, { framed: true });
await framedSave.api.start();
assert.equal(framedSave.closed, true, 'a web frame cannot render the save confirmation');
assert.equal(framedSave.parentMessages.length, 0);
console.log('popup storage, passkey, account, save-window, and move checks ok');
// page.js: the credential it hands the page takes the toJSON that @github/webauthn-json assigns (in strict mode).
{
  const listeners = [];
  const ctx = {
    btoa, atob, crypto, setTimeout, clearTimeout, DOMException,
    PublicKeyCredential: class {}, AuthenticatorAssertionResponse: class {}, AuthenticatorAttestationResponse: class {},
    navigator: { credentials: { create: async () => null, get: async () => null } },
    addEventListener: (_, f) => listeners.push(f), removeEventListener: () => {},
    postMessage: (m) => queueMicrotask(() => listeners.forEach((f) => f({ source: vm.runInContext('window', ctx), data: { bwliteRes: m.bwliteReq, result: {
      id: 'aWQ', rawId: 'aWQ', type: 'public-key', clientExtensionResults: {},
      response: { clientDataJSON: 'e30', authenticatorData: 'AA', signature: 'AA', userHandle: null } } } }))),
  };
  ctx.window = ctx;
  vm.runInNewContext(await readFile('./page.js', 'utf8'), ctx);
  const cred = await ctx.navigator.credentials.get({ publicKey: { challenge: new Uint8Array([1]) } });
  assert.doesNotThrow(() => { 'use strict'; cred.toJSON = () => 'mine'; }, 'credential.toJSON is assignable');
  assert.equal(cred.toJSON(), 'mine');
  console.log('page credential checks ok');
}
const inpageSource = await readFile('./inpage.js', 'utf8');
assert.equal(inpageSource.includes('popup.html#save='), false, 'the page bar cannot frame the extension popup');
assert.equal(inpageSource.includes('attachShadow({ mode: \'closed\' })'), true, 'the save token stays in a closed extension bar');

if (!process.argv.includes('--integration')) process.exit(0);

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
assert.equal(vault[0].d, undefined, 'derived domains are not trusted for matching');
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
