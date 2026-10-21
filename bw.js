// Bitwarden protocol: key derivation, EncString crypto, API calls, TOTP. No chrome.* here so it runs in Node tests too.
import { PUBLIC_SUFFIX_LIST } from './vendor/public_suffix_list.js';
const subtle = crypto.subtle, te = new TextEncoder(), td = new TextDecoder();
const CLIENT = { 'Device-Type': '2', 'Bitwarden-Client-Name': 'browser', 'Bitwarden-Client-Version': '2025.10.0' };

export const b64 = (buf) => {
  const a = new Uint8Array(buf);
  if (a.toBase64) return a.toBase64();
  let s = '';
  for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode(...a.subarray(i, i + 0x8000));
  return btoa(s);
};
export const unb64 = (s) => {
  if (Uint8Array.fromBase64) return Uint8Array.fromBase64(s);
  const bin = atob(s), out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const sha256 = async (data) => new Uint8Array(await subtle.digest('SHA-256', typeof data === 'string' ? te.encode(data) : data));
const hmac = async (key, data, hash = 'SHA-256') =>
  new Uint8Array(await subtle.sign('HMAC', await subtle.importKey('raw', key, { name: 'HMAC', hash }, false, ['sign']), data));

export function urls(server) {
  const cloud = server.match(/^https:\/\/vault\.bitwarden\.(com|eu)$/);
  if (cloud) return { api: `https://api.bitwarden.${cloud[1]}`, identity: `https://identity.bitwarden.${cloud[1]}` };
  return { api: `${server}/api`, identity: `${server}/identity` };
}

// --- keys ---------------------------------------------------------------

export async function makeMasterKey(password, email, kdf) {
  const salt = te.encode(email.trim().toLowerCase());
  if (kdf.kdf === 0) {
    const k = await subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: kdf.kdfIterations }, k, 256));
  }
  if (kdf.kdf === 1) {
    if (!globalThis.hashwasm) { // loaded on demand so PBKDF2 accounts never pay for it
      await new Promise((resolve, reject) =>
        document.head.append(Object.assign(document.createElement('script'), { src: 'vendor/argon2.umd.min.js', onload: resolve, onerror: reject })));
    }
    return globalThis.hashwasm.argon2id({
      password, salt: await sha256(salt), iterations: kdf.kdfIterations, memorySize: kdf.kdfMemory * 1024,
      parallelism: kdf.kdfParallelism, hashLength: 32, outputType: 'binary',
    });
  }
  throw new Error(`Unsupported KDF ${kdf.kdf}`);
}

export async function passwordHash(masterKey, password) {
  const k = await subtle.importKey('raw', masterKey, 'PBKDF2', false, ['deriveBits']);
  return b64(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: te.encode(password), iterations: 1 }, k, 256));
}

// HKDF-Expand only (Bitwarden skips the extract step), one 32-byte block each for enc and mac.
export const stretch = async (mk) => concat(await hmac(mk, concat(te.encode('enc'), [1])), await hmac(mk, concat(te.encode('mac'), [1])));

// --- EncString (type 2: AES-256-CBC + HMAC-SHA256; type 4: RSA-OAEP-SHA1) ---

// Imported CryptoKeys per key object: a vault decrypt reuses the same few keys thousands of times.
const keyCache = new WeakMap();
function cryptoKeys(key) {
  if (!keyCache.has(key)) keyCache.set(key, Promise.all([
    subtle.importKey('raw', key.slice(0, 32), 'AES-CBC', false, ['encrypt', 'decrypt']),
    subtle.importKey('raw', key.slice(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']),
  ]));
  return keyCache.get(key);
}

export async function decrypt(s, key) {
  const [type, rest] = [s.slice(0, s.indexOf('.')), s.slice(s.indexOf('.') + 1)];
  if (type !== '2') throw new Error(`Unsupported EncString type ${type}`);
  const [iv, ct, mac] = rest.split('|').map(unb64);
  const [aes, hmacKey] = await cryptoKeys(key);
  if (!(await subtle.verify('HMAC', hmacKey, mac, concat(iv, ct)))) throw new Error('MAC mismatch');
  return new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv }, aes, ct));
}
const decStr = async (s, key) => (s ? td.decode(await decrypt(s, key)) : '');

export async function encrypt(data, key) {
  if (typeof data === 'string') data = te.encode(data);
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const [aes, hmacKey] = await cryptoKeys(key);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv }, aes, data));
  return `2.${b64(iv)}|${b64(ct)}|${b64(await subtle.sign('HMAC', hmacKey, concat(iv, ct)))}`;
}

async function rsaDecrypt(s, pkcs8) {
  if (!s.startsWith('4.')) throw new Error(`Unsupported org key type ${s[0]}`);
  const k = await subtle.importKey('pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-1' }, false, ['decrypt']);
  return new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, k, unb64(s.slice(2))));
}

// --- API ----------------------------------------------------------------

async function post(url, body, headers = {}) {
  const r = await fetch(url, { method: 'POST', headers: { ...CLIENT, ...headers }, body });
  return { ok: r.ok, status: r.status, json: await r.json().catch(() => ({})) };
}

export async function prelogin(server, email) {
  const { identity, api } = urls(server);
  for (const base of [identity, api]) {
    const r = await post(`${base}/accounts/prelogin`, JSON.stringify({ email }), { 'Content-Type': 'application/json' });
    if (r.ok) return { kdf: r.json.kdf, kdfIterations: r.json.kdfIterations, kdfMemory: r.json.kdfMemory, kdfParallelism: r.json.kdfParallelism };
  }
  throw new Error('Could not reach the server (prelogin failed)');
}

const tokens = (j) => ({ access: j.access_token, refresh: j.refresh_token, expires: Date.now() + j.expires_in * 1000 });

// code: {kind: '2fa' | 'device', value} on the second attempt, after login threw an error with .need set.
export async function login(server, email, password, deviceId, code) {
  const kdf = await prelogin(server, email);
  const mk = await makeMasterKey(password, email, kdf);
  const body = new URLSearchParams({
    grant_type: 'password', username: email, password: await passwordHash(mk, password), scope: 'api offline_access',
    client_id: 'browser', deviceType: '2', deviceIdentifier: deviceId, deviceName: 'chrome',
  });
  if (code?.kind === '2fa') body.append('twoFactorToken', code.value), body.append('twoFactorProvider', '0'), body.append('twoFactorRemember', '1');
  if (code?.kind === 'device') body.append('newDeviceOtp', code.value);
  const authEmail = btoa(email).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const r = await post(`${urls(server).identity}/connect/token`, body, { 'Content-Type': 'application/x-www-form-urlencoded', 'Auth-Email': authEmail });
  const j = r.json;
  if (!r.ok) {
    const providers = j.TwoFactorProviders2 || j.twoFactorProviders2;
    if (providers) {
      if (!('0' in providers)) throw new Error('Only authenticator-app 2FA is supported');
      throw Object.assign(new Error('Authenticator code'), { need: '2fa' });
    }
    if (/new device/i.test(JSON.stringify(j))) throw Object.assign(new Error('Code emailed to you'), { need: 'device' });
    throw new Error(j.ErrorModel?.Message || j.errorModel?.message || j.message || j.error_description || `Login failed (${r.status})`);
  }
  const protectedKey = j.Key || j.key;
  return { kdf, protectedKey, userKey: await decrypt(protectedKey, await stretch(mk)), tokens: tokens(j) };
}

export async function unlock(password, email, kdf, protectedKey) {
  try {
    return await decrypt(protectedKey, await stretch(await makeMasterKey(password, email, kdf)));
  } catch (e) {
    if (e.message === 'MAC mismatch') throw new Error('Wrong master password');
    throw e;
  }
}

export async function refresh(server, refreshToken) {
  const body = new URLSearchParams({ grant_type: 'refresh_token', client_id: 'browser', refresh_token: refreshToken });
  const r = await post(`${urls(server).identity}/connect/token`, body, { 'Content-Type': 'application/x-www-form-urlencoded' });
  if (!r.ok) throw new Error('Session expired, log out and log in again');
  return { ...tokens(r.json), refresh: r.json.refresh_token || refreshToken };
}

// s: {server, tokens, onTokens(tokens)}; refreshes the access token when it is about to expire.
export async function api(s, path, method = 'GET', body) {
  if (Date.now() > s.tokens.expires - 60e3) await s.onTokens?.((s.tokens = await refresh(s.server, s.tokens.refresh)));
  const r = await fetch(urls(s.server).api + path, {
    method, body: body && JSON.stringify(body),
    headers: { ...CLIENT, Authorization: `Bearer ${s.tokens.access}`, ...(body && { 'Content-Type': 'application/json' }) },
  });
  if (!r.ok) throw new Error(`${method} ${path} failed (${r.status}): ${(await r.text()).slice(0, 200)}`);
  const text = await r.text(); // some calls (delete) answer with an empty body
  return text && JSON.parse(text);
}

// --- vault --------------------------------------------------------------

// ponytail: logins only; secure notes, cards and identities are skipped.
const collator = new Intl.Collator();
// prev: Map of id -> earlier result; entries whose revisionDate is unchanged are reused instead of decrypted again.
export async function decryptVault(sync, userKey, prev) {
  const priv = sync.profile.privateKey && (await decrypt(sync.profile.privateKey, userKey));
  const orgKeys = {};
  for (const o of sync.profile.organizations || []) if (o.key) orgKeys[o.id] = await rsaDecrypt(o.key, priv);
  const out = await Promise.all(sync.ciphers.filter((c) => c.type === 1 && !c.deletedDate).map(async (c) => {
    if (prev?.get(c.id)?.rev === c.revisionDate) return prev.get(c.id);
    try {
      const key = c.key ? await decrypt(c.key, orgKeys[c.organizationId] || userKey) : orgKeys[c.organizationId] || userKey;
      const l = c.login || {};
      const [name, notes, username, password, totp, ...uris] = await Promise.all(
        [c.name, c.notes, l.username, l.password, l.totp, ...(l.uris || []).map((u) => u.uri)].map((x) => decStr(x, key)));
      const passkeys = l.fido2Credentials?.length ? await Promise.all(l.fido2Credentials.map(async (f) =>
        Object.fromEntries(await Promise.all(PASSKEY_FIELDS.map(async (k) => [k, await decStr(f[k], key)]))))) : undefined;
      const m = l.uris?.some((u) => u.match != null) ? l.uris.map((u) => u.match) : undefined; // per-URI match type, when any is set
      return { id: c.id, rev: c.revisionDate, raw: c, key, name, notes, username, password, totp, uris, m, passkeys };
    } catch (e) {
      console.warn('Skipping undecryptable item', c.id, e);
    }
  }));
  return out.filter(Boolean).sort((a, b) => collator.compare(a.name, b.name) || collator.compare(a.username, b.username));
}

// item: a decryptVault() entry to edit, or null to create. Starts from the synced (still encrypted) cipher so
// fields this client doesn't show (custom fields, passkeys, attachments, history) are sent back untouched.
export async function saveCipher(s, userKey, item, v) {
  if (item?.raw?.edit === false) throw new Error('This login is read-only');
  if (item && (!item.raw || typeof item.raw !== 'object' || !item.id)) throw new Error('Login data is incomplete; sync and try again');
  if (!v || !Array.isArray(v.uris)) throw new Error('Login URLs are invalid');
  const key = item?.key || userKey;
  const e = (x) => (x ? encrypt(x, key) : null);
  const c = item ? structuredClone(item.raw) : { type: 1, organizationId: null, folderId: null, favorite: false, reprompt: 0, login: {} };
  c.login ||= {};
  const now = new Date().toISOString();
  if (item?.password && item.password !== v.password) {
    c.passwordHistory = [{ password: c.login.password, lastUsedDate: now }, ...(c.passwordHistory || [])].slice(0, 5);
    c.login.passwordRevisionDate = now;
  }
  c.name = await e(v.name);
  c.notes = await e(v.notes);
  Object.assign(c.login, { username: await e(v.username), password: await e(v.password), totp: await e(v.totp) });
  c.login.uris = await Promise.all(v.uris.map(async (u) => ({
    uri: await encrypt(u, key),
    uriChecksum: await encrypt(b64(await sha256(u)), key), // official clients drop a URI whose checksum doesn't match
    match: item?.raw.login?.uris?.[item.uris.indexOf(u)]?.match ?? null,
  })));
  // one passkey per login, as in the official clients: saving one replaces the old
  if (v.passkey) c.login.fido2Credentials = [{
    ...Object.fromEntries(await Promise.all(PASSKEY_FIELDS.map(async (k) => [k, await e(v.passkey[k])]))), creationDate: v.passkey.creationDate }];
  delete c.login.uri; // legacy single-URI field; the server would append it to uris
  if (c.attachments) c.attachments2 = Object.fromEntries(c.attachments.map((a) => [a.id, { fileName: a.fileName, key: a.key }]));
  delete c.attachments;
  c.encryptedFor = JSON.parse(atob(s.tokens.access.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).sub; // user id from the JWT
  if (!item) return api(s, '/ciphers', 'POST', c);
  c.lastKnownRevisionDate = c.revisionDate;
  return api(s, `/ciphers/${item.id}`, 'PUT', c);
}

// Moves an item to the trash, as the official clients' Delete does (restorable there for 30 days).
export const deleteCipher = (s, id) => api(s, `/ciphers/${id}/delete`, 'PUT');

// The list includes ICANN and private suffixes (for example github.io and pages.dev).
const psl = (() => {
  const exact = new Set(), wildcard = new Set(), exception = new Set();
  const idna = (rule) => {
    const prefix = rule.startsWith('!') ? '!' : rule.startsWith('*.') ? '*.' : '';
    const body = rule.slice(prefix === '!' ? 1 : prefix === '*.' ? 2 : 0);
    try { return `${prefix}${new URL(`https://${body}`).hostname.toLowerCase().replace(/\.$/, '')}`; } catch { return rule.toLowerCase(); }
  };
  for (const raw of PUBLIC_SUFFIX_LIST.split(/\s+/)) {
    if (!raw || raw.startsWith('//')) continue;
    const rule = idna(raw);
    if (rule[0] === '!') exception.add(rule.slice(1));
    else if (rule.startsWith('*.')) wildcard.add(rule.slice(2));
    else exact.add(rule);
  }
  return { exact, wildcard, exception };
})();

const normalizeHost = (host) => {
  let value = String(host || '').trim();
  try {
    // URL.hostname applies IDNA (for example bücher.de -> xn--bcher-kva.de)
    // consistently for both saved URIs and page origins.
    if (value && !value.includes('/') && !value.startsWith('[')) value = new URL(`https://${value}`).hostname;
  } catch {}
  return value.toLowerCase().replace(/\.$/, '');
};
const ipHost = (host) => /^[\d.]+$/.test(host) || host.includes(':');
const suffixLength = (host) => {
  const labels = normalizeHost(host).split('.');
  let best = 1;
  for (let i = 0; i < labels.length; i++) {
    const rule = labels.slice(i).join('.');
    if (psl.exception.has(rule)) return labels.length - i - 1;
    if (psl.exact.has(rule)) best = Math.max(best, labels.length - i);
    if (i > 0 && psl.wildcard.has(labels.slice(i).join('.'))) best = Math.max(best, labels.length - i + 1);
  }
  return best;
};

export function isPublicSuffix(host) {
  host = normalizeHost(host);
  return !!host && !ipHost(host) && host.split('.').length === suffixLength(host);
}

export function baseDomain(host) {
  host = normalizeHost(host);
  if (!host || ipHost(host)) return host;
  const p = host.split('.'), suffix = suffixLength(host);
  return p.length <= suffix ? host : p.slice(-(suffix + 1)).join('.');
}

const toURL = (u) => new URL(/^[a-z][\w+.-]*:\/\//i.test(u) ? u : `https://${u}`);

export function domainOf(u) {
  try {
    return baseDomain(toURL(u).hostname);
  } catch {
    return null;
  }
}

// groups: lists of domains the server treats as one site (sync.domains). Returns domain -> every domain it equals.
export function equivalents(groups) {
  const parent = new Map();
  const find = (x) => {
    if (!parent.has(x)) parent.set(x, x);
    while (parent.get(x) !== x) {
      parent.set(x, parent.get(parent.get(x)));
      x = parent.get(x);
    }
    return x;
  };
  const union = (a, b) => {
    a = find(a); b = find(b);
    if (a !== b) parent.set(b, a);
  };
  for (const group of groups || []) {
    if (!Array.isArray(group)) continue;
    const domains = group.map(domainOf).filter(Boolean);
    for (const d of domains) find(d);
    for (const d of domains.slice(1)) union(domains[0], d);
  }
  const components = new Map();
  for (const d of parent.keys()) {
    const root = find(d), set = components.get(root) || new Set();
    set.add(d); components.set(root, set);
  }
  const out = new Map();
  for (const set of components.values()) for (const d of set) out.set(d, set);
  return out;
}

// Per saved URI, its match type as in Bitwarden: null/0 base domain (or an equivalent one), 1 host (with port),
// 2 starts with, 3 exact, 4 regular expression, 5 never.
export function matches(item, url, equiv) {
  if (!item || !Array.isArray(item.uris)) return false;
  let page;
  try { page = new URL(url); } catch { return false; }
  const site = baseDomain(page.hostname);
  return item.uris.some((u, n) => {
    try {
      switch (item.m?.[n] ?? 0) {
        case 0: { const d = domainOf(u); return !!d && (d === site || !!equiv?.get(site)?.has(d)); }
        case 1: return toURL(u).host === page.host;
        case 2: return url.startsWith(u);
        case 3: return url === u;
        case 4: return new RegExp(u, 'i').test(url);
        default: return false;
      }
    } catch {
      return false;
    }
  });
}

// The logins for a page, best first: last used (used: {'account:cipher': time}), then vault order (rank).
export const forSite = (items, url, equiv, rank, used = {}) => (Array.isArray(items) ? items : []).filter((i) => matches(i, url, typeof equiv === 'function' ? equiv(i) : equiv))
  .sort((x, y) => (used[`${y.a}:${y.id}`] || 0) - (used[`${x.a}:${x.id}`] || 0) || rank(x.a) - rank(y.a));

// --- passkeys (WebAuthn, ES256 only) --------------------------------------
// Stored as the official clients store them (login.fido2Credentials, every field an EncString), so a passkey made here
// works there and back. Requests and results use the WebAuthn JSON shapes: binary values are base64url strings.

const PASSKEY_FIELDS = ['credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId', 'rpName', 'userHandle',
  'userName', 'userDisplayName', 'counter', 'discoverable'];
export const b64u = (buf) => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => unb64(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '='));
// Official clients give passkeys they create a GUID id and imported ones 'b64.' + base64url.
export const credIdBytes = (id) =>
  id.startsWith('b64.') ? unb64u(id.slice(4)) : Uint8Array.from(id.replace(/-/g, '').match(/../g), (x) => parseInt(x, 16));
const cborBytes = (b) => concat(b.length < 24 ? [0x40 + b.length] : b.length < 256 ? [0x58, b.length] : [0x59, b.length >> 8, b.length & 255], b);
const cborText = (s) => concat([0x60 + s.length], te.encode(s)); // short ASCII keys only
const toJSON = (r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, v instanceof ArrayBuffer || ArrayBuffer.isView(v) ? b64u(v) : v]));
const clientData = (type, o, origin) => te.encode(JSON.stringify({ type, challenge: o.challenge, origin, crossOrigin: false }));
// The signature counter stays 0 (allowed by WebAuthn), so signing in never writes to the vault.
const authData = async (rpId, flags, extra = []) => concat(await sha256(rpId), [flags, 0, 0, 0, 0], extra);
const UP_UV_BE_BS = 0x1d, AT = 0x40; // user present + verified, backup eligible + backed up (synced), attested data

// WebCrypto signs ECDSA as r|s; WebAuthn wants DER.
function der(sig) {
  const int = (b) => {
    let i = 0;
    while (i < b.length - 1 && !b[i]) i++;
    b = b.slice(i);
    return concat([2, b.length + (b[0] >> 7)], b[0] >> 7 ? [0] : [], b);
  };
  const body = concat(int(sig.slice(0, 32)), int(sig.slice(32)));
  return concat([0x30, body.length], body);
}

// o: PublicKeyCredentialCreationOptions as JSON. Returns the passkey to store and the result for the page.
export async function passkeyCreate(o, origin, rpId) {
  const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const id = crypto.randomUUID(), rawId = credIdBytes(id);
  const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey)); // 04 | x | y
  const cose = concat([0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 32], pub.slice(1, 33), [0x22, 0x58, 32], pub.slice(33)); // EC2, ES256, P-256
  const auth = await authData(rpId, UP_UV_BE_BS | AT, concat(new Uint8Array(16), [0, rawId.length], rawId, cose)); // zero AAGUID
  const att = concat([0xa3], cborText('fmt'), cborText('none'), cborText('attStmt'), [0xa0], cborText('authData'), cborBytes(auth));
  const passkey = {
    credentialId: id, keyType: 'public-key', keyAlgorithm: 'ECDSA', keyCurve: 'P-256', keyValue: b64u(await subtle.exportKey('pkcs8', kp.privateKey)),
    rpId, rpName: o.rp.name, userHandle: o.user.id, userName: o.user.name, userDisplayName: o.user.displayName,
    counter: '0', discoverable: 'true', creationDate: new Date().toISOString(),
  };
  const response = toJSON({
    clientDataJSON: clientData('webauthn.create', o, origin), attestationObject: att, authenticatorData: auth,
    publicKey: await subtle.exportKey('spki', kp.publicKey), publicKeyAlgorithm: -7, transports: ['internal', 'hybrid'],
  });
  const ext = o.extensions?.credProps ? { credProps: { rk: true } } : {};
  return { passkey, result: { id: b64u(rawId), rawId: b64u(rawId), type: 'public-key', authenticatorAttachment: 'platform', clientExtensionResults: ext, response } };
}

// p: a decrypted passkey; o: PublicKeyCredentialRequestOptions as JSON.
export async function passkeyGet(p, o, origin) {
  const auth = await authData(p.rpId, UP_UV_BE_BS);
  const cd = clientData('webauthn.get', o, origin);
  const key = await subtle.importKey('pkcs8', unb64u(p.keyValue), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, concat(auth, await sha256(cd))));
  const id = b64u(credIdBytes(p.credentialId));
  const response = toJSON({ clientDataJSON: cd, authenticatorData: auth, signature: der(sig), userHandle: p.userHandle ? unb64u(p.userHandle) : null });
  return { id, rawId: id, type: 'public-key', authenticatorAttachment: 'platform', clientExtensionResults: {}, response };
}

// --- TOTP (RFC 6238) ------------------------------------------------------

function base32(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const ch of s.toUpperCase().replace(/[\s=-]/g, '')) {
    const v = A.indexOf(ch);
    if (v < 0) throw new Error('Bad TOTP secret');
    bits += v.toString(2).padStart(5, '0');
  }
  return Uint8Array.from(bits.match(/.{8}/g) || [], (b) => parseInt(b, 2));
}

export async function totp(secret, now = Date.now()) {
  if (typeof secret !== 'string' || !secret.trim()) throw new Error('Bad TOTP secret');
  let algo = 'SHA-1', digits = 6, period = 30;
  if (/^otpauth:/i.test(secret)) {
    const q = new URL(secret).searchParams;
    secret = q.get('secret') || '';
    const algorithm = q.get('algorithm')?.toUpperCase() || 'SHA1';
    algo = { SHA1: 'SHA-1', 'SHA-1': 'SHA-1', SHA256: 'SHA-256', 'SHA-256': 'SHA-256', SHA512: 'SHA-512', 'SHA-512': 'SHA-512' }[algorithm];
    if (!algo) throw new Error('Unsupported TOTP algorithm');
    digits = q.has('digits') ? Number(q.get('digits')) : 6;
    period = q.has('period') ? Number(q.get('period')) : 30;
  }
  if (![6, 8].includes(digits)) throw new Error('Unsupported TOTP digits');
  if (!Number.isSafeInteger(period) || period <= 0 || period > 86400) throw new Error('Bad TOTP period');
  const key = base32(secret);
  if (!key.length) throw new Error('Bad TOTP secret');
  const counter = new Uint8Array(8);
  for (let t = Math.floor(now / 1000 / period), i = 7; i >= 0; i--, t = Math.floor(t / 256)) counter[i] = t & 0xff;
  const h = await hmac(key, counter, algo);
  const o = h[h.length - 1] & 0xf;
  const n = (((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 10 ** digits;
  return { code: String(n).padStart(digits, '0'), remaining: period - (Math.floor(now / 1000) % period) };
}
