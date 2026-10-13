// Bitwarden protocol: key derivation, EncString crypto, API calls, TOTP. No chrome.* here so it runs in Node tests too.
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
  return r.json();
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
      return { id: c.id, rev: c.revisionDate, raw: c, key, name, notes, username, password, totp, uris, d: uris.map(domainOf) };
    } catch (e) {
      console.warn('Skipping undecryptable item', c.id, e);
    }
  }));
  return out.filter(Boolean).sort((a, b) => collator.compare(a.name, b.name) || collator.compare(a.username, b.username));
}

// item: a decryptVault() entry to edit, or null to create. Starts from the synced (still encrypted) cipher so
// fields this client doesn't show (custom fields, passkeys, attachments, history) are sent back untouched.
export async function saveCipher(s, userKey, item, v) {
  const key = item?.key || userKey;
  const e = (x) => (x ? encrypt(x, key) : null);
  const c = item ? structuredClone(item.raw) : { type: 1, organizationId: null, folderId: null, favorite: false, reprompt: 0, login: {} };
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
  delete c.login.uri; // legacy single-URI field; the server would append it to uris
  if (c.attachments) c.attachments2 = Object.fromEntries(c.attachments.map((a) => [a.id, { fileName: a.fileName, key: a.key }]));
  delete c.attachments;
  delete c.data;
  c.encryptedFor = JSON.parse(atob(s.tokens.access.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).sub; // user id from the JWT
  if (!item) return api(s, '/ciphers', 'POST', c);
  c.lastKnownRevisionDate = c.revisionDate;
  return api(s, `/ciphers/${item.id}`, 'PUT', c);
}

// ponytail: base domain without the public suffix list; covers co.uk-style suffixes only. Add a PSL if it mismatches.
export function baseDomain(host) {
  if (/^[\d.]+$/.test(host) || host.includes(':')) return host;
  const p = host.split('.');
  return p.slice(/^(co|com|net|org|gov|ac|edu)$/.test(p.at(-2)) && p.at(-1).length === 2 ? -3 : -2).join('.');
}

export function domainOf(u) {
  try {
    return baseDomain(new URL(/^[a-z][\w+.-]*:\/\//i.test(u) ? u : `https://${u}`).hostname);
  } catch {
    return null;
  }
}

// item.d: domains precomputed by decryptVault, so matching a big vault doesn't parse every URL again.
export const matches = (item, host) => (item.d || item.uris.map(domainOf)).includes(baseDomain(host));

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
  let algo = 'SHA-1', digits = 6, period = 30;
  if (/^otpauth:/i.test(secret)) {
    const q = new URL(secret).searchParams;
    secret = q.get('secret') || '';
    algo = { SHA256: 'SHA-256', SHA512: 'SHA-512' }[q.get('algorithm')?.toUpperCase()] || 'SHA-1';
    digits = +q.get('digits') || 6;
    period = +q.get('period') || 30;
  }
  const counter = new Uint8Array(8);
  for (let t = Math.floor(now / 1000 / period), i = 7; i >= 0; i--, t = Math.floor(t / 256)) counter[i] = t & 0xff;
  const h = await hmac(base32(secret), counter, algo);
  const o = h[h.length - 1] & 0xf;
  const n = (((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 10 ** digits;
  return { code: String(n).padStart(digits, '0'), remaining: period - (Math.floor(now / 1000) % period) };
}
