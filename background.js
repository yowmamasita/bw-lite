// Service worker: passkey requests, the toolbar badge, the autofill shortcut, the in-page login menu and the
// "save this login?" offer. It reads the vaults the popup has opened (session storage); writing stays in the
// extension-owned save confirmation and passkey windows.
import * as bw from './bw.js';
import { fillTab } from './autofill.js';
import { withStateLock } from './coord.js';

const local = chrome.storage.local, session = chrome.storage.session, td = new TextDecoder();
const http = (url) => /^https?:\/\//i.test(url || '');
const https = (url) => /^https:\/\//i.test(url || '');
const accountId = (id) => typeof id === 'string' && /^[\w-]{1,64}$/.test(id);
const requestId = (id) => typeof id === 'string' && id.length > 0 && id.length < 200;

// --- vault state, cached until anything in storage changes -------------------

let state, stateVersion = 0, usedWrite = Promise.resolve();
async function vault() {
  if (state) return state;
  const version = stateVersion;
  const stored = await local.get(['accounts', 'used', 'neverSave']);
  const seen = new Set();
  const accounts = Array.isArray(stored.accounts) ? stored.accounts.filter((a) => accountId(a?.id) && !seen.has(a.id) && seen.add(a.id)) : [];
  const used = stored.used && typeof stored.used === 'object' ? stored.used : {};
  const neverSave = Array.isArray(stored.neverSave) ? stored.neverSave.filter((h) => typeof h === 'string') : [];
  const s = await session.get(accounts.flatMap((a) => [`${a.id}:key`, `${a.id}:list`]));
  const validSessionKey = (key) => {
    try { return typeof key === 'string' && bw.unb64(key).length === 64; } catch { return false; }
  };
  const items = [];
  let open = 0;
  for (const a of accounts) {
    let list = s[`${a.id}:list`];
    if (list && !validSessionKey(s[`${a.id}:key`])) {
      // A list without its key is a stale half of a lock/removal. Never expose it.
      await session.remove([`${a.id}:list`, `${a.id}:key`]).catch(() => {});
      list = null;
    }
    try {
      let parsed;
      if (!list && a.persistKey) { // Never lock, browser restarted: open the encrypted list as the popup would
        list = await withStateLock(async () => {
          // A popup can lock or remove this account while decrypt is suspended.
          // Re-read the account under the same lock and publish only while its
          // current persisted key still authorizes the restore.
          const latest = (await local.get('accounts')).accounts?.find((x) => x?.id === a.id);
          if (!latest?.persistKey || latest.persistKey !== a.persistKey || stateVersion !== version) return null;
          const current = await session.get([`${a.id}:key`, `${a.id}:list`]);
          if (validSessionKey(current[`${a.id}:key`]) && current[`${a.id}:list`]) return current[`${a.id}:list`];
          const { [`${a.id}:index4`]: index } = await local.get(`${a.id}:index4`);
          if (!index) return null;
          const persistKey = bw.unb64(latest.persistKey);
          if (persistKey.length !== 64) throw new Error('bad persisted vault key');
          const text = td.decode(await bw.decrypt(index, persistKey));
          parsed = JSON.parse(text);
          if (!Array.isArray(parsed)) throw new Error('cached list is not an array');
          const currentLatest = (await local.get('accounts')).accounts?.find((x) => x?.id === a.id);
          if (currentLatest?.persistKey !== latest.persistKey || stateVersion !== version) return null;
          await session.set({ [`${a.id}:list`]: text, [`${a.id}:key`]: latest.persistKey });
          return text;
        });
      }
      if (list) {
        parsed ||= JSON.parse(list);
        if (!Array.isArray(parsed)) throw new Error('cached list is not an array');
        open++, items.push(...parsed.filter((i) => i && Array.isArray(i.uris) && i.uris.every((u) => typeof u === 'string')
          && (!i.passkeys || Array.isArray(i.passkeys))).map((i) => ({ ...i, a: a.id })));
      }
    } catch (e) {
      console.warn('Skipping corrupt cached vault', a.id, e);
      await session.remove([`${a.id}:list`, `${a.id}:key`]).catch(() => {});
    }
  }
  // Recheck the session snapshot while holding the same lock as popup lock and
  // removal. A key/list can be revoked after the first read but before this
  // state is published; in that case discard the build and retry.
  const stable = await withStateLock(async () => {
    if (version !== stateVersion) return false;
    const rawLatest = (await local.get('accounts')).accounts;
    const seenLatest = new Set();
    const latestAccounts = Array.isArray(rawLatest) ? rawLatest.filter((a) => accountId(a?.id) && !seenLatest.has(a.id) && seenLatest.add(a.id)) : [];
    if (!Array.isArray(latestAccounts) || latestAccounts.length !== accounts.length
      || accounts.some((a, i) => latestAccounts[i]?.id !== a.id || latestAccounts[i]?.persistKey !== a.persistKey)) return false;
    const current = await session.get(accounts.flatMap((a) => [`${a.id}:key`, `${a.id}:list`]));
    return accounts.every((a) => current[`${a.id}:key`] === s[`${a.id}:key`] && current[`${a.id}:list`] === s[`${a.id}:list`]);
  });
  if (!stable) return vault();
  const eq = await local.get(accounts.map((a) => `${a.id}:eq`));
  const rank = (id) => accounts.findIndex((a) => a.id === id);
  if (version !== stateVersion) return vault();
  const equiv = new Map(accounts.map((a) => [a.id, bw.equivalents(eq[`${a.id}:eq`])]))
  return (state = { accounts, used, neverSave, items, open, equiv, rank });
}
const forSite = (v, url) => bw.forSite(v.items, url, (i) => v.equiv.get(i.a), v.rank, v.used);
const markUsed = (i, version = null) => {
  const job = usedWrite.catch(() => {}).then(async () => {
    if (version !== null && version !== stateVersion) return false;
    const { accounts = [], used = {} } = await local.get(['accounts', 'used']);
    if (!accounts.some((a) => a?.id === i.a) || (version !== null && version !== stateVersion)) return false;
    await local.set({ used: { ...(used && typeof used === 'object' ? used : {}), [`${i.a}:${i.id}`]: Date.now() } });
    return true;
  });
  usedWrite = job.catch(() => {});
  return job;
};

// --- badge: number of logins for the tab's page --------------------------------

async function badge(tabId, url) {
  const n = http(url) ? forSite(await vault(), url).length : 0;
  await chrome.action.setBadgeText({ tabId, text: n ? String(n) : '' }).catch(() => {});
}
let redraw;
chrome.storage.onChanged.addListener((changes, area) => {
  const relevant = area === 'local' || Object.keys(changes).some((k) => /:key$|:list$/.test(k));
  if (!relevant) return; // save/passkey hand-off records do not change the cached vault
  state = null;
  stateVersion++;
  clearTimeout(redraw);
  redraw = setTimeout(async () => (await chrome.tabs.query({})).forEach((t) => badge(t.id, t.url)), 300);
});
chrome.action.setBadgeBackgroundColor({ color: '#555' });

// --- autofill shortcut (Ctrl/Cmd+Shift+L): the top login, as the popup's highlighted Fill -------------

chrome.commands.onCommand.addListener(async (command, tab) => {
  if (command !== 'autofill' || !http(tab?.url)) return;
  const v = await vault();
  const version = stateVersion;
  const [item] = forSite(v, tab.url);
  if (!item) return chrome.action.openPopup().catch(() => {}); // locked or nothing saved: show why
  if (version !== stateVersion) return;
  const code = item.totp ? (await bw.totp(item.totp).catch(() => null))?.code || null : null;
  if (await fillTab(tab.id, item, v.equiv.get(item.a), code, async () => version === stateVersion, tab.documentId) && version === stateVersion) await markUsed(item, version);
});

// --- save offers: remembered per tab when a login is submitted, offered once the page has moved on -----------

const pending = new Map(); // tabId -> { at, username, password, url, offer? }
async function submitted(tabId, url, credentials) {
  if (!credentials || typeof credentials !== 'object') return;
  let { username, password } = credentials;
  if (!Number.isInteger(tabId) || !http(url) || typeof username !== 'string' || typeof password !== 'string') return;
  let page;
  try { page = new URL(url); } catch { return; }
  const now = Date.now(), origin = page.origin;
  const old = pending.get(tabId);
  const prev = old && now - old.at <= 60e3 && old.origin === origin ? old : null;
  if (!password) return pending.set(tabId, { at: now, username, url, origin }); // username step of a two-step login
  username ||= prev?.username || '';
  const version = stateVersion;
  const v = await vault();
  if (version !== stateVersion || !v.open || v.neverSave.includes(new URL(url).hostname)) return pending.delete(tabId);
  const logins = forSite(v, url);
  const lower = username.toLowerCase();
  const same = username ? logins.filter((i) => i.username.toLowerCase() === lower) : logins.length === 1 ? logins : [];
  if (logins.some((i) => i.password === password && (!username || i.username.toLowerCase() === lower)) || (!username && !same.length && logins.length)) {
    return pending.delete(tabId);
  }
  const offer = same.length ? { kind: 'update', a: same[0].a, id: same[0].id, username: same[0].username } : { kind: 'add', username };
  pending.set(tabId, { at: now, username, url, origin, offer: { ...offer, password, origin } });
}
chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.url || info.status === 'complete') badge(tabId, tab.url);
  const p = pending.get(tabId);
  // loaded, or a single-page app moved to another URL
  if (!(info.status === 'complete' || (info.url && tab.status === 'complete')) || !p?.offer) return;
  if (Date.now() - p.at > 60e3) return pending.delete(tabId);
  let current;
  try { current = new URL(tab.url); } catch { return pending.delete(tabId); }
  if (!http(tab.url) || current.origin !== p.origin) return pending.delete(tabId);
  pending.delete(tabId);
  const key = crypto.randomUUID();
  const version = stateVersion;
  await session.set({ [`save:${key}`]: { ...p.offer, tabId, expires: Date.now() + 60e3 } });
  if (version !== stateVersion) return session.remove(`save:${key}`);
  chrome.tabs.sendMessage(tabId, { bwliteBar: key }, { frameId: 0 }).catch(() => session.remove(`save:${key}`));
});
chrome.tabs.onRemoved.addListener((tabId) => pending.delete(tabId));

// The page bar only asks for review. The offer itself stays in session storage
// and is opened in an extension window after Chrome authenticates the sender's
// tab and origin. This keeps the password out of a web-accessible iframe.
async function openSave(key, sender) {
  if (!requestId(key) || !sender?.tab || !Number.isInteger(sender.tab.id) || sender.frameId !== 0
    || typeof sender.url !== 'string' || !http(sender.url)) {
    return { fallback: true };
  }
  let page;
  try { page = new URL(sender.url); } catch { return { fallback: true }; }
  if (typeof sender.origin === 'string' && sender.origin !== page.origin) return { fallback: true };
  let current;
  try { current = await chrome.tabs.get(sender.tab.id); } catch { return { fallback: true }; }
  let currentOrigin;
  try { currentOrigin = new URL(current?.url || '').origin; } catch { return { fallback: true }; }
  if (current?.id !== sender.tab.id || currentOrigin !== page.origin) return { fallback: true };
  return withStateLock(async () => {
    const keyName = `save:${key}`;
    const stored = await session.get(keyName);
    const offer = stored[keyName];
    if (!offer || offer.opened || offer.tabId !== sender.tab.id || offer.origin !== page.origin
      || !Number.isFinite(offer.expires) || offer.expires <= Date.now()) return { fallback: true };
    const opened = { ...offer, opened: true };
    await session.set({ [keyName]: opened });
    try {
      await chrome.windows.create({ url: `popup.html#save=${key}`, type: 'popup', width: 410, height: 240 });
      return { opened: true };
    } catch {
      await session.set({ [keyName]: offer });
      return { fallback: true };
    }
  });
}

// --- messages from inpage.js / bridge.js -----------------------------------------------

const validDescriptor = (d) => d && typeof d === 'object' && typeof d.id === 'string' && d.id.length > 0 && d.id.length < 1000
  && (d.type === undefined || d.type === 'public-key')
  && (d.transports === undefined || Array.isArray(d.transports) && d.transports.every((t) => ['usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card'].includes(t)));
const supportedPasskeyOptions = (kind, o) => {
  // The local implementation always creates a platform discoverable key and
  // cannot satisfy arbitrary authenticator/extension requirements. Let the
  // browser handle requests whose semantics we cannot reproduce.
  if (o.timeout !== undefined || o.authenticatorSelection || o.authenticatorAttachment || o.userVerification
    || o.attestation && o.attestation !== 'none') return false;
  if (o.extensions && (typeof o.extensions !== 'object' || Object.keys(o.extensions).some((k) => k !== 'credProps'))) return false;
  if (kind === 'create' && (o.rp?.icon !== undefined || o.user?.icon !== undefined)) return false;
  return kind === 'get' || kind === 'create';
};
const validPasskeyOptions = (kind, o) => {
  if (!o || typeof o !== 'object' || typeof o.challenge !== 'string' || !o.challenge.length || o.challenge.length > 1000) return false;
  if (!supportedPasskeyOptions(kind, o)) return false;
  if (kind === 'create') return o.rp && typeof o.rp === 'object' && typeof o.rp.name === 'string' && o.rp.name.length < 1000
    && (o.rp.id === undefined || (typeof o.rp.id === 'string' && o.rp.id.length > 0))
    && o.user && typeof o.user === 'object' && typeof o.user.id === 'string' && o.user.id.length > 0 && typeof o.user.name === 'string'
    && Array.isArray(o.pubKeyCredParams) && o.pubKeyCredParams.every((p) => p && typeof p === 'object' && Number.isInteger(p.alg)
      && (p.type === undefined || p.type === 'public-key')) && o.pubKeyCredParams.some((p) => p.alg === -7)
    && (!o.excludeCredentials || (Array.isArray(o.excludeCredentials) && o.excludeCredentials.every(validDescriptor)));
  return kind === 'get' && (o.rpId === undefined || (typeof o.rpId === 'string' && o.rpId.length > 0))
    && (!o.allowCredentials || (Array.isArray(o.allowCredentials) && o.allowCredentials.every(validDescriptor)));
};

chrome.runtime.onMessage.addListener((m, sender, reply) => {
  const senderOrigin = (() => {
    if (!sender?.tab || !Number.isInteger(sender.tab.id) || typeof sender.origin !== 'string' || typeof sender.url !== 'string') return false;
    try { return new URL(sender.url).origin === sender.origin; } catch { return false; }
  })();
  const job = m?.bwliteReq
    ? requestId(m.bwliteReq) && (m.kind === 'create' || m.kind === 'get') && validPasskeyOptions(m.kind, m.options)
      && senderOrigin
      ? passkey(m, sender).catch(() => ({ bwliteRes: m.bwliteReq, fallback: true }))
      : Promise.resolve({ bwliteRes: m.bwliteReq, fallback: true })
    : m?.bwliteMenu === true && sender.tab && http(sender.url) ? menu(sender)
    : typeof m?.bwliteFillKey === 'string' && m.bwliteFillKey.length < 200 && sender.tab && http(sender.url) ? fillFromMenu(m.bwliteFillKey, sender)
    : m?.bwliteSubmit && sender.tab ? submitted(sender.tab.id, sender.url, m.bwliteSubmit).then(() => null)
    : typeof m?.bwliteSaveOpen === 'string' ? openSave(m.bwliteSaveOpen, sender)
    : m?.bwliteUsed && typeof m.bwliteUsed.a === 'string' && m.bwliteUsed.a.length < 65
      && typeof m.bwliteUsed.id === 'string' && m.bwliteUsed.id.length < 200 ? markUsed(m.bwliteUsed)
    : null;
  if (!job) return;
  job.then(reply, () => reply(null));
  return true;
});

// The menu sees usernames and names only; the password goes out on a click, to the frame whose URL matches.
async function menu(sender) {
  if (!http(sender.url)) return [];
  const v = await vault();
  const multi = v.accounts.length > 1;
  return forSite(v, sender.url).slice(0, 8).map((i) => ({
    k: `${i.a}:${i.id}`, username: i.username, name: multi ? `${i.name} · ${v.accounts.find((a) => a.id === i.a)?.label}` : i.name,
  }));
}

async function fillFromMenu(k, sender) {
  const v = await vault();
  const version = stateVersion;
  const item = v.items.find((i) => `${i.a}:${i.id}` === k);
  if (!item || version !== stateVersion || !http(sender.url) || !bw.matches(item, sender.url, v.equiv.get(item.a))) return null;
  if (!await markUsed(item, version)) return null;
  const beforeCode = await session.get(`${item.a}:key`);
  if (!beforeCode[`${item.a}:key`]) return null;
  const code = item.totp ? (await bw.totp(item.totp).catch(() => null))?.code || null : null;
  const afterCode = await session.get(`${item.a}:key`);
  if (afterCode[`${item.a}:key`] !== beforeCode[`${item.a}:key`]) return null;
  return { username: item.username, password: item.password, code };
}

// --- passkeys: check the request and open a BW Lite window for it; that window (popup.js passkeyView) answers the
// page directly. The origin comes from Chrome (sender.origin), never from the page.

async function passkey({ bwliteReq, kind, options: o }, { origin, tab, documentId }) {
  const fallback = { bwliteRes: bwliteReq, fallback: true };
  let page;
  try { page = new URL(origin); } catch { return fallback; }
  const host = page.hostname.toLowerCase();
  const requested = (kind === 'create' ? o.rp?.id : o.rpId) || host;
  if (typeof requested !== 'string' || !requested || /[\s\/?#@:]/.test(requested)) return fallback;
  let rpId;
  try { rpId = new URL(`https://${requested}`).hostname.toLowerCase().replace(/\.$/, ''); } catch { return fallback; }
  // rpId must be the page's host or a registrable-domain suffix, never a public suffix.
  if (page.origin !== origin || !https(origin) || !(host === rpId || host.endsWith(`.${rpId}`))
    || (bw.isPublicSuffix(rpId) && !(host === 'localhost' && rpId === 'localhost'))) return fallback;
  if (kind === 'create' && !o.pubKeyCredParams?.some((p) => p.alg === -7)) return fallback;
  const version = stateVersion;
  if (!(await mayAnswer(kind, rpId))) return fallback;
  if (version !== stateVersion) return fallback;
  const key = crypto.randomUUID();
  await session.set({ [`pk:${key}`]: { id: bwliteReq, kind, options: o, origin, rpId, tabId: tab.id, documentId } });
  if (version !== stateVersion) return session.remove(`pk:${key}`).then(() => fallback);
  try {
    await chrome.windows.create({ url: `popup.html#pk=${key}`, type: 'popup', width: 410, height: 620 });
  } catch (e) {
    await session.remove(`pk:${key}`);
    throw e;
  }
  return null;
}

// No vaults: leave passkeys to the browser. Sign-in: skip the window when every vault is open and none has a
// passkey for the site (e.g. it wants a security key).
async function mayAnswer(kind, rpId) {
  const v = await vault();
  if (kind === 'create' || !v.accounts.length) return v.accounts.length > 0;
  return v.open < v.accounts.length || v.items.some((i) => i.passkeys?.some((p) => typeof p.rpId === 'string' && p.rpId.toLowerCase() === rpId));
}
