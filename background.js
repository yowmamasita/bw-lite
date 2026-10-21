// Service worker: passkey requests, the toolbar badge, the autofill shortcut, the in-page login menu and the
// "save this login?" offer. It reads the vaults the popup has opened (session storage); writing stays in the popup,
// which the save bar and the passkey window are.
import * as bw from './bw.js';
import { fillTab } from './autofill.js';

const local = chrome.storage.local, session = chrome.storage.session, td = new TextDecoder();
const http = (url) => /^https?:/.test(url || '');

// --- vault state, cached until anything in storage changes -------------------

let state;
async function vault() {
  if (state) return state;
  const { accounts = [], used = {}, neverSave = [] } = await local.get(['accounts', 'used', 'neverSave']);
  const s = await session.get(accounts.map((a) => `${a.id}:list`));
  const items = [];
  let open = 0;
  for (const a of accounts) {
    let list = s[`${a.id}:list`];
    if (!list && a.persistKey) { // Never lock, browser restarted: open the encrypted list as the popup would
      const { [`${a.id}:index4`]: index } = await local.get(`${a.id}:index4`);
      if (index) await session.set({ [`${a.id}:list`]: (list = td.decode(await bw.decrypt(index, bw.unb64(a.persistKey)))), [`${a.id}:key`]: a.persistKey });
    }
    if (list) open++, items.push(...JSON.parse(list));
  }
  const eq = await local.get(accounts.map((a) => `${a.id}:eq`));
  const rank = (id) => accounts.findIndex((a) => a.id === id);
  return (state = { accounts, used, neverSave, items, open, equiv: bw.equivalents(Object.values(eq).flat()), rank });
}
const forSite = (v, url) => bw.forSite(v.items, url, v.equiv, v.rank, v.used);
const markUsed = async (i) => local.set({ used: { ...(await local.get('used')).used, [`${i.a}:${i.id}`]: Date.now() } });

// --- badge: number of logins for the tab's page --------------------------------

async function badge(tabId, url) {
  const n = http(url) ? forSite(await vault(), url).length : 0;
  await chrome.action.setBadgeText({ tabId, text: n ? String(n) : '' }).catch(() => {});
}
let redraw;
chrome.storage.onChanged.addListener(() => {
  state = null;
  clearTimeout(redraw);
  redraw = setTimeout(async () => (await chrome.tabs.query({})).forEach((t) => badge(t.id, t.url)), 300);
});
chrome.action.setBadgeBackgroundColor({ color: '#555' });

// --- autofill shortcut (Ctrl/Cmd+Shift+L): the top login, as the popup's highlighted Fill -------------

chrome.commands.onCommand.addListener(async (command, tab) => {
  if (command !== 'autofill' || !http(tab?.url)) return;
  const v = await vault();
  const [item] = forSite(v, tab.url);
  if (!item) return chrome.action.openPopup().catch(() => {}); // locked or nothing saved: show why
  if (await fillTab(tab.id, item, v.equiv, item.totp && (await bw.totp(item.totp)).code)) await markUsed(item);
});

// --- save offers: remembered per tab when a login is submitted, offered once the page has moved on -----------

const pending = new Map(); // tabId -> { at, username, password, url, offer? }
async function submitted(tabId, url, { username, password }) {
  const prev = pending.get(tabId);
  if (!password) return pending.set(tabId, { at: Date.now(), username, url }); // username step of a two-step login
  username ||= prev?.username || '';
  const v = await vault();
  if (!v.open || v.neverSave.includes(new URL(url).hostname)) return pending.delete(tabId);
  const logins = forSite(v, url);
  const lower = username.toLowerCase();
  const same = username ? logins.filter((i) => i.username.toLowerCase() === lower) : logins.length === 1 ? logins : [];
  if (logins.some((i) => i.password === password && (!username || i.username.toLowerCase() === lower)) || (!username && !same.length && logins.length)) {
    return pending.delete(tabId);
  }
  const offer = same.length ? { kind: 'update', a: same[0].a, id: same[0].id, username: same[0].username } : { kind: 'add', username };
  pending.set(tabId, { at: Date.now(), username, url, offer: { ...offer, password, origin: new URL(url).origin } });
}
chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.url || info.status === 'complete') badge(tabId, tab.url);
  const p = pending.get(tabId);
  // loaded, or a single-page app moved to another URL
  if (!(info.status === 'complete' || (info.url && tab.status === 'complete')) || !p?.offer) return;
  if (Date.now() - p.at > 60e3) return pending.delete(tabId);
  pending.delete(tabId);
  const key = crypto.randomUUID();
  await session.set({ [`save:${key}`]: p.offer });
  chrome.tabs.sendMessage(tabId, { bwliteBar: key }, { frameId: 0 }).catch(() => session.remove(`save:${key}`));
});
chrome.tabs.onRemoved.addListener((tabId) => pending.delete(tabId));

// --- messages from inpage.js / bridge.js -----------------------------------------------

chrome.runtime.onMessage.addListener((m, sender, reply) => {
  const job = m.bwliteReq ? passkey(m, sender).catch(() => ({ bwliteRes: m.bwliteReq, fallback: true }))
    : m.bwliteMenu ? menu(sender)
    : m.bwliteFillKey ? fillFromMenu(m.bwliteFillKey, sender)
    : m.bwliteSubmit && sender.tab ? submitted(sender.tab.id, sender.url, m.bwliteSubmit).then(() => null)
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
  const item = v.items.find((i) => `${i.a}:${i.id}` === k);
  if (!item || !http(sender.url) || !bw.matches(item, sender.url, v.equiv)) return null;
  await markUsed(item);
  return { username: item.username, password: item.password, code: item.totp ? (await bw.totp(item.totp).catch(() => null))?.code : null };
}

// --- passkeys: check the request and open a BW Lite window for it; that window (popup.js passkeyView) answers the
// page directly. The origin comes from Chrome (sender.origin), never from the page.

async function passkey({ bwliteReq, kind, options: o }, { origin, tab, documentId }) {
  const fallback = { bwliteRes: bwliteReq, fallback: true };
  const host = new URL(origin).hostname;
  const rpId = (kind === 'create' ? o.rp?.id : o.rpId) || host;
  // rpId must be the page's host or a parent of it, but not a public suffix
  if (!origin.startsWith('https://') || !(host === rpId || host.endsWith(`.${rpId}`)) || rpId.length < bw.baseDomain(host).length) return fallback;
  if (kind === 'create' && !o.pubKeyCredParams?.some((p) => p.alg === -7)) return fallback;
  if (!(await mayAnswer(kind, rpId))) return fallback;
  const key = crypto.randomUUID();
  await session.set({ [`pk:${key}`]: { id: bwliteReq, kind, options: o, origin, rpId, tabId: tab.id, documentId } });
  await chrome.windows.create({ url: `popup.html#pk=${key}`, type: 'popup', width: 410, height: 620 });
  return null;
}

// No vaults: leave passkeys to the browser. Sign-in: skip the window when every vault is open and none has a
// passkey for the site (e.g. it wants a security key).
async function mayAnswer(kind, rpId) {
  const v = await vault();
  if (kind === 'create' || !v.accounts.length) return v.accounts.length > 0;
  return v.open < v.accounts.length || v.items.some((i) => i.passkeys?.some((p) => p.rpId === rpId));
}
