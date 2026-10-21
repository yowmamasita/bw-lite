import * as bw from './bw.js';
import { fillTab } from './autofill.js';
import { withStateLock, mutateAccounts } from './coord.js';

const app = document.getElementById('app');
const local = chrome.storage.local, session = chrome.storage.session; // session = memory only, gone when the browser quits
const td = new TextDecoder();
const collator = new Intl.Collator();

// accounts: ordered list (the order is the autofill priority) of
//   { id, server, email, label, kdf, protectedKey, tokens, lastSync, persistKey? }
// Per account in local storage: `${id}:index4` (encrypted list; entries carry passkeys, match types, note flag), `${id}:ids`,
// `${id}:profile`, `${id}:eq` (equivalent domain groups), `${id}:c:${cipherId}` (raw).
// Per account in session storage: `${id}:key` and `${id}:list` (decrypted list, so an open is a read + JSON.parse).
let st, accounts = [], keys = Object.create(null), lists = Object.create(null), vault = [], equiv = new Map(), tab, host, pageUrl, query = '', wide = false;
// Opened by background.js for a page: #pk=<key> a passkey request or #save=<key>
// an extension-owned save confirmation window. pk / sv are hand-offs from session storage.
const [mode, modeKey] = location.hash.slice(1).split('=');
let pk, sv;
let saveCancelled = false;
let saveTimer;

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (v != null && v !== false) el[k] = v;
  }
  el.append(...kids.flat().filter((k) => k != null && k !== false && k !== ''));
  return el;
}
const field = (label, el) => h('label', {}, label, el);
const title = (text) => h('h1', {}, text, themeButton());
const newId = () => crypto.randomUUID().slice(0, 8);
const strip = ({ raw, key, notes, ...listFields }) => (notes ? { ...listFields, note: true } : listFields);
const validList = (items) => Array.isArray(items) && items.every((i) => i && typeof i.id === 'string' && Array.isArray(i.uris)
  && i.uris.every((u) => typeof u === 'string') && (!i.passkeys || Array.isArray(i.passkeys)));
const keyBytes = (encoded) => {
  try {
    const key = typeof encoded === 'string' ? bw.unb64(encoded) : null;
    return key?.length === 64 ? key : null;
  } catch { return null; }
};
const validAccount = (a) => {
  if (!a || !/^[\w-]{1,64}$/.test(a.id) || typeof a.server !== 'string' || typeof a.email !== 'string') return false;
  try { return /^https?:$/i.test(new URL(a.server).protocol); } catch { return false; }
};
const normalizedAccounts = (list) => {
  const seen = new Set();
  return (Array.isArray(list) ? list : []).filter((a) => validAccount(a) && !seen.has(a.id) && seen.add(a.id));
};
// Keep object identity for buttons/forms while adopting a current storage snapshot.
const adoptAccounts = (next) => {
  const old = new Map(accounts.map((a) => [a.id, a]));
  accounts = normalizedAccounts(next).map((raw) => {
    const a = old.get(raw.id);
    if (!a) return raw;
    // A storage snapshot is authoritative. Remove fields omitted by it so a
    // stale persisted key cannot survive a lock or removal in another window.
    for (const key of Object.keys(a)) if (!Object.prototype.hasOwnProperty.call(raw, key)) delete a[key];
    return Object.assign(a, raw);
  });
  if (st) st.accounts = accounts;
  return accounts;
};
const acct = (id) => accounts.find((a) => a.id === id);
const unlocked = () => accounts.filter((a) => keys[a.id]);
const locked = () => accounts.filter((a) => !keys[a.id]);
const rank = (id) => accounts.findIndex((a) => a.id === id);

// Account changes are patches against the latest storage value. No popup writes
// its old complete array back after another popup has changed it.
const updateAccounts = (mutate) => mutateAccounts(local, async (current) => normalizedAccounts(await mutate(normalizedAccounts(current))))
  .then((next) => adoptAccounts(next));
const patchAccountsUnlocked = async (id, patch) => {
  const current = normalizedAccounts((await local.get('accounts')).accounts);
  const next = current.map((a) => a.id === id ? { ...a, ...patch } : a);
  await local.set({ accounts: next });
  adoptAccounts(next);
  return acct(id);
};
const update = (a, patch) => updateAccounts((list) => list.map((x) => x.id === a.id ? { ...x, ...patch } : x));
const sess = (a, locked = false) => ({
  server: a.server,
  tokens: a.tokens,
  onTokens: (tokens) => locked ? patchAccountsUnlocked(a.id, { tokens }) : update(a, { tokens }),
});
const accountTask = (a, fn) => withStateLock(async () => {
  const latest = normalizedAccounts((await local.get('accounts')).accounts);
  if (!latest.some((x) => x.id === a.id)) return;
  adoptAccounts(latest);
  const current = acct(a.id);
  const cached = await session.get(`${a.id}:key`);
  if (!keys[a.id] || bw.b64(keys[a.id]) !== cached[`${a.id}:key`]) return;
  return fn(current);
});
// One color per vault, by its place in the vault order.
const COLORS = ['#4f9dff', '#f0a03c', '#3fbf7f', '#c678dd', '#e5605a'];
const vaultTag = (id) => h('span', { className: 'vault', title: 'Vault' }, h('i', { style: `background: ${COLORS[rank(id) % COLORS.length]}` }), h('span', {}, acct(id)?.label));
// used: { 'account:cipher': time of last fill or passkey sign-in }, kept on this computer only, like Bitwarden's last used.
const markUsed = (i) => {
  if (mode === 'pk' && !pk) return Promise.resolve();
  st.used = { ...(st.used && typeof st.used === 'object' ? st.used : {}), [`${i.a}:${i.id}`]: Date.now() };
  return chrome.runtime.sendMessage({ bwliteUsed: { a: i.a, id: i.id } }).catch(() => {});
};
const byName = (a, b) => collator.compare(a.name, b.name) || collator.compare(a.username, b.username);

// Night (default) / day toggle; the choice is a per-browser convenience, so localStorage is enough.
function themeButton() {
  const root = document.documentElement;
  const label = () => (root.dataset.theme === 'light' ? 'night' : 'day');
  const b = h('button', {
    type: 'button', className: 'link', title: 'Toggle day/night',
    onclick: () => {
      if (root.dataset.theme === 'light') delete root.dataset.theme;
      else root.dataset.theme = 'light';
      try { localStorage.theme = root.dataset.theme || 'dark'; } catch {}
      b.textContent = label();
    },
  }, label());
  return b;
}

// Disables the button while fn runs and shows any error under the form.
async function run(btn, err, fn) {
  btn.disabled = true;
  err.textContent = '';
  try {
    await fn();
  } catch (e) {
    err.textContent = e?.message || String(e);
  } finally {
    btn.disabled = false;
  }
}

async function start() {
  let s;
  [st, s, [tab]] = await Promise.all([
    local.get(['accounts', 'used', 'deviceId', 'neverLock', 'server', 'email', 'kdf', 'protectedKey', 'tokens', 'persistKey']),
    session.get(null), chrome.tabs.query({ active: true, currentWindow: true })]);
  if (mode === 'pk') {
    if (!(pk = s[`pk:${modeKey}`])) return window.close();
    if (!['create', 'get'].includes(pk.kind) || typeof pk.id !== 'string' || !Number.isInteger(pk.tabId)
      || typeof pk.origin !== 'string' || !pk.options || typeof pk.options !== 'object') {
      session.remove(`pk:${modeKey}`);
      return window.close();
    }
    tab = { id: pk.tabId, url: pk.origin };
    addEventListener('pagehide', () => answer(CANCEL)); // closing the window cancels
  }
  if (mode === 'save') {
    if (!(sv = s[`save:${modeKey}`])) return closeSave();
    saveCancelled = false;
    let offer;
    try { offer = new URL(sv.origin); } catch { return closeSave(); }
    if (!['add', 'update'].includes(sv.kind) || !/^https?:$/i.test(offer.protocol) || offer.origin !== sv.origin
      || !Number.isFinite(sv.expires) || sv.expires <= Date.now() || typeof sv.password !== 'string'
      || (sv.kind === 'update' && (!/^[\w-]{1,64}$/.test(sv.a) || typeof sv.id !== 'string'))) return closeSave();
    // The background authenticated the originating tab and origin before it
    // opened this extension window. Do not rely on whichever tab happens to
    // be active now, and never allow a web page to frame this view.
    if (!Number.isInteger(sv.tabId) || window !== top) return closeSave();
    tab = { id: sv.tabId, url: sv.origin };
  } else if (window !== top) return; // a web page framing the full popup gets nothing
  pageUrl = /^https?:\/\//i.test(tab?.url) ? tab.url : null;
  host = pageUrl && new URL(pageUrl).hostname;
  if (!st.accounts && st.protectedKey) s = await migrate();
  const rawAccounts = st.accounts;
  accounts = normalizedAccounts(rawAccounts);
  // Persisted keys are restored under the same state lock as lock/removal.
  // Re-read each account before publishing a key so a suspended decrypt cannot
  // resurrect an account that another popup just removed.
  await withStateLock(async () => {
    const latest = normalizedAccounts((await local.get('accounts')).accounts);
    adoptAccounts(latest);
    const currentSession = await session.get(null);
    for (const a of accounts) {
      const sessionKey = keyBytes(currentSession[`${a.id}:key`]);
      const persisted = keyBytes(a.persistKey);
      const key = sessionKey || persisted;
      if (!key) continue;
      keys[a.id] = key;
      if (!sessionKey) await session.set({ [`${a.id}:key`]: bw.b64(key) });
    }
    if (!Array.isArray(rawAccounts) || accounts.length !== rawAccounts.length) {
      const clean = normalizedAccounts(accounts);
      await local.set({ accounts: clean });
      adoptAccounts(clean);
    }
  });
  // The save offer is a tiny extension-owned window. It must never fall
  // through to the full login/unlock/vault views when its account closed.
  if (mode === 'save' && (!accounts.length || !unlocked().length)) return closeSave();
  if (!accounts.length) return loginView();
  if (!unlocked().length) return unlockView();
  const problems = await loadVaults(s);
  await loadEquiv();
  vaultView();
  if (problems) status(problems);
}

// 0.1/0.2 stored one account in flat keys. Move it into the accounts list; its cached vault is re-synced.
async function migrate() {
  return withStateLock(async () => {
    const latest = await local.get(['accounts', 'server', 'email', 'kdf', 'protectedKey', 'tokens', 'persistKey', 'deviceId', 'neverLock']);
    if (Array.isArray(latest.accounts)) return session.get(null);
    const a = { id: newId(), server: latest.server, email: latest.email, label: latest.email, kdf: latest.kdf,
      protectedKey: latest.protectedKey, tokens: latest.tokens };
    if (latest.neverLock && latest.persistKey) a.persistKey = latest.persistKey;
    st = { deviceId: latest.deviceId, neverLock: latest.neverLock, accounts: [a] };
    await local.clear();
    await local.set(st);
    await session.clear();
    return {};
  });
}

// "Never lock" (like Bitwarden's Never timeout) also keeps the key in local storage so it survives a browser restart.
async function setKey(a, key) {
  await withStateLock(async () => {
    const latest = normalizedAccounts((await local.get('accounts')).accounts);
    if (!latest.some((x) => x.id === a.id)) return;
    adoptAccounts(latest);
    const current = acct(a.id);
    const k = bw.b64(key);
    const { neverLock } = await local.get('neverLock');
    const next = latest.map((x) => {
      if (x.id !== a.id) return x;
      const copy = { ...x };
      if (neverLock) copy.persistKey = k;
      else delete copy.persistKey;
      return copy;
    });
    keys[a.id] = key;
    await local.set({ accounts: next });
    adoptAccounts(next);
    await session.set({ [`${current.id}:key`]: k });
  });
}

async function setList(a, items, persist = true) {
  if (acct(a.id) !== a || !keys[a.id]) return;
  if (!validList(items)) throw new Error('Vault cache is invalid');
  lists[a.id] = items;
  const list = JSON.stringify(items);
  await Promise.all([
    session.set({ [`${a.id}:list`]: list }),
    persist && local.set({ [`${a.id}:index4`]: await bw.encrypt(list, keys[a.id]) }),
  ]);
}

function merge() {
  const parts = unlocked().map((a) => Array.isArray(lists[a.id]) ? lists[a.id] : []);
  vault = parts.length === 1 ? parts[0] : parts.flat().sort(byName);
}

// Loads every unlocked account that isn't loaded yet; one failing account doesn't block the others.
async function loadVaults(s = {}) {
  const todo = unlocked().filter((a) => !lists[a.id]);
  const res = await Promise.allSettled(todo.map((a) => accountTask(a, () => loadAccount(a, s))));
  merge();
  return failures(todo, res);
}

async function loadAccount(a, s) {
  if (acct(a.id) !== a || !keys[a.id]) return;
  const cachedKey = s[`${a.id}:key`];
  if (s[`${a.id}:list`] && keyBytes(cachedKey) && bw.b64(keys[a.id]) === cachedKey) {
    try {
      const cached = JSON.parse(s[`${a.id}:list`]);
      if (validList(cached)) return (lists[a.id] = cached);
    } catch {}
    await session.remove(`${a.id}:list`);
  } else if (s[`${a.id}:list`]) {
    await session.remove([`${a.id}:list`, `${a.id}:key`]);
  }
  const { [`${a.id}:index4`]: index } = await local.get(`${a.id}:index4`);
  if (!index) {
    await local.remove([`${a.id}:index`, `${a.id}:index2`, `${a.id}:index3`]);
    return syncAccountNow(a);
  }
  try {
    const cached = JSON.parse(td.decode(await bw.decrypt(index, keys[a.id])));
    if (!validList(cached)) throw new Error('cached list is invalid');
    await setList(a, cached, false);
  } catch {
    await local.remove([`${a.id}:index`, `${a.id}:index2`, `${a.id}:index3`, `${a.id}:index4`]);
    return syncAccountNow(a);
  }
}

const loadEquiv = async () => {
  const stored = await local.get(accounts.map((a) => `${a.id}:eq`));
  equiv = new Map(accounts.map((a) => [a.id, bw.equivalents(stored[`${a.id}:eq`])]));
  return equiv;
};

const failures = (todo, res) =>
  res.map((r, i) => r.status === 'rejected' && `${todo[i].label}: ${r.reason?.message || String(r.reason)}`).filter(Boolean).join('\n');

// Manual (Sync button / Ctrl+S), except for an account with no local data yet. Unchanged items aren't decrypted again.
const syncAccount = (a) => accountTask(a, () => syncAccountNow(a));
async function syncAccountNow(a) {
  const p = `${a.id}:`;
  if (acct(a.id) !== a || !keys[a.id]) return;
  const sync = await bw.api(sess(a, true), '/sync');
  if (acct(a.id) !== a || !keys[a.id]) return;
  const prev = new Map((Array.isArray(lists[a.id]) ? lists[a.id] : []).map((i) => [i.id, i]));
  const items = (await bw.decryptVault(sync, keys[a.id], prev)).map((i) => ({ ...strip(i), a: a.id }));
  if (acct(a.id) !== a || !keys[a.id]) return;
  const ids = sync.ciphers.map((c) => c.id), keep = new Set(ids);
  const stored = await local.get(`${p}ids`);
  const old = Array.isArray(stored[`${p}ids`]) ? stored[`${p}ids`] : [];
  // raw ciphers stored one key per item so editing reads just the one it needs
  await local.remove(old.filter((id) => !keep.has(id)).map((id) => `${p}c:${id}`));
  const d = sync.domains || {};
  const eq = [...(d.equivalentDomains || []), ...(d.globalEquivalentDomains || []).filter((g) => !g.excluded).map((g) => g.domains)];
  await local.set({ [`${p}profile`]: sync.profile, [`${p}ids`]: ids, [`${p}eq`]: eq, ...Object.fromEntries(sync.ciphers.map((c) => [`${p}c:${c.id}`, c])) });
  await setList(a, items);
  await patchAccountsUnlocked(a.id, { lastSync: Date.now() });
  await loadEquiv();
}

async function syncAll() {
  const todo = unlocked();
  const res = await Promise.allSettled(todo.map(syncAccount));
  merge();
  vaultView();
  const problems = failures(todo, res);
  if (problems) throw new Error(problems);
}

function loginView() {
  if (mode === 'save') return closeSave();
  const server = h('input', { value: accounts.at(-1)?.server || 'https://vault.bitwarden.com', required: true });
  const email = h('input', { type: 'email', required: true });
  const pw = h('input', { type: 'password', required: true });
  const label = h('input', { placeholder: 'Defaults to the email' });
  const code = h('input', { autocomplete: 'one-time-code' });
  const codeField = h('label', { hidden: true }, h('span'), code);
  const btn = h('button', { className: 'primary' }, 'Log in');
  const err = h('p', { className: 'err' });
  let need;
  const form = h('form', {
    onsubmit: (e) => {
      e.preventDefault();
      run(btn, err, async () => {
        const srv = server.value.trim().replace(/\/+$/, ''), mail = email.value.trim();
        if (accounts.some((a) => a.server === srv && a.email.toLowerCase() === mail.toLowerCase())) throw new Error('This vault is already added');
        if (!st.deviceId) await local.set({ deviceId: (st.deviceId = crypto.randomUUID()) }); // one id per install avoids new-device emails
        try {
          const r = await bw.login(srv, mail, pw.value, st.deviceId, need && { kind: need, value: code.value.trim() });
          const a = { id: newId(), server: srv, email: mail, label: label.value.trim() || mail, kdf: r.kdf, protectedKey: r.protectedKey, tokens: r.tokens };
          await updateAccounts((list) => [...list, a]);
          await setKey(a, r.userKey);
          await syncAccount(a);
          merge();
          vaultView();
        } catch (e) {
          if (!e.need) throw e;
          need = e.need;
          codeField.hidden = false;
          codeField.firstChild.textContent = e.message;
          code.focus();
        }
      });
    },
  },
    field('Server', server), field('Email', email), field('Master password', pw), field('Label', label), codeField,
    h('div', { className: 'inline' }, btn, accounts.length && h('button', { type: 'button', onclick: accountsView }, 'Cancel')), err);
  app.replaceChildren(title(accounts.length ? 'Add vault' : 'BW Lite'), form);
  email.focus();
}

// One password box for every locked vault: each vault it opens unlocks, the rest stay locked.
function unlockView() {
  if (mode === 'save') return closeSave();
  const todo = locked();
  const pw = h('input', { type: 'password', required: true });
  const btn = h('button', { className: 'primary' }, 'Unlock');
  const err = h('p', { className: 'err' });
  const form = h('form', {
    onsubmit: (e) => {
      e.preventDefault();
      run(btn, err, async () => {
        const opened = await Promise.all(todo.map((a) =>
          bw.unlock(pw.value, a.email, a.kdf, a.protectedKey).then((k) => setKey(a, k).then(() => true), () => false)));
        if (!opened.includes(true)) throw new Error('Wrong master password');
        const problems = await loadVaults();
        vaultView();
        if (problems) status(problems);
      });
    },
  },
    field(`Master password${todo.length > 1 ? ' (tried on every locked vault)' : ''}`, pw),
    h('p', { className: 'muted' }, `Locked: ${todo.map((a) => a.label).join(', ')}`),
    h('div', { className: 'inline' }, btn, unlocked().length && h('button', { type: 'button', onclick: vaultView }, 'Skip')), err);
  app.replaceChildren(title('BW Lite'), form, h('button', { className: 'link', onclick: accountsView }, 'Vaults'));
  pw.focus();
}

function accountsView() {
  if (mode === 'save') return closeSave();
  const rows = accounts.map((a, i) => {
    const label = h('input', { value: a.label, title: 'Label shown on this vault\'s items', onchange: () => update(a, { label: label.value.trim() || a.email }) });
    const remove = h('button', {
      title: 'Log out and remove this vault from BW Lite',
      onclick: () => (remove.textContent === 'Sure?' ? removeAccount(a) : (remove.textContent = 'Sure?')),
    }, 'Remove');
    return h('div', { className: 'row' },
      h('div', { className: 'info' }, label, h('small', {}, accounts.length > 1 && vaultTag(a.id), `${a.email} · ${new URL(a.server).host}${keys[a.id] ? '' : ' · locked'}`)),
      h('div', { className: 'actions' },
        h('button', { title: 'Higher autofill priority', disabled: i === 0, onclick: () => move(i, -1) }, '↑'),
        h('button', { title: 'Lower autofill priority', disabled: i === accounts.length - 1, onclick: () => move(i, 1) }, '↓'),
        remove));
  });
  app.replaceChildren(title('Vaults'),
    h('p', { className: 'muted' }, 'Order is the autofill priority: the first vault with a login for the site fills, unless you last used another one there.'),
    h('div', { className: 'list' }, rows),
    h('div', { className: 'inline' },
      h('button', { className: 'primary', onclick: loginView }, 'Add vault'),
      h('button', { onclick: () => (unlocked().length ? vaultView() : unlockView()) }, 'Done')));
}

async function move(i, d) {
  const id = accounts[i]?.id;
  if (!id) return;
  await updateAccounts((list) => {
    const from = list.findIndex((a) => a.id === id), target = from + d;
    if (from < 0 || target < 0 || target >= list.length) return list;
    const next = [...list];
    [next[from], next[target]] = [next[target], next[from]];
    return next;
  });
  accountsView();
}

async function removeAccount(a) {
  const p = `${a.id}:`;
  await withStateLock(async () => {
    // Publish the removal before deleting session data so another popup cannot
    // reopen this account from its persisted key during the cleanup window.
    const latest = normalizedAccounts((await local.get('accounts')).accounts);
    if (!latest.some((x) => x.id === a.id)) return;
    const next = latest.filter((x) => x.id !== a.id);
    await local.set({ accounts: next });
    adoptAccounts(next);
    delete keys[a.id];
    delete lists[a.id];
    const stored = await local.get(`${p}ids`);
    const ids = Array.isArray(stored[`${p}ids`]) ? stored[`${p}ids`] : [];
    try {
      await local.remove([`${p}index`, `${p}index2`, `${p}index3`, `${p}index4`, `${p}eq`, `${p}ids`, `${p}profile`, ...ids.map((id) => `${p}c:${id}`)]);
    } finally {
      await session.remove([`${p}key`, `${p}list`]);
    }
    const { used = {} } = await local.get('used');
    await local.set({ used: Object.fromEntries(Object.entries(used || {}).filter(([k]) => !k.startsWith(`${a.id}:`))) });
  });
  merge();
  if (accounts.length) accountsView();
  else loginView();
}

async function lockAll() {
  await withStateLock(async () => {
    const stored = await local.get('accounts');
    const latest = normalizedAccounts(stored.accounts);
    // A single global lock avoids deadlocks between two windows locking the
    // same accounts in different orders.
    adoptAccounts(latest);
    keys = Object.create(null);
    lists = Object.create(null);
    vault = [];
    const next = latest.map((a) => { const copy = { ...a }; delete copy.persistKey; return copy; });
    await local.set({ accounts: next }); // first, so background cannot reopen a persisted key in between
    adoptAccounts(next);
    await session.clear();
  });
  unlockView();
}

async function fullItem(a, raw) {
  if (!a || !keys[a.id] || !raw || typeof raw !== 'object') throw new Error('Login is no longer available; sync and try again');
  const { [`${a.id}:profile`]: profile } = await local.get(`${a.id}:profile`);
  if (!profile || typeof profile !== 'object' || typeof profile.privateKey !== 'string') throw new Error('Login profile is missing; sync and try again');
  const [item] = await bw.decryptVault({ profile, ciphers: [raw] }, keys[a.id]);
  if (!item) throw new Error('Could not decrypt this login; sync and try again');
  return { ...item, a: a.id };
}

async function latestList(a) {
  const s = await session.get([`${a.id}:key`, `${a.id}:list`]);
  if (s[`${a.id}:key`] === bw.b64(keys[a.id]) && typeof s[`${a.id}:list`] === 'string') {
    try {
      const cached = JSON.parse(s[`${a.id}:list`]);
      if (validList(cached)) return cached;
    } catch {}
  }
  return Array.isArray(lists[a.id]) ? lists[a.id] : [];
}

// The list only holds what it shows; editing needs the raw cipher and its key.
async function loadItem(i) {
  const k = `${i.a}:c:${i.id}`;
  return fullItem(acct(i.a), (await local.get(k))[k]);
}
const openEdit = async (i) => editView(await loadItem(i));

// Applies a saved cipher from the server's reply locally, no full sync needed.
async function storeCipher(a, raw) {
  if (acct(a.id) !== a || !keys[a.id] || !raw?.id) return;
  const p = `${a.id}:`;
  const stored = await local.get(`${p}ids`);
  const ids = Array.isArray(stored[`${p}ids`]) ? stored[`${p}ids`] : [];
  await local.set({ [`${p}c:${raw.id}`]: raw, [`${p}ids`]: ids.includes(raw.id) ? ids : [...ids, raw.id] });
  const base = await latestList(a);
  await setList(a, [...base.filter((i) => i.id !== raw.id), strip(await fullItem(a, raw))].sort(byName));
  merge();
}

async function deleteItem(item) {
  const a = acct(item.a);
  if (!a) return;
  await accountTask(a, async () => {
    if (acct(a.id) !== a || !keys[a.id]) return;
    const p = `${a.id}:`;
    await bw.deleteCipher(sess(a, true), item.id);
    if (acct(a.id) !== a || !keys[a.id]) return;
    const stored = await local.get(`${p}ids`);
    const ids = Array.isArray(stored[`${p}ids`]) ? stored[`${p}ids`] : [];
    await local.remove(`${p}c:${item.id}`);
    await local.set({ [`${p}ids`]: ids.filter((id) => id !== item.id) });
    await setList(a, (await latestList(a)).filter((i) => i.id !== item.id));
    merge();
    vaultView();
  });
}

async function saveItem(a, item, value, authorize = async () => true) {
  let saved = false;
  await accountTask(a, async () => {
    if (acct(a.id) !== a || !keys[a.id]) return;
    if (item && (!item.raw || item.raw.edit === false)) throw new Error(item?.raw?.edit === false ? 'This login is read-only' : 'Login is no longer available; sync and try again');
    // Keep the revision captured when the edit form opened. Reloading a newer
    // raw cipher here would turn a concurrent edit into an overwrite instead
    // of letting the server's lastKnownRevisionDate reject it.
    if (!await authorize()) return;
    let raw;
    try {
      raw = await bw.saveCipher(sess(a, true), keys[a.id], item, value);
    } catch (e) {
      if (/\(409\)/.test(e?.message || '')) throw new Error('Login changed elsewhere; sync and try again');
      throw e;
    }
    if (!await authorize()) return;
    const sessionKey = await session.get(`${a.id}:key`);
    if (acct(a.id) === a && keys[a.id] && sessionKey[`${a.id}:key`] === bw.b64(keys[a.id])) {
      await storeCipher(a, raw);
      saved = true;
    }
  });
  return saved;
}

function status(msg) {
  const el = document.getElementById('status');
  if (el) el.textContent = msg;
}

async function copy(btn, text) {
  await navigator.clipboard.writeText(text);
  const old = btn.textContent;
  btn.textContent = 'Copied';
  setTimeout(() => (btn.textContent = old), 1000);
}

async function fill(item) {
  const key = keys[item.a];
  if (!key) return status('Vault locked; unlock it before filling');
  let code = null;
  if (item.totp) code = (await bw.totp(item.totp).catch(() => null))?.code;
  const guard = async () => {
    const current = await session.get(`${item.a}:key`);
    return keys[item.a] === key && current[`${item.a}:key`] === bw.b64(key);
  };
  const ok = await fillTab(tab.id, item, equiv.get(item.a), code, guard, tab.documentId).catch((e) => status(e.message));
  if (!ok) return ok === false && status('No login form for this login on the page');
  if (!await guard()) return status('Vault locked before filling finished');
  if (code) await navigator.clipboard.writeText(code);
  await markUsed(item);
  window.close();
}

function totpButton(item) {
  const b = h('button', { className: 'quiet totp', title: 'Copy TOTP code', onclick: async () => copy(b, (await bw.totp(item.totp)).code) });
  const tick = () => bw.totp(item.totp).then((t) => (b.textContent = `${t.code} · ${t.remaining}s`), () => (b.textContent = 'bad TOTP'));
  tick();
  b._tick = tick;
  return b;
}
setInterval(() => document.querySelectorAll('.totp').forEach((b) => b.textContent !== 'Copied' && b._tick?.()), 1000);

// Layout: top bar (brand + text actions), full-width search, a line saying what the list shows, then logins grouped
// under their name with the username leading each row. Fill is the only boxed button; the autofill pick is solid.
function vaultView() {
  if (mode === 'save' && !sv) return closeSave();
  if (pk) return passkeyView();
  if (sv) return saveView();
  const multi = accounts.length > 1;
  let top, here = []; // top: the login autofill uses (first of the site's logins); Enter fills it
  const q = h('input', {
    type: 'search', placeholder: 'Search all logins', value: query,
    oninput: () => ((query = q.value), draw()),
    onkeydown: (e) => e.key === 'Enter' && top && fill(top),
  });
  const context = h('p', { className: 'context' });
  const list = h('div', { className: 'list' });
  const quiet = (text, title, onclick) => h('button', { className: 'quiet', title, onclick }, text);
  const row = (i) => h('div', { className: 'row' },
    h('div', { className: 'info' },
      h('b', { title: i.username }, i.username || '(no username)'),
      (i.totp || i.passkeys || i.note) && h('small', {}, i.totp && totpButton(i), i.passkeys && h('span', {}, 'passkey'),
        i.note && h('button', { className: 'quiet tag', title: 'Has a note: open it', onclick: () => openEdit(i).catch((e) => status(e.message)) }, 'note'))),
    h('div', { className: 'actions' },
      here.includes(i) && h('button', { className: i === top ? 'primary' : '', title: i === top ? 'Fill (Enter)' : 'Fill', onclick: () => fill(i) }, 'Fill'),
      i.username && quiet('user', 'Copy username', (e) => copy(e.target, i.username)),
      i.password && quiet('pass', 'Copy password', (e) => copy(e.target, i.password)),
      quiet('edit', 'Edit', () => openEdit(i).catch((e) => status(e.message)))));
  const draw = () => {
    const s = q.value.trim().toLowerCase();
    here = pageUrl ? bw.forSite(vault, pageUrl, (i) => equiv.get(i.a), rank, st.used) : [];
    const scoped = here.length > 0 && !wide; // a site with logins: search those first, the whole vault on request
    q.placeholder = scoped ? `Search logins for ${host}` : 'Search all logins';
    const items = s
      ? (scoped ? here : vault).filter((i) => `${i.name} ${i.username} ${i.uris.join(' ')}`.toLowerCase().includes(s))
      : host ? here : vault;
    top = here.includes(items[0]) ? items[0] : null;
    const shown = items.slice(0, 50);
    const n = `${items.length} login${items.length === 1 ? '' : 's'}`;
    context.replaceChildren(s ? `${items.length ? n : 'No logins'}${scoped ? ` for ${host}` : ''} matching “${q.value.trim()}”${items.length > 50 ? ', first 50 shown' : ''}`
      : host ? (items.length ? `${n} for ${host}` : `No logins for ${host}. Type to search.`)
      : `${n}${items.length > 50 ? ', first 50 shown' : ''}`,
    s && scoped ? quiet('search whole vault', 'Search all logins, not just this site\'s', () => ((wide = true), draw(), q.focus())) : '');
    const mixed = new Set(shown.map((i) => i.a)).size > 1; // vault names only when they tell rows apart
    const out = [];
    let group;
    for (const i of shown) {
      const g = mixed ? `${i.name}\n${i.a}` : i.name; // same name in two vaults: two groups
      if (g !== group) out.push(h('div', { className: 'group' }, h('span', {}, i.name || '(no name)'), mixed && vaultTag(i.a)));
      group = g;
      out.push(row(i));
    }
    list.replaceChildren(...out);
  };
  const last = Math.min(...unlocked().map((a) => a.lastSync || 0));
  const ago = last ? Math.round((Date.now() - last) / 60e3) : null;
  const syncBtn = h('button', {
    id: 'sync', className: 'quiet', title: `Sync now (Ctrl+S)${ago == null ? '' : ` · last synced ${ago < 1 ? 'just now' : ago < 120 ? `${ago} min ago` : `${Math.round(ago / 60)} h ago`}`}`,
    onclick: () => ((syncBtn.textContent = 'syncing…'), run(syncBtn, document.getElementById('status'), syncAll).finally(() => (syncBtn.textContent = 'sync'))),
  }, 'sync');
  const neverLock = h('input', {
    type: 'checkbox', checked: !!st.neverLock,
    onchange: async () => {
      await withStateLock(async () => {
        const latest = normalizedAccounts((await local.get('accounts')).accounts);
        const next = latest.map((a) => {
          const copy = { ...a }, key = keys[a.id];
          if (neverLock.checked && key) copy.persistKey = bw.b64(key);
          else delete copy.persistKey;
          return copy;
        });
        await local.set({ neverLock: (st.neverLock = neverLock.checked), accounts: next });
        adoptAccounts(next);
      });
    },
  });
  const stillLocked = locked().length;
  const theme = themeButton();
  theme.className = 'quiet';
  app.replaceChildren(
    h('div', { className: 'bar' }, h('span', { className: 'brand' }, 'BW Lite'),
      h('nav', {}, quiet('new', 'Add login', () => editView(null)), syncBtn, quiet('lock', 'Lock all vaults', lockAll), theme)),
    h('header', {}, q), context, list, h('p', { id: 'status', className: 'err' }),
    h('footer', {},
      h('label', { className: 'check', title: 'Keeps the vault keys on this computer so the vaults stay open after a browser restart. Anyone with access to this browser profile can then open them.' }, neverLock, 'Never lock'),
      h('span', {},
        stillLocked > 0 && h('button', { className: 'link', onclick: unlockView }, `${stillLocked} locked`),
        h('button', { className: 'link', onclick: accountsView }, multi ? `Vaults (${accounts.length})` : 'Vaults'))));
  draw();
  q.focus();
}

const genPassword = () => {
  const cs = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_';
  return Array.from(crypto.getRandomValues(new Uint32Array(20)), (n) => cs[n % cs.length]).join('');
};

function editView(item) {
  if (mode === 'save') return closeSave();
  const name = h('input', { value: item ? item.name : host || '', required: true });
  const user = h('input', { value: item?.username || '' });
  const pass = h('input', { type: 'password', value: item?.password || '' });
  const totp = h('input', { value: item?.totp || '', placeholder: 'Secret or otpauth:// URI' });
  const uris = h('textarea', { rows: 2, value: (item ? item.uris : host ? [new URL(tab.url).origin] : []).join('\n'), placeholder: 'One URL per line' });
  const notes = h('textarea', { rows: 3, value: item?.notes || '' });
  const target = !item && unlocked().length > 1 && h('select', {}, unlocked().map((a) => h('option', { value: a.id }, a.label)));
  const readOnly = item?.raw.edit === false;
  const btn = h('button', { className: 'primary', disabled: readOnly }, readOnly ? 'Read-only' : 'Save');
  const err = h('p', { className: 'err' });
  // second click confirms; the item goes to the server's trash
  const del = h('button', {
    type: 'button', className: 'danger', title: 'Move to the trash (restore it from the Bitwarden web vault)',
    onclick: () => (del.textContent === 'Sure?' ? run(del, err, () => deleteItem(item)) : (del.textContent = 'Sure?')),
  }, 'Delete');
  const form = h('form', {
    onsubmit: (e) => {
      e.preventDefault();
      if (readOnly) return;
      run(btn, err, async () => {
        if (totp.value.trim()) await bw.totp(totp.value.trim()); // reject a bad secret before saving it
        const a = acct(item?.a || (target ? target.value : unlocked()[0].id));
        if (!await saveItem(a, item, {
          name: name.value.trim(), username: user.value, password: pass.value, totp: totp.value.trim(), notes: notes.value,
          uris: uris.value.split('\n').map((u) => u.trim()).filter(Boolean),
        })) throw new Error('Vault locked or removed before the save finished');
        vaultView();
      });
    },
  },
    target && field('Vault', target),
    field('Name', name), field('Username', user),
    field('Password', h('div', { className: 'inline' }, pass,
      h('button', { type: 'button', onclick: () => (pass.type = pass.type === 'password' ? 'text' : 'password') }, 'Show'),
      h('button', { type: 'button', onclick: () => ((pass.value = genPassword()), (pass.type = 'text')) }, 'Gen'))),
    field('TOTP', totp), field('URLs', uris), field('Notes', notes),
    h('div', { className: 'inline' }, btn, h('button', { type: 'button', onclick: vaultView }, 'Cancel'), item && !readOnly && del), err);
  app.replaceChildren(title(item ? 'Edit login' : 'Add login'), item && accounts.length > 1 && h('p', { className: 'muted' }, vaultTag(item.a)), form);
  name.focus();
}

const CANCEL = { error: { name: 'NotAllowedError', message: 'Cancelled' } };

function closeSave() {
  const active = !!sv;
  saveCancelled = true;
  sv = null;
  if (saveTimer) clearTimeout(saveTimer), saveTimer = null;
  app.replaceChildren();
  if (active) {
    session.remove(`save:${modeKey}`);
    window.close();
  } else if (mode === 'save') window.close();
}

// A lock/removal in another popup revokes this window's in-memory keys and any hand-off UI.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'session') return;
  const has = (key) => Object.prototype.hasOwnProperty.call(changes, key);
  if (mode === 'save' && has(`save:${modeKey}`) && changes[`save:${modeKey}`].newValue === undefined) return closeSave();
  if (mode === 'pk' && has(`pk:${modeKey}`) && changes[`pk:${modeKey}`].newValue === undefined) return answer(CANCEL);
  const removed = [...new Set(Object.entries(changes).filter(([k, v]) => /:key$/.test(k) && v.newValue === undefined)
    .map(([k]) => k.slice(0, k.lastIndexOf(':'))))];
  if (!removed.length) return;
  for (const id of removed) { delete keys[id]; delete lists[id]; }
  merge();
  if (pk) answer(CANCEL);
  else if (mode === 'save') closeSave();
  else if (st && accounts.length) unlocked().length ? vaultView() : unlockView();
});

// Sends the page its answer, once, and closes the window.
async function answer(res) {
  if (!pk) return;
  const { id, tabId, documentId } = pk;
  pk = null;
  const handoff = await session.get(`pk:${modeKey}`).catch(() => ({}));
  if (handoff[`pk:${modeKey}`]?.id !== id && res !== CANCEL) return window.close();
  // the page's own passkey UI needs its window focused
  if (res.fallback) {
    const t = await chrome.tabs.get(tabId).catch(() => null);
    if (t) await chrome.windows.update(t.windowId, { focused: true }).catch(() => {});
  }
  chrome.tabs.sendMessage(tabId, { bwliteRes: id, ...res }, { documentId }).catch(() => {});
  session.remove(`pk:${modeKey}`);
  window.close();
}

// ponytail: user verification is the unlocked vault plus this click; there is no extra master password prompt.
function passkeyView() {
  const { kind, rpId, origin, options: o } = pk;
  const err = h('p', { className: 'err' });
  const multi = unlocked().length > 1;
  const pkRow = (text, sub, btn) => h('div', { className: 'row' },
    h('div', { className: 'info' }, h('b', { title: text }, text), sub && h('small', {}, sub)), h('div', { className: 'actions' }, btn));
  const action = (text, primary, fn) => {
    const b = h('button', { type: 'button', className: primary ? 'primary' : '', onclick: () => run(b, err, fn) }, text);
    return b;
  };
  const authorized = async (a) => {
    const id = typeof a === 'string' ? a : a?.id || a?.a;
    const current = await session.get(`${id}:key`);
    return !!id && !!keys[id] && current[`${id}:key`] === bw.b64(keys[id]);
  };
  const ids = (list) => new Set((Array.isArray(list) ? list : []).filter((c) => c && typeof c.id === 'string').map((c) => c.id));
  const mine = vault.flatMap((i) => (i.passkeys || []).filter((p) => typeof p.rpId === 'string' && p.rpId.toLowerCase() === rpId).map((p) => {
    try { return { i, p, id: bw.b64u(bw.credIdBytes(p.credentialId)) }; } catch { return null; }
  }).filter(Boolean));
  const others = h('div', { className: 'inline' },
    h('button', { type: 'button', onclick: () => answer({ fallback: true }) }, 'Use device or security key'),
    h('button', { type: 'button', onclick: () => answer(CANCEL) }, 'Cancel'));
  const show = (heading, text, rows, extra = '') =>
    app.replaceChildren(title(heading), h('p', { className: 'muted' }, text), h('div', { className: 'list' }, rows), extra, others, err);

  if (kind === 'get') {
    const allow = ids(o.allowCredentials);
    const rows = mine.filter((m) => !allow.size || allow.has(m.id)).map(({ i, p }) =>
      pkRow(p.userName || i.username || '(no username)', `${i.name}${multi ? ` · ${acct(i.a)?.label}` : ''}`,
        action('Use', true, async () => {
          const result = await bw.passkeyGet(p, o, origin);
          if (!await authorized(i.a)) return answer(CANCEL);
          await markUsed(i);
          answer({ result });
        })));
    return show('Sign in with passkey', rows.length ? `Passkeys for ${rpId}:` : `No passkey for ${rpId} in BW Lite.`, rows);
  }

  const exclude = ids(o.excludeCredentials);
  if (mine.some((m) => exclude.has(m.id))) return answer({ error: { name: 'InvalidStateError', message: 'This passkey is already saved' } });
  const save = async (a, item) => {
    if (!a || !await authorized(a)) return answer(CANCEL);
    const { passkey, result } = await bw.passkeyCreate(o, origin, rpId);
    if (!await authorized(a)) return answer(CANCEL);
    const v = item ? { ...item, passkey }
      : { name: o.rp.name || rpId, username: o.user.name || '', password: '', totp: '', notes: '', uris: [origin], passkey };
    if (!await saveItem(a, item, v)) return answer(CANCEL);
    if (!await authorized(a)) return answer(CANCEL);
    answer({ result });
  };
  // existing logins for the site that have no passkey yet
      const rows = vault.filter((i) => bw.matches(i, pageUrl, equiv.get(i.a)) && !i.passkeys).map((i) =>
    pkRow(i.username || '(no username)', `${i.name}${multi ? ` · ${acct(i.a)?.label}` : ''}`,
      action('Save here', false, async () => save(acct(i.a), await loadItem(i)))));
  const target = multi && h('select', {}, unlocked().map((a) => h('option', { value: a.id }, a.label)));
  const create = h('div', { className: 'inline' }, target,
    action('Save as new login', true, () => save(target ? acct(target.value) : unlocked()[0])));
  show('Save passkey', `Save a passkey for ${o.user.name || 'this account'} on ${rpId}${rows.length ? ', in a new login or an existing one:' : '?'}`, rows, create);
}

// The "save this login?" bar. sv: { kind: 'add' | 'update', username, password, origin, a?, id? } from background.js.
function saveView() {
  if (mode !== 'save' || !sv) return closeSave();
  const { kind, username, password, origin } = sv;
  const expires = sv.expires;
  const err = h('p', { className: 'err' });
  const close = closeSave;
  const valid = () => sv && sv.expires === expires && Number.isFinite(expires) && expires > Date.now();
  saveTimer = setTimeout(() => sv?.expires === expires && close(), Math.max(0, expires - Date.now()));
  const target = kind === 'add' && unlocked().length > 1 && h('select', {}, unlocked().map((a) => h('option', { value: a.id }, a.label)));
  const save = h('button', {
    className: 'primary',
    onclick: () => run(save, err, async () => {
      if (saveCancelled || !valid()) return close();
      const a = acct(sv.a || (target ? target.value : unlocked()[0].id));
      if (!a || !keys[a.id]) return close();
      const item = kind === 'update' ? await loadItem(sv) : null;
      if (!valid()) return close();
      const saved = await saveItem(a, item, item ? { ...item, password }
        : { name: new URL(origin).hostname, username, password, totp: '', notes: '', uris: [origin] }, valid);
      if (!saved) return close();
      close();
    }),
  }, kind === 'add' ? 'Save' : 'Update');
  const never = kind === 'add' && h('button', {
    title: `Never offer to save logins for ${new URL(origin).hostname}`,
    onclick: async () => {
      if (!valid()) return close();
      const { neverSave = [] } = await local.get('neverSave');
      const hostname = new URL(origin).hostname;
      await local.set({ neverSave: [...new Set((Array.isArray(neverSave) ? neverSave : []).concat(hostname))] });
      close();
    },
  }, 'Never');
  app.replaceChildren(
    h('div', { className: 'bar' }, h('span', { className: 'brand' }, 'BW Lite')),
    h('p', {}, kind === 'add' ? `Save the login${username ? ` for ${username}` : ''}?` : `Update the password for ${username || 'this login'}?`),
    h('div', { className: 'inline' }, target, save, never, h('button', { onclick: close }, 'Not now')), err);
}

document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 's') {
    e.preventDefault();
    document.getElementById('sync')?.click();
  }
});

start().catch((e) => mode === 'save' ? closeSave() : app.replaceChildren(h('p', { className: 'err' }, e?.message || String(e))));
