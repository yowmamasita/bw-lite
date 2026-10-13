import * as bw from './bw.js';

const app = document.getElementById('app');
const local = chrome.storage.local, session = chrome.storage.session; // session = memory only, gone when the browser quits
const td = new TextDecoder();
const collator = new Intl.Collator();

// accounts: ordered list (the order is the autofill priority) of
//   { id, server, email, label, kdf, protectedKey, tokens, lastSync, persistKey? }
// Per account in local storage: `${id}:index` (encrypted list), `${id}:ids`, `${id}:profile`, `${id}:c:${cipherId}` (raw).
// Per account in session storage: `${id}:key` and `${id}:list` (decrypted list, so an open is a read + JSON.parse).
let st, accounts = [], keys = {}, lists = {}, vault = [], tab, host, query = '';

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
const saveAccounts = () => local.set({ accounts });
const update = (a, patch) => (Object.assign(a, patch), saveAccounts());
const sess = (a) => ({ server: a.server, tokens: a.tokens, onTokens: (tokens) => update(a, { tokens }) });
const acct = (id) => accounts.find((a) => a.id === id);
const unlocked = () => accounts.filter((a) => keys[a.id]);
const locked = () => accounts.filter((a) => !keys[a.id]);
const rank = (id) => accounts.findIndex((a) => a.id === id);
const strip = ({ raw, key, notes, ...listFields }) => listFields;
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
    err.textContent = e.message;
  } finally {
    btn.disabled = false;
  }
}

async function start() {
  let s;
  [st, s, [tab]] = await Promise.all([
    local.get(['accounts', 'deviceId', 'neverLock', 'server', 'email', 'kdf', 'protectedKey', 'tokens', 'persistKey']),
    session.get(null), chrome.tabs.query({ active: true, currentWindow: true })]);
  host = /^https?:/.test(tab?.url) ? new URL(tab.url).hostname : null;
  if (!st.accounts && st.protectedKey) s = await migrate();
  accounts = st.accounts || [];
  for (const a of accounts) {
    const k = s[`${a.id}:key`] || a.persistKey;
    if (k) keys[a.id] = bw.unb64(k);
  }
  if (!accounts.length) return loginView();
  if (!unlocked().length) return unlockView();
  const problems = await loadVaults(s);
  vaultView();
  if (problems) status(problems);
}

// 0.1/0.2 stored one account in flat keys. Move it into the accounts list; its cached vault is re-synced.
async function migrate() {
  const a = { id: newId(), server: st.server, email: st.email, label: st.email, kdf: st.kdf, protectedKey: st.protectedKey, tokens: st.tokens };
  if (st.neverLock && st.persistKey) a.persistKey = st.persistKey;
  st = { deviceId: st.deviceId, neverLock: st.neverLock, accounts: [a] };
  await local.clear();
  await local.set(st);
  await session.clear();
  return {};
}

// "Never lock" (like Bitwarden's Never timeout) also keeps the key in local storage so it survives a browser restart.
async function setKey(a, key) {
  keys[a.id] = key;
  const k = bw.b64(key);
  await Promise.all([session.set({ [`${a.id}:key`]: k }), st.neverLock && update(a, { persistKey: k })]);
}

async function setList(a, items, persist = true) {
  lists[a.id] = items;
  const list = JSON.stringify(items);
  await Promise.all([
    session.set({ [`${a.id}:list`]: list }),
    persist && local.set({ [`${a.id}:index`]: await bw.encrypt(list, keys[a.id]) }),
  ]);
}

function merge() {
  const parts = unlocked().map((a) => lists[a.id] || []);
  vault = parts.length === 1 ? parts[0] : parts.flat().sort(byName);
}

// Loads every unlocked account that isn't loaded yet; one failing account doesn't block the others.
async function loadVaults(s = {}) {
  const todo = unlocked().filter((a) => !lists[a.id]);
  const res = await Promise.allSettled(todo.map(async (a) => {
    if (s[`${a.id}:list`]) return (lists[a.id] = JSON.parse(s[`${a.id}:list`]));
    const { [`${a.id}:index`]: index } = await local.get(`${a.id}:index`);
    if (!index) return syncAccount(a);
    await setList(a, JSON.parse(td.decode(await bw.decrypt(index, keys[a.id]))), false);
  }));
  merge();
  return failures(todo, res);
}

const failures = (todo, res) =>
  res.map((r, i) => r.status === 'rejected' && `${todo[i].label}: ${r.reason.message}`).filter(Boolean).join('\n');

// Manual (Sync button / Ctrl+S), except for an account with no local data yet. Unchanged items aren't decrypted again.
async function syncAccount(a) {
  const p = `${a.id}:`;
  const sync = await bw.api(sess(a), '/sync?excludeDomains=true');
  const prev = new Map((lists[a.id] || []).map((i) => [i.id, i]));
  const items = (await bw.decryptVault(sync, keys[a.id], prev)).map((i) => ({ ...strip(i), a: a.id }));
  const ids = sync.ciphers.map((c) => c.id), keep = new Set(ids);
  const { [`${p}ids`]: old = [] } = await local.get(`${p}ids`);
  // raw ciphers stored one key per item so editing reads just the one it needs
  await local.remove(old.filter((id) => !keep.has(id)).map((id) => `${p}c:${id}`));
  await local.set({ [`${p}profile`]: sync.profile, [`${p}ids`]: ids, ...Object.fromEntries(sync.ciphers.map((c) => [`${p}c:${c.id}`, c])) });
  await setList(a, items);
  await update(a, { lastSync: Date.now() });
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
          accounts.push(a);
          await saveAccounts();
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
  const rows = accounts.map((a, i) => {
    const label = h('input', { value: a.label, title: 'Label shown on this vault\'s items', onchange: () => update(a, { label: label.value.trim() || a.email }) });
    const remove = h('button', {
      title: 'Log out and remove this vault from BW Lite',
      onclick: () => (remove.textContent === 'Sure?' ? removeAccount(a) : (remove.textContent = 'Sure?')),
    }, 'Remove');
    return h('div', { className: 'row' },
      h('div', { className: 'info' }, label, h('small', {}, `${a.email} · ${new URL(a.server).host}${keys[a.id] ? '' : ' · locked'}`)),
      h('div', { className: 'actions' },
        h('button', { title: 'Higher autofill priority', disabled: i === 0, onclick: () => move(i, -1) }, '↑'),
        h('button', { title: 'Lower autofill priority', disabled: i === accounts.length - 1, onclick: () => move(i, 1) }, '↓'),
        remove));
  });
  app.replaceChildren(title('Vaults'),
    h('p', { className: 'muted' }, 'Order is the autofill priority: the first vault with a login for the site fills.'),
    h('div', { className: 'list' }, rows),
    h('div', { className: 'inline' },
      h('button', { className: 'primary', onclick: loginView }, 'Add vault'),
      h('button', { onclick: () => (unlocked().length ? vaultView() : unlockView()) }, 'Done')));
}

async function move(i, d) {
  [accounts[i], accounts[i + d]] = [accounts[i + d], accounts[i]];
  await saveAccounts();
  accountsView();
}

async function removeAccount(a) {
  const p = `${a.id}:`;
  const { [`${p}ids`]: ids = [] } = await local.get(`${p}ids`);
  await local.remove([`${p}index`, `${p}ids`, `${p}profile`, ...ids.map((id) => `${p}c:${id}`)]);
  await session.remove([`${p}key`, `${p}list`]);
  accounts = accounts.filter((x) => x !== a);
  delete keys[a.id];
  delete lists[a.id];
  await saveAccounts();
  merge();
  if (accounts.length) accountsView();
  else loginView();
}

async function lockAll() {
  keys = {};
  lists = {};
  vault = [];
  for (const a of accounts) delete a.persistKey;
  await Promise.all([session.clear(), saveAccounts()]);
  unlockView();
}

async function fullItem(a, raw) {
  const { [`${a.id}:profile`]: profile } = await local.get(`${a.id}:profile`);
  return { ...(await bw.decryptVault({ profile, ciphers: [raw] }, keys[a.id]))[0], a: a.id };
}

// The list only holds what it shows; editing needs the raw cipher and its key.
async function openEdit(i) {
  const k = `${i.a}:c:${i.id}`;
  editView(await fullItem(acct(i.a), (await local.get(k))[k]));
}

// Applies a saved cipher from the server's reply locally, no full sync needed.
async function storeCipher(a, raw) {
  const p = `${a.id}:`;
  const { [`${p}ids`]: ids = [] } = await local.get(`${p}ids`);
  await local.set({ [`${p}c:${raw.id}`]: raw, [`${p}ids`]: ids.includes(raw.id) ? ids : [...ids, raw.id] });
  await setList(a, [...lists[a.id].filter((i) => i.id !== raw.id), strip(await fullItem(a, raw))].sort(byName));
  merge();
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

// Runs inside the page. Must stay self-contained: it is serialized by chrome.scripting.
function fillPage(username, password) {
  const inputs = [...document.querySelectorAll('input')].filter((i) => !i.disabled && !i.readOnly && i.getClientRects().length);
  const pw = inputs.find((i) => i.type === 'password');
  const texts = (pw ? inputs.slice(0, inputs.indexOf(pw)) : inputs).filter((i) => ['text', 'email', 'tel'].includes(i.type));
  const user = pw ? texts.at(-1) : texts.find((i) => i.type === 'email' || /user|email|login/i.test(i.autocomplete + i.name + i.id)) || texts[0];
  const set = (el, v) => {
    el.focus();
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, v);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };
  if (user && username) set(user, username);
  if (pw && password) set(pw, password);
  return !!((user && username) || pw);
}

// ponytail: fills the top frame only; login forms inside iframes aren't reached.
async function fill(item) {
  const now = await chrome.tabs.get(tab.id);
  if (!/^https?:/.test(now.url) || !bw.matches(item, new URL(now.url).hostname)) return status('The tab changed, not filling');
  const [{ result }] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: fillPage, args: [item.username, item.password] });
  if (!result) return status('No login form found on this page');
  if (item.totp) await navigator.clipboard.writeText((await bw.totp(item.totp)).code);
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
  const multi = accounts.length > 1;
  let top; // the login autofill uses: first match in vault order; Enter fills it
  const q = h('input', {
    type: 'search', placeholder: 'Search all logins', value: query,
    oninput: () => ((query = q.value), draw()),
    onkeydown: (e) => e.key === 'Enter' && top && fill(top),
  });
  const context = h('p', { className: 'context' });
  const list = h('div', { className: 'list' });
  const quiet = (text, title, onclick) => h('button', { className: 'quiet', title, onclick }, text);
  const row = (i, mixed) => h('div', { className: 'row' },
    h('div', { className: 'info' },
      h('b', { title: i.username }, i.username || '(no username)'),
      (mixed || i.totp) && h('small', {}, mixed && h('span', { className: 'vault', title: 'Vault' }, acct(i.a)?.label), i.totp && totpButton(i))),
    h('div', { className: 'actions' },
      host && bw.matches(i, host) && h('button', { className: i === top ? 'primary' : '', title: i === top ? 'Fill (Enter)' : 'Fill', onclick: () => fill(i) }, 'Fill'),
      i.username && quiet('user', 'Copy username', (e) => copy(e.target, i.username)),
      i.password && quiet('pass', 'Copy password', (e) => copy(e.target, i.password)),
      quiet('edit', 'Edit', () => openEdit(i).catch((e) => status(e.message)))));
  const draw = () => {
    const s = q.value.trim().toLowerCase();
    const items = s
      ? vault.filter((i) => `${i.name} ${i.username} ${i.uris.join(' ')}`.toLowerCase().includes(s))
      : host ? vault.filter((i) => bw.matches(i, host)).sort((x, y) => rank(x.a) - rank(y.a)) : vault;
    top = host && items[0] && bw.matches(items[0], host) ? items[0] : null;
    const shown = items.slice(0, 50);
    const n = `${items.length} login${items.length === 1 ? '' : 's'}`;
    context.textContent = s ? `${items.length ? n : 'No logins'} matching “${q.value.trim()}”${items.length > 50 ? ', first 50 shown' : ''}`
      : host ? (items.length ? `${n} for ${host}` : `No logins for ${host}. Type to search.`)
      : `${n}${items.length > 50 ? ', first 50 shown' : ''}`;
    const mixed = new Set(shown.map((i) => i.a)).size > 1; // vault names only when they tell rows apart
    const out = [];
    let group;
    for (const i of shown) {
      if (i.name !== group) out.push(h('div', { className: 'group' }, (group = i.name) || '(no name)'));
      out.push(row(i, mixed));
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
      await local.set({ neverLock: (st.neverLock = neverLock.checked) });
      for (const a of accounts) {
        if (st.neverLock && keys[a.id]) a.persistKey = bw.b64(keys[a.id]);
        else delete a.persistKey;
      }
      await saveAccounts();
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
  const form = h('form', {
    onsubmit: (e) => {
      e.preventDefault();
      run(btn, err, async () => {
        if (totp.value.trim()) await bw.totp(totp.value.trim()); // reject a bad secret before saving it
        const a = acct(item?.a || (target ? target.value : unlocked()[0].id));
        await storeCipher(a, await bw.saveCipher(sess(a), keys[a.id], item, {
          name: name.value.trim(), username: user.value, password: pass.value, totp: totp.value.trim(), notes: notes.value,
          uris: uris.value.split('\n').map((u) => u.trim()).filter(Boolean),
        }));
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
    h('div', { className: 'inline' }, btn, h('button', { type: 'button', onclick: vaultView }, 'Cancel')), err);
  const vaultName = item && accounts.length > 1 && acct(item.a)?.label;
  app.replaceChildren(title(item ? 'Edit login' : 'Add login'), vaultName && h('p', { className: 'muted' }, `Vault: ${vaultName}`), form);
  name.focus();
}

document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 's') {
    e.preventDefault();
    document.getElementById('sync')?.click();
  }
});

start().catch((e) => app.replaceChildren(h('p', { className: 'err' }, e.message)));
