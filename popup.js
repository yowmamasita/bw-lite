import * as bw from './bw.js';

const app = document.getElementById('app');
const local = chrome.storage.local, session = chrome.storage.session; // session = memory only, gone when the browser quits
let st, userKey, vault = [], tab, host, query = '';

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (v != null && v !== false) el[k] = v;
  }
  el.append(...kids.flat().filter((k) => k != null && k !== false && k !== ''));
  return el;
}
const save = (obj) => (Object.assign(st, obj), local.set(obj));
const sess = () => ({ server: st.server, tokens: st.tokens, onTokens: (tokens) => save({ tokens }) });
const field = (label, el) => h('label', {}, label, el);
const title = (text) => h('h1', {}, text, themeButton());

// Night (default) / day toggle; the choice is a per-browser convenience, so localStorage is enough.
function themeButton() {
  const root = document.documentElement;
  const label = () => (root.dataset.theme === 'light' ? 'Night' : 'Day');
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
  // small settings only; the encrypted index and raw ciphers are read when needed
  const keys = ['server', 'email', 'kdf', 'protectedKey', 'tokens', 'deviceId', 'lastSync', 'neverLock', 'persistKey'];
  let k, list;
  [st, { userKey: k, list }, [tab]] = await Promise.all([
    local.get(keys), session.get(['userKey', 'list']), chrome.tabs.query({ active: true, currentWindow: true })]);
  host = /^https?:/.test(tab?.url) ? new URL(tab.url).hostname : null;
  if (!st.protectedKey) return loginView();
  if (!k && !st.persistKey) return unlockView();
  userKey = bw.unb64(k || st.persistKey);
  if (!list) return loadVault();
  vault = JSON.parse(list);
  vaultView();
}

// "Never lock" (like Bitwarden's Never timeout) also keeps the key in local storage so it survives a browser restart.
async function setKey(key) {
  userKey = key;
  const k = bw.b64(key);
  await Promise.all([session.set({ userKey: k }), st.neverLock && local.set({ persistKey: k })]);
}

function loginView() {
  const server = h('input', { value: st.server || 'https://vault.bitwarden.com', required: true });
  const email = h('input', { type: 'email', value: st.email || '', required: true });
  const pw = h('input', { type: 'password', required: true });
  const code = h('input', { autocomplete: 'one-time-code' });
  const codeField = h('label', { hidden: true }, h('span'), code);
  const btn = h('button', { className: 'primary' }, 'Log in');
  const err = h('p', { className: 'err' });
  let need;
  const form = h('form', {
    onsubmit: (e) => {
      e.preventDefault();
      run(btn, err, async () => {
        const srv = server.value.trim().replace(/\/+$/, '');
        if (!st.deviceId) await save({ deviceId: crypto.randomUUID() });
        try {
          const r = await bw.login(srv, email.value.trim(), pw.value, st.deviceId, need && { kind: need, value: code.value.trim() });
          await save({ server: srv, email: email.value.trim(), kdf: r.kdf, protectedKey: r.protectedKey, tokens: r.tokens });
          await setKey(r.userKey);
          await syncVault();
        } catch (e) {
          if (!e.need) throw e;
          need = e.need;
          codeField.hidden = false;
          codeField.firstChild.textContent = e.message;
          code.focus();
        }
      });
    },
  }, field('Server', server), field('Email', email), field('Master password', pw), codeField, btn, err);
  app.replaceChildren(title('BW Lite'), form);
  (st.email ? pw : email).focus();
}

function unlockView() {
  const pw = h('input', { type: 'password', required: true });
  const btn = h('button', { className: 'primary' }, 'Unlock');
  const err = h('p', { className: 'err' });
  const form = h('form', {
    onsubmit: (e) => {
      e.preventDefault();
      run(btn, err, async () => {
        await setKey(await bw.unlock(pw.value, st.email, st.kdf, st.protectedKey));
        await loadVault();
      });
    },
  }, field(`Master password for ${st.email}`, pw), btn, err);
  app.replaceChildren(title('BW Lite'), form, h('button', { className: 'link', onclick: logout }, 'Log out'));
  pw.focus();
}

async function logout() {
  await local.clear();
  // same device id avoids new-device emails
  await local.set({ deviceId: st.deviceId, server: st.server, email: st.email, neverLock: st.neverLock });
  await session.clear();
  st = await local.get(null);
  loginView();
}

const strip = ({ raw, key, notes, ...listFields }) => listFields;
const byName = (a, b) => a.name.localeCompare(b.name);

// The decrypted list also lives in session storage (memory only, cleared with the key on lock or browser quit),
// so an unlocked popup opens with one read + JSON.parse. The encrypted copy in local storage serves unlock;
// persist rewrites it when the items changed.
async function setVault(items, persist = true) {
  vault = items;
  const list = JSON.stringify(items);
  await Promise.all([session.set({ list }), persist && local.set({ index: await bw.encrypt(list, userKey) })]);
}

// Manual (Sync button / Ctrl+S), except when there is no local data yet. Unchanged items aren't decrypted again.
async function syncVault() {
  const sync = await bw.api(sess(), '/sync?excludeDomains=true');
  const items = (await bw.decryptVault(sync, userKey, new Map(vault.map((i) => [i.id, i])))).map(strip);
  const ids = sync.ciphers.map((c) => c.id), keep = new Set(ids);
  const { ids: old = [] } = await local.get('ids');
  // raw ciphers stored one key per item so editing reads just the one it needs; 'sync' is the pre-0.2 layout
  await local.remove(['sync', 'revision', ...old.filter((id) => !keep.has(id)).map((id) => `c:${id}`)]);
  await local.set({ profile: sync.profile, ids, ...Object.fromEntries(sync.ciphers.map((c) => [`c:${c.id}`, c])) });
  await setVault(items);
  await save({ lastSync: Date.now() });
  vaultView();
}

async function loadVault() {
  const { index, ids } = await local.get(['index', 'ids']);
  if (!index || !ids) return syncVault();
  await setVault(JSON.parse(new TextDecoder().decode(await bw.decrypt(index, userKey))), false);
  vaultView();
}

async function fullItem(raw) {
  const { profile } = await local.get('profile');
  return (await bw.decryptVault({ profile, ciphers: [raw] }, userKey))[0];
}

// The list only holds what it shows; editing needs the raw cipher and its key.
async function openEdit(i) {
  const k = `c:${i.id}`;
  editView(await fullItem((await local.get(k))[k]));
}

// Applies a saved cipher from the server's reply locally, no full sync needed.
async function storeCipher(raw) {
  const { ids } = await local.get('ids');
  await local.set({ [`c:${raw.id}`]: raw, ids: ids.includes(raw.id) ? ids : [...ids, raw.id] });
  await setVault([...vault.filter((i) => i.id !== raw.id), strip(await fullItem(raw))].sort(byName));
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
  const b = h('button', { className: 'totp', title: 'Copy TOTP code', onclick: async () => copy(b, (await bw.totp(item.totp)).code) });
  const tick = () => bw.totp(item.totp).then((t) => (b.textContent = `${t.code} · ${t.remaining}s`), () => (b.textContent = 'bad TOTP'));
  tick();
  b._tick = tick;
  return b;
}
setInterval(() => document.querySelectorAll('.totp').forEach((b) => b.textContent !== 'Copied' && b._tick?.()), 1000);

function vaultView() {
  const q = h('input', { type: 'search', placeholder: 'Search vault', value: query, oninput: () => ((query = q.value), draw()) });
  const list = h('div', { className: 'list' });
  const row = (i) => h('div', { className: 'row' },
    h('div', { className: 'info', title: 'Edit', onclick: () => openEdit(i).catch((e) => status(e.message)) }, h('b', {}, i.name || '(no name)'), h('small', {}, i.username)),
    h('div', { className: 'actions' },
      host && bw.matches(i, host) && h('button', { className: 'primary', onclick: () => fill(i) }, 'Fill'),
      i.username && h('button', { title: 'Copy username', onclick: (e) => copy(e.target, i.username) }, 'User'),
      i.password && h('button', { title: 'Copy password', onclick: (e) => copy(e.target, i.password) }, 'Pass'),
      i.totp && totpButton(i)));
  const draw = () => {
    const s = q.value.trim().toLowerCase();
    const items = s
      ? vault.filter((i) => `${i.name} ${i.username} ${i.uris.join(' ')}`.toLowerCase().includes(s))
      : vault.filter((i) => !host || bw.matches(i, host));
    list.replaceChildren(...(items.length
      ? items.slice(0, 50).map(row)
      : [h('p', { className: 'muted' }, s ? 'No matches' : 'No logins for this site. Type to search.')]));
  };
  const lock = async () => (await Promise.all([session.remove(['userKey', 'list']), local.remove('persistKey')]), unlockView());
  const neverLock = h('input', {
    type: 'checkbox', checked: !!st.neverLock,
    onchange: async () => {
      await save({ neverLock: neverLock.checked });
      await (neverLock.checked ? local.set({ persistKey: bw.b64(userKey) }) : local.remove('persistKey'));
    },
  });
  const ago = st.lastSync ? Math.round((Date.now() - st.lastSync) / 60e3) : null;
  const syncBtn = h('button', {
    id: 'sync', title: `Sync now (Ctrl+S)${ago == null ? '' : ` · last synced ${ago < 1 ? 'just now' : ago < 120 ? `${ago} min ago` : `${Math.round(ago / 60)} h ago`}`}`,
    onclick: () => ((syncBtn.textContent = 'Syncing…'), run(syncBtn, document.getElementById('status'), syncVault).finally(() => (syncBtn.textContent = 'Sync'))),
  }, 'Sync');
  app.replaceChildren(
    h('header', {}, q, h('button', { title: 'Add login', onclick: () => editView(null) }, '+'), syncBtn, h('button', { onclick: lock }, 'Lock'), themeButton()),
    list, h('p', { id: 'status', className: 'err' }),
    h('footer', {}, h('label', { className: 'check', title: 'Keeps the vault key on this computer so the vault stays open after a browser restart. Anyone with access to this browser profile can then open your vault.' }, neverLock, 'Never lock')));
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
  const readOnly = item?.raw.edit === false;
  const btn = h('button', { className: 'primary', disabled: readOnly }, readOnly ? 'Read-only' : 'Save');
  const err = h('p', { className: 'err' });
  const form = h('form', {
    onsubmit: (e) => {
      e.preventDefault();
      run(btn, err, async () => {
        if (totp.value.trim()) await bw.totp(totp.value.trim()); // reject a bad secret before saving it
        await storeCipher(await bw.saveCipher(sess(), userKey, item, {
          name: name.value.trim(), username: user.value, password: pass.value, totp: totp.value.trim(), notes: notes.value,
          uris: uris.value.split('\n').map((u) => u.trim()).filter(Boolean),
        }));
        vaultView();
      });
    },
  },
    field('Name', name), field('Username', user),
    field('Password', h('div', { className: 'inline' }, pass,
      h('button', { type: 'button', onclick: () => (pass.type = pass.type === 'password' ? 'text' : 'password') }, 'Show'),
      h('button', { type: 'button', onclick: () => ((pass.value = genPassword()), (pass.type = 'text')) }, 'Gen'))),
    field('TOTP', totp), field('URLs', uris), field('Notes', notes),
    h('div', { className: 'inline' }, btn, h('button', { type: 'button', onclick: vaultView }, 'Cancel')), err);
  app.replaceChildren(title(item ? 'Edit login' : 'Add login'), form);
  name.focus();
}

document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 's') {
    e.preventDefault();
    document.getElementById('sync')?.click();
  }
});

start().catch((e) => app.replaceChildren(h('p', { className: 'err' }, e.message)));
