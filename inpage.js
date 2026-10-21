// Content script in every frame: fills logins, shows the login menu under login fields, notices submitted logins and
// shows the "save this login?" bar (popup.html in a frame). fillTab (autofill.js) also injects it into tabs opened
// before the extension was loaded, hence the guard.
if (!globalThis.bwliteFill) {
  const visible = (i) => !i.disabled && !i.readOnly && i.getClientRects().length;
  // loose: with no password field, fall back to the first text field (the username step of a two-step login).
  // ponytail: fields inside shadow DOM aren't seen.
  const loginFields = (loose) => {
    const all = [...document.querySelectorAll('input')].filter(visible), pw = all.find((i) => i.type === 'password');
    const texts = (pw ? all.slice(0, all.indexOf(pw)) : all).filter((i) => ['text', 'email', 'tel'].includes(i.type));
    const user = pw ? texts.at(-1) : texts.find((i) => i.type === 'email' || /user|email|login/i.test(i.autocomplete + i.name + i.id)) || (loose && texts[0]);
    return { all, user, pw };
  };

  globalThis.bwliteFill = (username, password, code) => {
    const { user, pw } = loginFields(true);
    const set = (el, v) => {
      el.focus();
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, v);
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    };
    if (user && username) set(user, username);
    if (pw && password) set(pw, password);
    if (code) navigator.clipboard.writeText(code).catch(() => {});
    return !!((user && username) || pw);
  };

  // --- menu under a login field: logins for this frame's site, from background.js. A closed shadow root keeps the
  // usernames out of the page's reach; only a real click fills.
  let menu, menuFor;
  const closeMenu = () => (menu?.remove(), (menu = menuFor = null));
  const el = (tag, text) => Object.assign(document.createElement(tag), { textContent: text });
  function showMenu(field, logins) {
    const r = field.getBoundingClientRect();
    menuFor = field;
    menu = document.createElement('bwlite-menu');
    menu.style.cssText = `all: initial; position: fixed; z-index: 2147483647; left: ${r.left}px; top: ${r.bottom + 2}px;`;
    const root = menu.attachShadow({ mode: 'closed' });
    root.append(el('style', `
      div { min-width: ${Math.max(r.width, 220)}px; max-width: 360px; background: #000; color: #fff; border: 1px solid #555;
        font: 12px/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      @media (prefers-color-scheme: light) { div { background: #fff; color: #000; border-color: #bbb; } }
      button { all: unset; display: block; box-sizing: border-box; width: 100%; padding: 6px 9px; cursor: pointer; }
      button:hover { background: #8884; }
      b, small { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      small { opacity: .6; }`));
    const box = root.appendChild(document.createElement('div'));
    for (const l of logins) {
      const b = box.appendChild(document.createElement('button'));
      b.append(el('b', l.username || '(no username)'), el('small', l.name));
      b.addEventListener('click', async (e) => {
        if (!e.isTrusted) return;
        closeMenu();
        const c = await chrome.runtime.sendMessage({ bwliteFillKey: l.k });
        if (c) bwliteFill(c.username, c.password, c.code);
      });
    }
    root.addEventListener('mousedown', (e) => e.preventDefault()); // keep focus in the field so the click lands
    document.documentElement.append(menu);
  }
  async function maybeShow(f) {
    if (f === menuFor) return;
    closeMenu();
    const { user, pw } = loginFields(false);
    if ((f !== user && f !== pw) || f.autocomplete === 'new-password') return;
    const logins = await chrome.runtime.sendMessage({ bwliteMenu: true }).catch(() => null);
    if (logins?.length && document.activeElement === f && !menu) showMenu(f, logins);
  }
  // click too: a field the page focused before this script ran (autofocus) gets no focusin when clicked
  document.addEventListener('focusin', (e) => maybeShow(e.target), true);
  document.addEventListener('click', (e) => e.isTrusted && e.target === document.activeElement && maybeShow(e.target), true);
  if (document.activeElement instanceof HTMLInputElement) maybeShow(document.activeElement);
  document.addEventListener('focusout', (e) => e.target === menuFor && closeMenu(), true);
  document.addEventListener('keydown', (e) => e.key === 'Escape' && closeMenu(), true);
  addEventListener('scroll', closeMenu, true);
  addEventListener('resize', closeMenu);

  // --- logins being submitted: background.js offers to save them after the page navigates
  function capture() {
    const { all, user } = loginFields(false);
    const pws = all.filter((i) => i.type === 'password' && i.value);
    const username = user?.value.trim() || '';
    // no password yet: the username step of a two-step login, remembered for the password step
    if (pws.length || username) chrome.runtime.sendMessage({ bwliteSubmit: { username, password: pws.at(-1)?.value || '' } }).catch(() => {});
  }
  document.addEventListener('submit', capture, true);
  document.addEventListener('keydown', (e) => e.key === 'Enter' && e.target instanceof HTMLInputElement && capture(), true);
  document.addEventListener('click', (e) => e.isTrusted && e.target.closest?.('button, input[type=submit], [role=button]') && capture(), true);

  // --- the save bar, top frame only
  let bar;
  chrome.runtime.onMessage.addListener((m) => {
    if (!m.bwliteBar || window !== top) return;
    bar?.remove();
    bar = document.createElement('iframe');
    bar.src = chrome.runtime.getURL(`popup.html#save=${m.bwliteBar}`);
    bar.style.cssText = 'all: initial; position: fixed; top: 12px; right: 12px; z-index: 2147483647; width: 382px; height: 110px; border: 1px solid #555; background: #000;';
    document.documentElement.append(bar);
  });
  addEventListener('message', (e) => {
    if (!bar || e.source !== bar.contentWindow) return;
    if (e.data?.bwliteBar === 'close') bar = bar.remove();
    else if (e.data?.bwliteBar === 'size') bar.style.height = `${Math.min(e.data.height + 2, 500)}px`;
  });
}
