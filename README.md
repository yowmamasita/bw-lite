# BW Lite

A minimal, unofficial Chrome extension for Bitwarden and Vaultwarden. It does six things: search your logins, copy
them, autofill the current page, show TOTP codes, sign in with passkeys, and add or edit logins. Nothing else. Any number of accounts
(bitwarden.com, bitwarden.eu, self-hosted, mixed) show up as one list.

About 1,250 lines of plain JavaScript, no build step, no framework. The only third-party code is
[hash-wasm](https://github.com/Daninet/hash-wasm) (MIT), loaded only for accounts that use Argon2id.

Not affiliated with or endorsed by Bitwarden, Inc. It is a separate client written from scratch against the public
API; none of Bitwarden's client code is used.

## Install

Download the latest `bw-lite-<version>.zip` from [Releases](https://github.com/yowmamasita/bw-lite/releases) and unzip
it somewhere permanent (Chrome loads the extension from that folder on every start). Then open `chrome://extensions`,
turn on **Developer mode**, click **Load unpacked** and pick the `bw-lite` folder. To update, replace the folder's
contents and click the extension's reload button.

The extension ID is always `edggmjogcnhnppgfidekhhdjpdjcpdmk`. There is no `.crx`: Chrome refuses `.crx` files that
don't come from the Chrome Web Store (`CRX_REQUIRED_PROOF_MISSING`).

## Use

- **Server**: `https://vault.bitwarden.com` (or `https://vault.bitwarden.eu`) for the cloud, else your self-hosted URL.
- **Logins for the current site** show up when you open the popup. Typing searches those first; **search whole vault**
  widens it to everything. On a site without logins, typing searches everything right away.
- **Fill** fills the username and password on the page and copies the TOTP code, if the login has one. The login you
  last filled (or signed in with by passkey) moves to the top of the site's list and gets the highlighted **Fill**, as
  in Bitwarden. That order is kept on this computer only.
- **Several vaults**: add more under **Vaults**. Their logins merge into one list. When a list mixes vaults, each group title shows its vault's label (editable
  there) with a color dot. The order on that page is the autofill priority for logins you haven't used yet: the first vault with a login for the site provides
  the highlighted **Fill**, which **Enter** triggers; a vault without one falls through to the next. One password box
  unlocks every vault that uses that password; the others stay locked until you enter theirs. Sync, Lock and Never lock
  apply to all vaults.
- **Login fields** get a small menu with the site's logins when you click into them; picking one fills the form.
- **Ctrl+Shift+L** (Cmd+Shift+L on a Mac) fills the top login without opening the popup. Change it at
  `chrome://extensions/shortcuts`.
- **The toolbar icon** shows how many logins the current site has.
- **Save / update prompt**: after you log in with a login BW Lite doesn't know, or with a new password for one it does,
  a bar at the top right offers to save or update it. **Never** stops it for that site.
- **Login forms inside frames** are filled too, but only frames whose own address matches the login.
- **Matching** follows each saved URL's match setting from Bitwarden (base domain, host, starts with, exact, regular
  expression, never) and Bitwarden's equivalent domains (google.com and youtube.com count as one site, and so on).
- **note** under a login means it has a note; click it to open the login.
- **Delete** (in the edit view, click twice) moves the login to the trash, as Bitwarden does; restore it from the web
  vault.
- **Click a login** to edit it, **+** to add one (prefilled with the current site). **Gen** makes a 20-character password.
- **Sync** is manual: the Sync button or **Ctrl/Cmd+S** (hover it for the last sync time). It only runs by itself at
  first login. Saving a login updates the local copy from the server's reply, no full sync needed.
- **Never lock** (checkbox under the list) keeps the vault open across browser restarts, like Bitwarden's "Never"
  vault timeout. Off by default: the vault then locks when the browser quits.
- **Passkeys**: when a site asks to create or use a passkey, a BW Lite window opens. Saving puts it in a new login or an
  existing one for the site (one passkey per login, like Bitwarden); signing in lists the vault's passkeys for the site.
  **Use device or security key** hands the request to Chrome's own passkey dialog. Passkeys are stored in Bitwarden's
  format, so the official apps use the ones made here and the other way round. A site that only wants a security key
  isn't interrupted: with every vault unlocked and no passkey for the site, Chrome's dialog shows straight away.
- **Day / Night** toggles the theme. **Lock** locks right away, even with Never lock on.

Two-step login supports authenticator apps and Bitwarden's emailed new-device codes.

## Speed

Measured with a 2,300-login vault on an Intel i5-9500T: the popup shows the list about 25 ms after Chrome itself has
opened the page, unlock is the account's key derivation (about 260 ms for PBKDF2 at 600,000 iterations) plus about
50 ms, and opening a login for editing takes about 40 ms.

## Security model

- Your master password never leaves the popup; the server only sees the standard Bitwarden password hash.
- The decrypted key and the decrypted login list live in `chrome.storage.session`, which Chrome keeps in memory only
  and never exposes to web pages. Locking or quitting the browser clears them.
- With **Never lock** on, the vault key is also written to `chrome.storage.local` unencrypted, exactly like
  Bitwarden's own "Never" timeout: anyone who can read this browser profile can open your vault. Lock removes it.
- On disk (`chrome.storage.local`) everything stays encrypted with your vault key: the raw items as the server sent them
  and an encrypted copy of the login list used to unlock quickly. The refresh token is stored there too, as in the
  official extension.
- Passkey requests are checked against the page's real origin (from Chrome, not the page): HTTPS only, and the site
  can only ask for its own domain or a parent of it. Clicking **Use** or **Save** counts as user verification, as an
  unlocked vault does; there is no extra master password prompt.
- Filling only happens on a click (popup, field menu) or the shortcut, and only in frames whose own URL matches the
  login, so a frame from another site embedded in the page never gets the password.
- The field menu lives in a closed shadow root, so the page's scripts can't read the usernames in it, and it ignores
  clicks the page fakes. Passwords only go to the frame when you pick a login. The save bar is BW Lite's own page in a
  frame, which the page can't read either.
- The background script reads the vaults that are open (session storage, or the stored key with Never lock) to count
  logins for the badge and answer the field menu. It never writes to the vault; saving happens in the popup or the bar.
- This code has not had an independent security review. Use it at your own judgement.

## Not supported

Secure notes, cards and identities (they're hidden, not deleted); passkey requests inside iframes;
login fields inside shadow DOM; a save prompt on a single-page app whose URL doesn't change after logging in; passkey autofill (`mediation: "conditional"`, left to Chrome);
passkey algorithms other than ES256 (left to Chrome); auto-lock timers; clearing the clipboard; 2FA methods other than an authenticator app;
captcha challenges. Domain matching uses a short list of country suffixes (`co.uk` and similar) instead of the full
public suffix list.

## Development

```sh
docker run -d --name bwlite-vw -p 127.0.0.1:8099:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_MAX_BURST=100 -e LOGIN_RATELIMIT_SECONDS=1 vaultwarden/server
node test.mjs   # login, sync, create, edit, passkeys, org items, per-item keys, token refresh, Argon2id
./pack.sh       # dist/bw-lite-<version>.zip
```

## License

MIT. `vendor/argon2.umd.min.js` is hash-wasm, MIT, see `vendor/hash-wasm.LICENSE`.
