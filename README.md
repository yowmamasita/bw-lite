# BW Lite

A minimal, unofficial Chrome extension for Bitwarden and Vaultwarden. It does five things: search your logins, copy
them, autofill the current page, show TOTP codes, and add or edit logins. Nothing else.

About 500 lines of plain JavaScript, no build step, no framework. The only third-party code is
[hash-wasm](https://github.com/Daninet/hash-wasm) (MIT), loaded only for accounts that use Argon2id.

Not affiliated with or endorsed by Bitwarden, Inc. It is a separate client written from scratch against the public
API; none of Bitwarden's client code is used.

## Install

Download the latest `bw-lite-<version>.zip` from [Releases](https://github.com/yowmamasita/bw-lite/releases), unzip it,
then in Chrome open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked** and pick the `bw-lite`
folder.

A signed `.crx` is attached to each release too. Chrome on Windows and macOS refuses `.crx` files that don't come from
the Chrome Web Store, so use the zip there; the `.crx` is for Chromium builds and enterprise policies that allow it.

## Use

- **Server**: `https://vault.bitwarden.com` (or `https://vault.bitwarden.eu`) for the cloud, else your self-hosted URL.
- **Logins for the current site** show up when you open the popup; type to search everything.
- **Fill** fills the username and password on the page and copies the TOTP code, if the login has one.
- **Click a login** to edit it, **+** to add one (prefilled with the current site). **Gen** makes a 20-character password.
- **Sync** is manual: the Sync button or **Ctrl/Cmd+S** (hover it for the last sync time). It only runs by itself at
  first login. Saving a login updates the local copy from the server's reply, no full sync needed.
- **Day / Night** toggles the theme. **Lock** forgets the key until you unlock again.

Two-step login supports authenticator apps and Bitwarden's emailed new-device codes.

## Speed

Measured with a 2,300-login vault on an Intel i5-9500T: the popup shows the list about 25 ms after Chrome itself has
opened the page, unlock is the account's key derivation (about 260 ms for PBKDF2 at 600,000 iterations) plus about
50 ms, and opening a login for editing takes about 40 ms.

## Security model

- Your master password never leaves the popup; the server only sees the standard Bitwarden password hash.
- The decrypted key and the decrypted login list live in `chrome.storage.session`, which Chrome keeps in memory only
  and never exposes to web pages. Locking or quitting the browser clears them.
- On disk (`chrome.storage.local`) everything stays encrypted with your vault key: the raw items as the server sent them
  and an encrypted copy of the login list used to unlock quickly. The refresh token is stored there too, as in the
  official extension.
- Fill only runs when you click it, only in the tab's top frame, and only if the tab still matches the login's domain.
- This code has not had an independent security review. Use it at your own judgement.

## Not supported

Secure notes, cards and identities (they're hidden, not deleted); deleting items; the "save this login?" prompt;
login forms inside iframes; auto-lock timers; clearing the clipboard; 2FA methods other than an authenticator app;
captcha challenges. Domain matching uses a short list of country suffixes (`co.uk` and similar) instead of the full
public suffix list.

## Development

```sh
docker run -d --name bwlite-vw -p 127.0.0.1:8099:80 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_MAX_BURST=100 -e LOGIN_RATELIMIT_SECONDS=1 vaultwarden/server
node test.mjs   # login, sync, create, edit, org items, per-item keys, token refresh, Argon2id
./pack.sh       # dist/bw-lite-<version>.zip; with BW_LITE_KEY and CHROME set, also the signed .crx
```

## License

MIT. `vendor/argon2.umd.min.js` is hash-wasm, MIT, see `vendor/hash-wasm.LICENSE`.
