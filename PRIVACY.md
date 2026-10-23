# Privacy

BW Lite talks only to the Bitwarden or Vaultwarden server you sign in to. It sends that server what any Bitwarden client sends: your email, a hash derived from your master password, two-step login codes, and your encrypted vault items when you add or edit them. Your master password itself never leaves the extension.

Your vault key and the decrypted list are kept in the browser's memory-only session storage and are removed when you lock or close the browser, unless you pick Never lock. Encrypted vault data, account settings and login tokens are stored in your browser profile.

The developer receives nothing: there is no analytics, tracking, advertising or telemetry, and no data is sold or shared with anyone.

The extension reads the page you're on only to find login fields, fill them when you ask, offer to save a login you just submitted, and answer passkey requests from that site.

Questions: https://github.com/yowmamasita/bw-lite/issues
