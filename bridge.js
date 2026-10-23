// Content script: carries page.js's passkey requests to background.js and the answers back into the page.
// This is only a transport boundary. background.js owns the authoritative
// WebAuthn validation; bridge.js copies a fixed passkey allowlist and never
// forwards arbitrary page message fields.
const idOf = (id) => typeof id === 'string' && id.length > 0 && id.length < 200;
const createFields = ['challenge', 'timeout', 'rp', 'user', 'pubKeyCredParams', 'excludeCredentials', 'extensions',
  'authenticatorSelection', 'attestation'];
const getFields = ['challenge', 'timeout', 'rpId', 'allowCredentials', 'extensions', 'userVerification'];
const options = (kind, source) => {
  if (!source || typeof source !== 'object' || !['create', 'get'].includes(kind)) return null;
  const fields = kind === 'create' ? createFields : getFields;
  const out = {};
  for (const key of fields) if (Object.prototype.hasOwnProperty.call(source, key)) out[key] = source[key];
  // This cheap check lets malformed requests fall back immediately. The
  // background validator checks all nested descriptors and protocol rules.
  return typeof out.challenge === 'string' && out.challenge.length > 0 && out.challenge.length <= 16384 ? out : null;
};
const response = (m, id) => {
  if (!m || m.bwliteRes !== id) return null;
  const out = { bwliteRes: id };
  if (m.fallback === true) out.fallback = true;
  if (m.error && typeof m.error.name === 'string' && typeof m.error.message === 'string')
    out.error = { name: m.error.name, message: m.error.message };
  if (m.result && typeof m.result === 'object') {
    const r = m.result, rr = r.response;
    if (typeof r.id === 'string' && typeof r.rawId === 'string' && r.type === 'public-key' && rr && typeof rr === 'object') {
      const names = rr.attestationObject
        ? ['clientDataJSON', 'attestationObject', 'authenticatorData', 'publicKey', 'publicKeyAlgorithm', 'transports']
        : ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle'];
      const clean = Object.fromEntries(names.filter((k) => rr[k] !== undefined).map((k) => [k, rr[k]]));
      const extensions = r.clientExtensionResults?.credProps && typeof r.clientExtensionResults.credProps === 'object'
        ? { credProps: { rk: r.clientExtensionResults.credProps.rk === true } } : {};
      out.result = { id: r.id, rawId: r.rawId, type: r.type, authenticatorAttachment: r.authenticatorAttachment,
        clientExtensionResults: extensions, response: clean };
    }
  }
  return out;
};
const send = (m, id) => {
  const r = response(m, id);
  if (r) postMessage(r, location.origin);
};

addEventListener('message', (e) => {
  if (e.source !== window || !e.data) return;
  const { bwliteReq: id, kind } = e.data;
  if (!idOf(id)) return;
  const o = options(kind, e.data.options);
  if (!o) return send({ bwliteRes: id, fallback: true }, id);
  chrome.runtime.sendMessage({ bwliteReq: id, kind, options: o }).then((r) => r && send(r, id), () => send({ bwliteRes: id, fallback: true }, id));
});
chrome.runtime.onMessage.addListener((m) => m?.bwliteRes && send(m, m.bwliteRes));
