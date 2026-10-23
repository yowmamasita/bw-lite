// Runs in the page itself (MAIN world) so it can wrap navigator.credentials. Passkey requests go to BW Lite via
// bridge.js; the answer is a credential, an error, or "fallback" to hand the call to the browser's own passkey UI.
(() => {
  const c = navigator.credentials;
  if (!c || !window.PublicKeyCredential) return;
  const native = { create: c.create.bind(c), get: c.get.bind(c) };
  const bytes = (b) => (ArrayBuffer.isView(b) ? new Uint8Array(b.buffer, b.byteOffset, b.byteLength) : new Uint8Array(b));
  const b64u = (b) => btoa(String.fromCharCode(...bytes(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const buf = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (ch) => ch.charCodeAt(0)).buffer;
  const toJSON = (v) => (v instanceof ArrayBuffer || ArrayBuffer.isView(v) ? b64u(v)
    : Array.isArray(v) ? v.map(toJSON)
    : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, toJSON(x)])) : v);
  // writable: @github/webauthn-json assigns its own credential.toJSON, which throws on a read-only property
  const props = (o) => Object.fromEntries(Object.entries(o).map(([k, value]) => [k, { value, enumerable: true, writable: true, configurable: true }]));

  // Objects with the real prototypes, so `instanceof PublicKeyCredential` holds; own values shadow the native getters.
  function credential(j) {
    const r = j.response;
    const response = r.attestationObject
      ? Object.create(AuthenticatorAttestationResponse.prototype, props({
        clientDataJSON: buf(r.clientDataJSON), attestationObject: buf(r.attestationObject), getTransports: () => r.transports,
        getAuthenticatorData: () => buf(r.authenticatorData), getPublicKey: () => buf(r.publicKey), getPublicKeyAlgorithm: () => r.publicKeyAlgorithm,
      }))
      : Object.create(AuthenticatorAssertionResponse.prototype, props({
        clientDataJSON: buf(r.clientDataJSON), authenticatorData: buf(r.authenticatorData), signature: buf(r.signature),
        userHandle: r.userHandle ? buf(r.userHandle) : null,
      }));
    return Object.create(PublicKeyCredential.prototype, props({
      id: j.id, rawId: buf(j.rawId), type: j.type, authenticatorAttachment: j.authenticatorAttachment, response,
      getClientExtensionResults: () => j.clientExtensionResults, toJSON: () => j,
    }));
  }

  // ponytail: an AbortSignal on the request is ignored; the BW Lite window stays open until answered or closed.
  const ask = (kind, publicKey) => new Promise((resolve) => {
    const id = crypto.randomUUID();
    const done = (r) => (removeEventListener('message', on), clearTimeout(t), resolve(r));
    const on = (e) => e.source === window && e.data?.bwliteRes === id && done(e.data);
    const t = setTimeout(() => done({ error: { name: 'NotAllowedError', message: 'Timed out' } }), publicKey.timeout || 300e3);
    addEventListener('message', on);
    postMessage({ bwliteReq: id, kind, options: toJSON(publicKey) }, '*');
  });

  // Passkey autofill (mediation: conditional) stays with the browser.
  const wrap = (kind) => async function (o) {
    if (!o?.publicKey || o.mediation === 'conditional') return native[kind](o);
    const r = await ask(kind, o.publicKey);
    if (r.fallback) return native[kind](o);
    if (r.error) throw new DOMException(r.error.message, r.error.name);
    return credential(r.result);
  };
  c.create = wrap('create');
  c.get = wrap('get');
})();
