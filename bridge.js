// Content script: carries page.js's passkey requests to background.js and the answers back into the page.
addEventListener('message', (e) => {
  if (e.source !== window || !e.data?.bwliteReq) return;
  const id = e.data.bwliteReq;
  // An immediate answer (fallback) comes back here; one from the BW Lite window arrives through onMessage.
  chrome.runtime.sendMessage(e.data).then((r) => r && postMessage(r, '*'), () => postMessage({ bwliteRes: id, fallback: true }, '*'));
});
chrome.runtime.onMessage.addListener((m) => m.bwliteRes && postMessage(m, '*'));
