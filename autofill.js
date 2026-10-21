// Filling a tab, shared by the popup and background.js (shortcut). The work in the page is inpage.js's bwliteFill.
import { matches } from './bw.js';

// Fills every frame of the tab whose own URL matches the login, so a login form in an iframe is reached but a frame
// from another site never gets the password. code: TOTP to put on the clipboard from the page.
export async function fillTab(tabId, item, equiv, code = null, guard = async () => true, documentId = null) {
  const all = documentId ? { tabId, documentIds: [documentId] } : { tabId, allFrames: true };
  if (!await guard()) return false;
  await chrome.scripting.executeScript({ target: all, files: ['inpage.js'] });
  if (!await guard()) return false;
  const frames = (await chrome.scripting.executeScript({ target: all, func: () => location.href }))
    .filter((r) => /^https?:/.test(r.result) && matches(item, r.result, equiv));
  const res = await Promise.all(frames.map(async ({ frameId, result: href, documentId: frameDocumentId }) => {
    // Lock/revocation and navigation can happen during TOTP generation or
    // while another frame is being injected. Check immediately before each
    // credential handoff as well as inside the page.
    if (!await guard()) return [];
    return chrome.scripting.executeScript({
      target: frameDocumentId ? { tabId, documentIds: [frameDocumentId] } : { tabId, frameIds: [frameId] },
      args: [href, item.username, item.password, code],
      func: (expected, u, p, c) => location.href === expected && bwliteFill(u, p, c), // the frame may have navigated meanwhile
    });
  }));
  return res.some(([r]) => r?.result);
}
