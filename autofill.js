// Filling a tab, shared by the popup and background.js (shortcut). The work in the page is inpage.js's bwliteFill.
import { matches } from './bw.js';

// Fills every frame of the tab whose own URL matches the login, so a login form in an iframe is reached but a frame
// from another site never gets the password. code: TOTP to put on the clipboard from the page.
export async function fillTab(tabId, item, equiv, code = null) {
  const all = { tabId, allFrames: true };
  await chrome.scripting.executeScript({ target: all, files: ['inpage.js'] });
  const frames = (await chrome.scripting.executeScript({ target: all, func: () => location.href }))
    .filter((r) => /^https?:/.test(r.result) && matches(item, r.result, equiv));
  const res = await Promise.all(frames.map(({ frameId, result: href }) => chrome.scripting.executeScript({
    target: { tabId, frameIds: [frameId] }, args: [href, item.username, item.password, code],
    func: (href, u, p, c) => location.href === href && bwliteFill(u, p, c), // the frame may have navigated meanwhile
  })));
  return res.some(([r]) => r?.result);
}
