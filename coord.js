// One shared transaction boundary for every popup/background context.
// Web Locks are shared by extension contexts (Chrome 111 is the minimum
// supported version). The queue is only a fallback for one-context test runs.
const LOCK = 'bwlite:state';
let fallback = Promise.resolve();

export function withStateLock(fn) {
  if (globalThis.navigator?.locks?.request) {
    return navigator.locks.request(LOCK, { mode: 'exclusive' }, fn);
  }
  const job = fallback.catch(() => {}).then(fn);
  fallback = job.catch(() => {});
  return job;
}

// Storage has no compare-and-swap operation. Keeping the read, mutation and
// write in the same Web Lock makes patches from two popup windows commute
// instead of letting a stale full account snapshot overwrite the other one.
export function mutateAccounts(local, mutate) {
  return withStateLock(async () => {
    const stored = await local.get('accounts');
    const current = Array.isArray(stored.accounts) ? structuredClone(stored.accounts) : [];
    const next = await mutate(current);
    if (!Array.isArray(next)) throw new Error('Account update must return an array');
    await local.set({ accounts: next });
    return next;
  });
}
