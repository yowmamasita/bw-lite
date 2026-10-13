// Runs before first paint (classic script in <head>) so a light-mode user never sees a dark flash.
try {
  if (localStorage.theme === 'light') document.documentElement.dataset.theme = 'light';
} catch {}
