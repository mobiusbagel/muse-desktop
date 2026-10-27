// Muse sidebar destinations for the Jump List section tasks (0.5.6).
//
// URL map verified against the live product (2026-10-27):
// the sidebar's Ideas, Goals, Library and Feed sections have real
// routes under muse.ai; Search and the (Muse) Settings overlay do
// not — they open with global keyboard chords inside the web app
// (Ctrl+K and Ctrl+, respectively, from anywhere in Muse).
//
// Two mechanisms, both honest:
// - Sections: navigate the main window (an existing window via
//   loadURL, or a cold-start window created directly at the URL —
//   main.js/mainWindow.js handle the creation side; the decision
//   logic for an existing window lives here).
// - Overlays: send the chord as raw input events
//   (webContents.sendInputEvent) once the page has loaded. No page
//   DOM access, no script injection — input events only, exactly
//   what the user's own keyboard would produce. If the page is
//   still loading we wait for did-finish-load (one-shot) under a
//   timeout; on timeout the chord is skipped and a log line is
//   written rather than firing blind into a half-loaded page.
//
// Dependency-free: every Electron object arrives injected, so the
// whole module is unit-testable in plain Node.
'use strict';

// The section routes (product routes, not personal data).
const SECTION_URLS = {
  ideas: 'https://muse.ai/ideas',
  goals: 'https://muse.ai/goals',
  library: 'https://muse.ai/library',
  feed: 'https://muse.ai/feed',
};

// The URL a section task navigates to, or null for any other task.
function sectionUrlForTask(task) {
  return Object.prototype.hasOwnProperty.call(SECTION_URLS, task) ? SECTION_URLS[task] : null;
}

// Navigate an existing main window to a section task's URL.
// `alreadyRequestedUrl` is the URL the window is known to be
// loading already (the cold-start case: the window was created
// directly at the section URL) — navigating again would just
// restart the load. Returns true when a navigation was issued.
function navigateWindowToSection(win, task, alreadyRequestedUrl) {
  const url = sectionUrlForTask(task);
  if (!url || !win) return false;
  if (alreadyRequestedUrl === url) return false;
  const current =
    win.webContents && typeof win.webContents.getURL === 'function' ? win.webContents.getURL() : '';
  if (current === url) return false;
  win.loadURL(url);
  return true;
}

// The overlay chords, as sendInputEvent modifiers + keyCode. The
// keyCodes are the literal characters Electron expects: 'K' for
// Ctrl+K, ',' for Ctrl+, .
const CHORDS = {
  search: { keyCode: 'K', modifiers: ['control'] },
  'muse-settings': { keyCode: ',', modifiers: ['control'] },
};

// The chord a task fires, or null for any other task.
function chordForTask(task) {
  return Object.prototype.hasOwnProperty.call(CHORDS, task) ? CHORDS[task] : null;
}

// The exact sendInputEvent sequence for a chord: keyDown then
// keyUp, same keyCode and modifiers on both.
function chordInputEvents(chord) {
  return [
    { type: 'keyDown', keyCode: chord.keyCode, modifiers: [...chord.modifiers] },
    { type: 'keyUp', keyCode: chord.keyCode, modifiers: [...chord.modifiers] },
  ];
}

const CHORD_LOAD_TIMEOUT_MS = 15_000;

// sendChordWhenReady({ webContents, chord, timeoutMs, log,
// setTimeoutFn, clearTimeoutFn }) → Promise<true|false>: fires the
// chord's input events once the page is loaded and resolves true;
// when the page is still loading it waits one-shot for
// did-finish-load under the timeout; on timeout it sends nothing,
// logs a line, and resolves false.
function sendChordWhenReady({
  webContents,
  chord,
  timeoutMs = CHORD_LOAD_TIMEOUT_MS,
  log = () => {},
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
}) {
  return new Promise((resolve) => {
    const fire = () => {
      for (const event of chordInputEvents(chord)) webContents.sendInputEvent(event);
      resolve(true);
    };
    if (!webContents.isLoading()) {
      fire();
      return;
    }
    let settled = false;
    const timer = setTimeoutFn(() => {
      if (settled) return;
      settled = true;
      if (typeof webContents.removeListener === 'function') {
        webContents.removeListener('did-finish-load', onLoaded);
      }
      log(
        `[muse-nav] page still loading after ${timeoutMs}ms — chord ` +
          `${chord.modifiers.join('+')}+${chord.keyCode} skipped`,
      );
      resolve(false);
    }, timeoutMs);
    function onLoaded() {
      if (settled) return;
      settled = true;
      clearTimeoutFn(timer);
      fire();
    }
    webContents.once('did-finish-load', onLoaded);
  });
}

module.exports = {
  SECTION_URLS,
  sectionUrlForTask,
  navigateWindowToSection,
  CHORDS,
  chordForTask,
  chordInputEvents,
  CHORD_LOAD_TIMEOUT_MS,
  sendChordWhenReady,
};
