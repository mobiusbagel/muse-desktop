// Permission prompt service (Phase 2).
// Implements the prompt interface the RPC gate depends on:
//   ask({ capability, method, detail, rememberScope }) -> Promise<{ allowed, alwaysAllow, remember, timedOut? }>
// Each ask opens a small always-on-top window ON THIS PC naming the
// capability and the exact path / command / pid requested. No answer
// within the timeout (60s default) is a denial, as is closing the
// window. Asks are serialized: one prompt at a time, in arrival order.
//
// Structural rule (0.4.0, scoped by 0.6.1): for a never-allow capability
// (shell.run) this service forces the CAPABILITY-level alwaysAllow off
// on EVERY answer it returns — renderer response, timeout, window
// close — via sanitizePromptAnswer. The 0.6.1 "remember" checkbox is
// rendered for every capability, but for shell.run it means "remember
// this exact command" (a shellAllowlist entry), never a silent
// capability; the guarantee lives here and in the dispatcher, not in
// the page.
//
// The window is a LOCAL bundled page (src/prompt/) with the same
// isolation rules as the settings window — nothing here is ever exposed
// to the remote muse.ai page.
'use strict';

const { BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { sanitizePromptAnswer } = require('./permissions');

// If the prompt page cannot load and paint within this window, the ask
// fails closed (denied) instead of leaving a blank window on screen.
const LOAD_TIMEOUT_MS = 15_000;

const PROMPT_PAGE = path.join(__dirname, 'prompt', 'index.html');
const PROMPT_PRELOAD = path.join(__dirname, 'prompt', 'preload.js');

function createPermissionPromptService({ timeoutMs = 60_000 } = {}) {
  let chain = Promise.resolve();
  let current = null; // { request, finish }

  ipcMain.handle('bridge-prompt:get-request', () => (current ? current.request : null));
  ipcMain.on('bridge-prompt:respond', (_event, answer) => {
    if (current) {
      current.finish({
        allowed: Boolean(answer && answer.allowed),
        alwaysAllow: Boolean(answer && answer.alwaysAllow),
        remember: Boolean(answer && answer.remember),
      });
    }
  });

  function showPrompt(request) {
    return new Promise((resolve) => {
      let settled = false;
      let timer = null;
      let loadTimer = null;
      const win = new BrowserWindow({
        width: 480,
        height: 380,
        // Never display the window before its page has painted: showing
        // first raced the load and could leave a blank white prompt on
        // screen (seen live 2026-10-27, twice). Shown on ready-to-show.
        show: false,
        resizable: false,
        minimizable: false,
        maximizable: false,
        alwaysOnTop: true,
        title: 'Muse — Permission Request',
        icon: path.join(__dirname, '..', 'assets', 'icon.png'),
        autoHideMenuBar: true,
        webPreferences: {
          preload: PROMPT_PRELOAD,
          contextIsolation: true,
          nodeIntegration: false,
          sandbox: true,
        },
      });

      const finish = (answer) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        clearTimeout(loadTimer);
        if (current && current.request === request) current = null;
        if (!win.isDestroyed()) win.close();
        // Sanitized on the way out: for shell.run this strips any
        // alwaysAllow, whatever the page (or a tampered page) sent.
        resolve(sanitizePromptAnswer(request.capability, answer));
      };
      current = { request, finish };

      // The answer clock starts when the prompt is actually visible —
      // page-load time is not answer time.
      win.once('ready-to-show', () => {
        clearTimeout(loadTimer);
        loadTimer = null;
        win.show();
        win.focus();
        timer = setTimeout(() => finish({ allowed: false, timedOut: true }), timeoutMs);
      });
      // A page that fails to load, or never paints, denies the ask
      // rather than stranding a blank window until the answer clock.
      win.webContents.on('did-fail-load', () => finish({ allowed: false, timedOut: true }));
      loadTimer = setTimeout(() => finish({ allowed: false, timedOut: true }), LOAD_TIMEOUT_MS);

      win.on('closed', () => {
        // Closing the window without answering is a denial.
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          clearTimeout(loadTimer);
          if (current && current.request === request) current = null;
          resolve(sanitizePromptAnswer(request.capability, { allowed: false }));
        }
      });

      win.loadFile(PROMPT_PAGE);
    });
  }

  function ask(request) {
    const result = chain.then(() => showPrompt(request));
    // Keep the chain alive even if a prompt errors.
    chain = result.then(
      () => {},
      () => {},
    );
    return result;
  }

  return { ask };
}

module.exports = { createPermissionPromptService };
