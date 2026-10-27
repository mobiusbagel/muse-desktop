// Permission prompt service (Phase 2).
// Implements the prompt interface the RPC gate depends on:
//   ask({ capability, method, detail, canAlwaysAllow }) -> Promise<{ allowed, alwaysAllow, timedOut? }>
// Each ask opens a small always-on-top window ON THIS PC naming the
// capability and the exact path / command / pid requested. No answer
// within the timeout (60s default) is a denial, as is closing the
// window. Asks are serialized: one prompt at a time, in arrival order.
//
// Structural rule (0.4.0): for a never-allow capability (shell.run)
// this service forces alwaysAllow off on EVERY answer it returns —
// renderer response, timeout, window close — via sanitizePromptAnswer.
// The renderer additionally doesn't render the checkbox for such
// requests, but the guarantee lives here, not in the page.
//
// The window is a LOCAL bundled page (src/prompt/) with the same
// isolation rules as the settings window — nothing here is ever exposed
// to the remote muse.ai page.
'use strict';

const { BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { sanitizePromptAnswer } = require('./permissions');

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
      });
    }
  });

  function showPrompt(request) {
    return new Promise((resolve) => {
      let settled = false;
      const win = new BrowserWindow({
        width: 480,
        height: 380,
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
        if (current && current.request === request) current = null;
        if (!win.isDestroyed()) win.close();
        // Sanitized on the way out: for shell.run this strips any
        // alwaysAllow, whatever the page (or a tampered page) sent.
        resolve(sanitizePromptAnswer(request.capability, answer));
      };
      current = { request, finish };

      const timer = setTimeout(() => finish({ allowed: false, timedOut: true }), timeoutMs);

      win.on('closed', () => {
        // Closing the window without answering is a denial.
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          if (current && current.request === request) current = null;
          resolve(sanitizePromptAnswer(request.capability, { allowed: false }));
        }
      });

      win.loadFile(PROMPT_PAGE);
      win.show();
      win.focus();
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
