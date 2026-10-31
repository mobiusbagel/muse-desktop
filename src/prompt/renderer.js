// Renderer for the permission prompt. All request data is inserted via
// textContent — never innerHTML — so a crafted path or target string
// cannot inject markup into this page.
'use strict';

const CAPABILITY_LABELS = {
  'fs.list': 'List folder contents',
  'fs.read': 'Read a file',
  'fs.write': 'Write or create files/folders',
  'fs.delete': 'Delete a file or folder',
  'fs.move': 'Move or rename a file or folder',
  'app.launch': 'Launch an application',
  'process.list': 'List running processes',
  'process.kill': 'End a process',
  'shell.run': 'Run a command',
  'screen.capture': 'Take a screenshot',
};

async function init() {
  const request = await window.musePrompt.getRequest();
  const capEl = document.getElementById('capability');
  const detailEl = document.getElementById('detail');
  if (!request) {
    capEl.textContent = 'Unknown request';
    detailEl.textContent = '';
    return;
  }
  capEl.textContent = CAPABILITY_LABELS[request.capability] || request.capability;
  detailEl.textContent = request.detail || '';

  const rememberBox = document.getElementById('remember');
  const rememberLabel = document.getElementById('rememberLabel');
  if (request.capability === 'shell.run') {
    // The detail IS the exact command: render it as a scrollable
    // monospace block, fully viewable, never truncated.
    detailEl.classList.add('command');
    // 0.6.1: shell.run has no capability-level "always allow" — the
    // checkbox remembers THIS EXACT COMMAND ONLY (a shellAllowlist
    // entry). Any different command prompts again.
    rememberLabel.textContent =
      'Remember this exact command — allow it without asking from now on (any different command still asks)';
  }
  document.getElementById('allow').addEventListener('click', () => {
    window.musePrompt.respond({ allowed: true, remember: rememberBox.checked });
  });
  document.getElementById('deny').addEventListener('click', () => {
    window.musePrompt.respond({ allowed: false, remember: false });
  });
}

init();
