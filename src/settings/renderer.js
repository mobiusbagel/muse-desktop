// Renderer for the local settings page. Talks to the main process only via
// the window.museSettings bridge from preload.js.
'use strict';

const $ = (id) => document.getElementById(id);
const BYTES_PER_GB = 1024 ** 3;
// formatBytes / formatPercent are globals from ../formatBytes.js
// (loaded before this script in index.html) — adaptive display from the
// exact byte count, so small usage never renders as "0.00 GB".
const cleanErr = (err) =>
  String((err && err.message) || err).replace(/^Error invoking remote method '[^']+':\s*/, '');

// Move-flow errors render as single plain sentences (0.2.4 design rule:
// the move UI carries no explanatory prose — controls and one-line state
// only). The engine's messages are mapped here, in the presentation
// layer; the engine itself is unchanged.
function shortMoveError(text) {
  const msg = String(text || '').split('\n')[0];
  if (/not enough free space/i.test(msg)) return 'Not enough free space there.';
  if (/could not check free space/i.test(msg)) return "Couldn't check free space there.";
  if (/destination is the current/i.test(msg)) return "That's already the current location.";
  if (/inside the (current|destination)/i.test(msg)) {
    return "The Muse folder can't be moved inside itself.";
  }
  if (/already in progress/i.test(msg)) return 'A move is already in progress.';
  if (/exists and is not a folder/i.test(msg)) return "That location isn't a folder.";
  return msg;
}

let state = null;
let pendingDest = null;

function setStatus(msg, isError = false) {
  const el = $('status');
  el.textContent = msg;
  el.className = isError ? 'status error' : 'status';
}

function render() {
  if (!state) return;
  $('folderPath').textContent = state.folder;
  const capBytes = state.maxStorageGB * BYTES_PER_GB;
  const usageEl = $('usageText');
  usageEl.textContent =
    `${formatBytes(state.usedBytes)} used of ${state.maxStorageGB} GB cap ` +
    `(${formatPercent(state.usedBytes, capBytes)})`;
  usageEl.title = `${state.usedBytes.toLocaleString('en-US')} bytes`;
  $('usageBar').style.width =
    `${capBytes > 0 ? Math.min(100, (state.usedBytes / capBytes) * 100) : 0}%`;
  if (document.activeElement !== $('capInput')) $('capInput').value = state.maxStorageGB;
  $('moveBtn').disabled = state.moving;
  $('saveCapBtn').disabled = state.moving;
  $('remoteAccessToggle').checked = !!state.bridgeRemoteAccess;
  $('bridgeStatus').textContent = state.bridgeStatus || '';
  $('appVersionText').textContent = state.appVersion ? `Version ${state.appVersion}` : '';
  $('updateStatusText').textContent = state.updateStatus || '';
  $('autoCheckToggle').checked = !!state.autoCheckUpdates;
  $('checkUpdatesBtn').disabled = state.updateStatus === 'Checking…';
}

async function refresh() {
  state = await window.museSettings.getState();
  render();
}

$('saveCapBtn').addEventListener('click', async () => {
  try {
    state = await window.museSettings.saveCap($('capInput').value);
    render();
    setStatus('Storage cap saved.');
  } catch (err) {
    setStatus(cleanErr(err), true);
  }
});

$('remoteAccessToggle').addEventListener('change', async (event) => {
  try {
    state = await window.museSettings.setRemoteAccess(event.target.checked);
    render();
  } catch (err) {
    setStatus(cleanErr(err), true);
    await refresh();
  }
});

$('checkUpdatesBtn').addEventListener('click', async () => {
  try {
    $('updateStatusText').textContent = 'Checking…';
    $('checkUpdatesBtn').disabled = true;
    state = await window.museSettings.checkUpdates();
    render();
  } catch (err) {
    setStatus(cleanErr(err), true);
    await refresh();
  }
});

$('autoCheckToggle').addEventListener('change', async (event) => {
  try {
    state = await window.museSettings.setAutoCheck(event.target.checked);
    render();
  } catch (err) {
    setStatus(cleanErr(err), true);
    await refresh();
  }
});

$('moveBtn').addEventListener('click', async () => {
  setStatus('');
  let parent;
  try {
    parent = await window.museSettings.pickFolder();
  } catch (err) {
    setStatus(cleanErr(err), true);
    return;
  }
  if (!parent) return; // picker canceled: nothing happens
  // The picker chooses a parent location; the assistant folder is the
  // "Muse" folder inside it. precheckMove resolves and reports it.
  const pre = await window.museSettings.precheckMove(parent);
  if (!pre.ok) {
    setStatus(pre.errors.map(shortMoveError).join('\n'), true);
    return;
  }
  pendingDest = parent;
  // Confirm step: the new location, nothing else. A non-empty Muse
  // folder already there gets one extra line and a Merge button.
  if (pre.needsMergeConfirm) {
    $('confirmText').textContent =
      `That folder already has files.\nNew location:\n${pre.destination}`;
    $('confirmBtn').textContent = 'Merge';
  } else {
    $('confirmText').textContent = `New location:\n${pre.destination}`;
    $('confirmBtn').textContent = 'Move';
  }
  $('confirmBox').classList.remove('hidden');
});

$('confirmBtn').addEventListener('click', () => {
  $('confirmBox').classList.add('hidden');
  startMove();
});

$('confirmCancelBtn').addEventListener('click', () => {
  $('confirmBox').classList.add('hidden');
  pendingDest = null;
  setStatus('Move canceled.');
});

$('cancelMoveBtn').addEventListener('click', () => {
  window.museSettings.cancelMove();
  setStatus('Canceling…');
});

window.museSettings.onProgress((p) => {
  const pct = p.bytesTotal > 0 ? Math.floor((p.bytesDone / p.bytesTotal) * 100) : 100;
  $('progressBar').style.width = `${pct}%`;
  $('progressText').textContent = `${pct}%`;
});

async function startMove() {
  const dest = pendingDest;
  pendingDest = null;
  if (!dest) return;
  $('progressBox').classList.remove('hidden');
  $('progressBar').style.width = '0%';
  $('progressText').textContent = '0%';
  $('moveBtn').disabled = true;
  $('saveCapBtn').disabled = true;
  setStatus('Moving…');
  try {
    const res = await window.museSettings.startMove(dest);
    let msg = `Moved to ${res.to}`;
    if (res.remainsAtOld && res.remainsAtOld.length > 0) {
      msg += `\nCouldn't delete from the old folder:\n${res.remainsAtOld.join('\n')}`;
    }
    setStatus(msg);
  } catch (err) {
    setStatus(shortMoveError(cleanErr(err)), true);
  } finally {
    $('progressBox').classList.add('hidden');
    await refresh();
  }
}

refresh();
