// Renderer for the Bridge Activity window. Entries arrive formatted
// from the main process; every field is inserted via textContent —
// an audit summary can contain a shell command with arbitrary markup
// in it, and it must render as text, never as HTML.
'use strict';

function render(entries) {
  const list = document.getElementById('list');
  list.textContent = '';
  if (!entries || entries.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = 'No bridge activity yet.';
    list.appendChild(empty);
    return;
  }
  for (const entry of entries) {
    const row = document.createElement('div');
    row.className = 'row';
    for (const [cls, text] of [
      ['time', entry.time],
      ['summary', entry.summary],
      ['decision', entry.decision],
      ['outcome', entry.outcome],
    ]) {
      const span = document.createElement('span');
      span.className = cls;
      span.textContent = text || '';
      row.appendChild(span);
    }
    list.appendChild(row);
  }
}

async function refresh() {
  render(await window.museActivity.getEntries());
}

document.getElementById('refresh').addEventListener('click', refresh);
refresh();
