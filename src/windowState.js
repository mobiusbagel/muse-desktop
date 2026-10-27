// Persists window size/position/maximized state as JSON in userData and
// restores it on the next launch.
'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULTS = { width: 1400, height: 900 };

class WindowState {
  constructor(filePath) {
    this.filePath = filePath;
    this.data = { ...DEFAULTS };
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (parsed && Number.isFinite(parsed.width) && Number.isFinite(parsed.height)) {
        this.data = { ...DEFAULTS, ...parsed };
      }
    } catch {
      // First run or unreadable file: fall back to defaults.
    }
    this._saveTimer = null;
  }

  /** Bounds suitable for BrowserWindow options (x/y only if finite). */
  get bounds() {
    const { x, y, width, height } = this.data;
    const b = { width, height };
    if (Number.isFinite(x) && Number.isFinite(y)) {
      b.x = x;
      b.y = y;
    }
    return b;
  }

  get isMaximized() {
    return !!this.data.isMaximized;
  }

  /** Drop saved x/y when the window would open (mostly) off-screen,
   *  e.g. after a monitor was unplugged. `displays` = array of rects. */
  sanitizePosition(displays) {
    const b = this.bounds;
    if (b.x === undefined) return;
    const visible = displays.some((d) => {
      const w = Math.min(b.x + b.width, d.x + d.width) - Math.max(b.x, d.x);
      const h = Math.min(b.y + b.height, d.y + d.height) - Math.max(b.y, d.y);
      return w > 100 && h > 100;
    });
    if (!visible) {
      delete this.data.x;
      delete this.data.y;
    }
  }

  track(win) {
    const update = () => {
      if (win.isDestroyed()) return;
      const maximized = win.isMaximized();
      this.data.isMaximized = maximized;
      if (!maximized) Object.assign(this.data, win.getBounds());
      this._scheduleSave();
    };
    win.on('resize', update);
    win.on('move', update);
    win.on('close', () => {
      update();
      this._saveNow();
    });
  }

  _scheduleSave() {
    if (this._saveTimer) return;
    this._saveTimer = setTimeout(() => {
      this._saveTimer = null;
      this._saveNow();
    }, 300);
  }

  _saveNow() {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2));
    } catch (err) {
      console.error('[window-state] save failed:', err.message);
    }
  }
}

module.exports = WindowState;
