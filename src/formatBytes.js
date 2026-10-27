// Display formatting for byte counts and percentages (0.2.4).
//
// The settings window used to render usage as `(bytes / 2^30).toFixed(2)`
// GB, so real usage of a couple of MB showed as "0.00 GB used" even
// though the percentage next to it was truthful. These helpers format
// from the exact byte count with adaptive units/precision instead:
//
//   formatBytes(2149581)                  -> "2.05 MB"
//   formatBytes(1073741824)               -> "1.00 GB"
//   formatPercent(2149581, 10 * 1024**3)  -> "0.02%"
//
// UMD-style: CommonJS in Node (unit tests, main process) and plain
// globals when loaded via a <script> tag in the local settings page.
// No Electron, no dependencies.
'use strict';

(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.formatBytes = api.formatBytes;
    root.formatPercent = api.formatPercent;
  }
})(typeof window !== 'undefined' ? window : globalThis, () => {
  const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const BASE = 1024;

  // Trim trailing zeros from a toFixed() string, keeping at least
  // `minDecimals` decimal places.
  function trimZeros(fixed, minDecimals) {
    if (!fixed.includes('.')) return fixed;
    const [int, dec] = fixed.split('.');
    let trimmed = dec.replace(/0+$/, '');
    while (trimmed.length < minDecimals) trimmed += '0';
    return trimmed.length > 0 ? `${int}.${trimmed}` : int;
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    if (bytes < BASE) return `${Math.round(bytes)} B`;

    let value = bytes / BASE;
    let unit = 1; // KB
    while (value >= BASE && unit < UNITS.length - 1) {
      value /= BASE;
      unit += 1;
    }
    // GB and up keep 2–3 decimals; KB/MB up to 2, trailing zeros trimmed.
    const render = (v, u) =>
      u >= 3 ? trimZeros(v.toFixed(3), 2) : trimZeros(v.toFixed(2), 0);
    let text = render(value, unit);
    // Rounding can push 1023.999… up to a displayed "1024" — step up a
    // unit so the rendered value stays < 1024 in its unit.
    if (parseFloat(text) >= BASE && unit < UNITS.length - 1) {
      value /= BASE;
      unit += 1;
      text = render(value, unit);
    }
    return `${text} ${UNITS[unit]}`;
  }

  function formatPercent(usedBytes, capBytes) {
    if (
      !Number.isFinite(usedBytes) ||
      !Number.isFinite(capBytes) ||
      capBytes <= 0 ||
      usedBytes <= 0
    ) {
      return '0%';
    }
    const pct = (usedBytes / capBytes) * 100;
    if (pct < 1) {
      // Two significant figures, however small: 0.02%, 0.0031%, …
      const decimals = Math.max(2, Math.ceil(-Math.log10(pct)) + 1);
      return `${trimZeros(pct.toFixed(decimals), 0)}%`;
    }
    // Larger values: up to 2 decimals (12.5%, 47.24%, 250%).
    return `${trimZeros(pct.toFixed(2), 0)}%`;
  }

  return { formatBytes, formatPercent };
});
