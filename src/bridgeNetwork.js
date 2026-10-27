// Bridge network selection (0.3.0, Phase 3 app side; status reasons 0.3.1).
//
// Pure functions over an os.networkInterfaces() result plus, for the
// status line, a small set of caller-supplied probe facts — no OS calls
// in here, so the interface choice and every status string are
// unit-testable without a real Tailscale install:
//
//   findTailscaleAddress(interfaces)              -> "100.x.y.z" | null
//   hasTailscaleAdapter(interfaces)               -> bool
//   getBridgeStatus(enabled, interfaces, port,
//                   probes)                       -> { mode, reason, address, label }
//
// `probes` is { binaryPresent, processRunning } with tri-state values
// (true / false / null-or-undefined = unknown), gathered by the caller
// (src/tailscaleProbe.js) only when remote access is on. They exist so
// the settings line can say *why* no Tailscale address was found —
// not connected vs. not running vs. not installed — instead of the
// pre-0.3.1 shrug. Probes never influence binding: the bridge binds
// loopback plus a found tailnet address, exactly as in 0.3.0.
//
// The bridge only ever binds two kinds of address: loopback (always) and,
// when the user turns remote access on, the machine's Tailscale IPv4 —
// an address in the CGNAT range 100.64.0.0/10 that Tailscale assigns.
// LAN and public addresses are never selected, and nothing here ever
// produces a wildcard bind.
'use strict';

const BRIDGE_PORT = 47631;

// Tailscale assigns IPv4 addresses from 100.64.0.0/10 (RFC 6598 CGNAT):
// second octet 64–127.
function isTailscaleIPv4(address) {
  if (typeof address !== 'string') return false;
  const parts = address.split('.');
  if (parts.length !== 4) return false;
  const octets = parts.map((p) => (/^\d{1,3}$/.test(p) ? Number(p) : NaN));
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  return octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127;
}

// The first usable Tailscale IPv4 across all interfaces, or null.
// `interfaces` is the os.networkInterfaces() shape:
// { name: [{ address, family, internal, ... }, ...], ... }
function findTailscaleAddress(interfaces) {
  if (!interfaces || typeof interfaces !== 'object') return null;
  for (const entries of Object.values(interfaces)) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      if (!entry || entry.internal) continue;
      // Node reports family as 'IPv4' (string) on modern versions.
      if (entry.family !== 'IPv4' && entry.family !== 4) continue;
      if (isTailscaleIPv4(entry.address)) return entry.address;
    }
  }
  return null;
}

// True when an interface is named like Tailscale's adapter ("Tailscale"
// on Windows, "tailscale0" on Linux). Name-based on purpose: the adapter
// can be present — client installed, service ran — while holding no
// tailnet IPv4 at all (logged out / disconnected).
function hasTailscaleAdapter(interfaces) {
  if (!interfaces || typeof interfaces !== 'object') return false;
  return Object.keys(interfaces).some((name) => /tailscale/i.test(name));
}

// Why no tailnet address could be bound, from the strongest signal down:
//   adapter present               -> 'not-connected' (the client is on
//                                    the machine; it just has no live
//                                    tailnet address)
//   a Tailscale process is running-> 'not-connected' (ditto — the tray
//                                    app can run with the service down)
//   client binary on disk only    -> 'not-running' (installed, start it)
//   both probes known-negative    -> 'not-installed'
//   signals missing/inconclusive  -> 'unknown' (pre-0.3.1 callers and
//                                    probe failures land here)
function tailscaleMissingReason(interfaces, probes) {
  if (hasTailscaleAdapter(interfaces)) return 'not-connected';
  if (!probes) return 'unknown';
  if (probes.processRunning === true) return 'not-connected';
  if (probes.binaryPresent === true) return 'not-running';
  if (probes.binaryPresent === false && probes.processRunning === false) return 'not-installed';
  return 'unknown';
}

const MISSING_LABELS = {
  'not-connected': 'Bridge: Tailscale not connected',
  'not-running': 'Bridge: Tailscale not running',
  'not-installed': 'Bridge: Tailscale not installed',
  unknown: 'Bridge: Tailscale not detected',
};

// The one-line bridge status for the settings window.
//   mode: 'local' | 'tailscale' | 'tailscale-missing'
//   reason: null, or for 'tailscale-missing' one of 'not-connected' |
//     'not-running' | 'not-installed' | 'unknown'
//   address: the tailnet IPv4 when mode is 'tailscale', else null
function getBridgeStatus(remoteAccessEnabled, interfaces, port = BRIDGE_PORT, probes = null) {
  if (!remoteAccessEnabled) {
    return { mode: 'local', reason: null, address: null, label: 'Bridge: this PC only' };
  }
  const address = findTailscaleAddress(interfaces);
  if (!address) {
    const reason = tailscaleMissingReason(interfaces, probes);
    return { mode: 'tailscale-missing', reason, address: null, label: MISSING_LABELS[reason] };
  }
  return { mode: 'tailscale', reason: null, address, label: `Bridge: Tailscale — ${address}:${port}` };
}

module.exports = {
  findTailscaleAddress,
  hasTailscaleAdapter,
  tailscaleMissingReason,
  getBridgeStatus,
  isTailscaleIPv4,
  BRIDGE_PORT,
};
