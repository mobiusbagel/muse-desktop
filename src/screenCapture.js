// Screenshot capture for the Local Bridge (`screen.capture`, 0.5.1).
//
// Electron-free by design (same injection pattern as rpc.js /
// updater.js): the OS-level capturer is injected, so the whole module
// — parameter validation, display selection, downscale math — is
// unit-testable in plain Node with a fake capturer. main.js wires the
// real one from Electron's desktopCapturer.getSources.
//
// The capture contract:
//   params (all optional): displayIndex (default 0 = the first screen
//     source), maxWidth (default 2560; a wider capture is downscaled
//     proportionally; a narrower one is NEVER upscaled).
//   result: { format: 'png', width, height, displayIndex, dataBase64 }
//     — the PNG bytes of the final image, base64-encoded; width/height
//     are the FINAL image's dimensions (after any downscale).
//
// Errors are ScreenCaptureError with a stable `.code`; rpc.js maps
// them onto RpcError so the client sees the usual error shape.
// Invalid parameters are a clean `invalid_params` — never a crash.
'use strict';

const DEFAULT_DISPLAY_INDEX = 0;
const DEFAULT_MAX_WIDTH = 2560;
// Bounds for maxWidth: below 16 px a "screenshot" is a thumbnail of a
// thumbnail; above 16384 no real display exists to capture. Anything
// outside is treated as a caller bug, not clamped silently — the
// caller should learn its parameter was absurd.
const MIN_MAX_WIDTH = 16;
const MAX_MAX_WIDTH = 16384;

class ScreenCaptureError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ScreenCaptureError';
    this.code = code;
  }
}

function invalidParams(message) {
  return new ScreenCaptureError('invalid_params', message);
}

// Validate + normalize the (all-optional) capture params. Throws
// invalid_params on anything non-integer or out of bounds.
function validateCaptureParams(params = {}) {
  const raw = params && typeof params === 'object' ? params : {};
  const displayIndex = raw.displayIndex === undefined ? DEFAULT_DISPLAY_INDEX : raw.displayIndex;
  const maxWidth = raw.maxWidth === undefined ? DEFAULT_MAX_WIDTH : raw.maxWidth;
  if (!Number.isInteger(displayIndex) || displayIndex < 0) {
    throw invalidParams('screen.capture "displayIndex" must be a non-negative integer.');
  }
  if (!Number.isInteger(maxWidth) || maxWidth < MIN_MAX_WIDTH || maxWidth > MAX_MAX_WIDTH) {
    throw invalidParams(
      `screen.capture "maxWidth" must be an integer between ${MIN_MAX_WIDTH} and ${MAX_MAX_WIDTH}.`,
    );
  }
  return { displayIndex, maxWidth };
}

// The one-line summary the permission prompt shows. Display numbers
// are 1-based for humans (displayIndex 0 is "display 1"), and the
// defaults are filled in so the user sees the effective request.
function describeCaptureRequest(params = {}) {
  let normalized;
  try {
    normalized = validateCaptureParams(params);
  } catch {
    normalized = { displayIndex: DEFAULT_DISPLAY_INDEX, maxWidth: DEFAULT_MAX_WIDTH };
  }
  return `Take a screenshot — display ${normalized.displayIndex + 1}, up to ${normalized.maxWidth}px wide`;
}

// Downscale math: proportional, width-driven, never upscales. The
// height follows the aspect ratio, rounded, floored at 1 px.
function computeScaledSize(nativeWidth, nativeHeight, maxWidth) {
  if (nativeWidth <= maxWidth) {
    return { width: nativeWidth, height: nativeHeight, scaled: false };
  }
  return {
    width: maxWidth,
    height: Math.max(1, Math.round((nativeHeight * maxWidth) / nativeWidth)),
    scaled: true,
  };
}

// getSources is injected: (options) => Promise<source[]>, where each
// source's `thumbnail` is a NativeImage-shaped object
// ({ getSize(), isEmpty(), resize({width, height}), toPNG() }).
function createScreenCapture({ getSources } = {}) {
  if (typeof getSources !== 'function') {
    throw new TypeError('createScreenCapture requires a getSources function.');
  }

  async function captureScreen(params = {}) {
    const { displayIndex, maxWidth } = validateCaptureParams(params);

    let sources;
    try {
      // The thumbnail bound is maxWidth x maxWidth: Electron fits the
      // capture inside it, and the module's own downscale below then
      // guarantees the contract even if a source comes back wider
      // than requested.
      sources = await getSources({ types: ['screen'], thumbnailSize: { width: maxWidth, height: maxWidth } });
    } catch (err) {
      throw new ScreenCaptureError(
        'tool_failed',
        `Screen capture failed: ${err && err.message ? err.message : String(err)}`,
      );
    }
    if (!Array.isArray(sources) || sources.length === 0) {
      throw new ScreenCaptureError('no_screens', 'No screens are available to capture.');
    }
    if (displayIndex >= sources.length) {
      throw invalidParams(
        `screen.capture "displayIndex" ${displayIndex} is out of range: ${sources.length} screen(s) available.`,
      );
    }

    const image = sources[displayIndex] && sources[displayIndex].thumbnail;
    if (!image || (typeof image.isEmpty === 'function' && image.isEmpty())) {
      throw new ScreenCaptureError('tool_failed', 'The screen capture came back empty.');
    }
    const native = image.getSize();
    if (!native || !(native.width > 0) || !(native.height > 0)) {
      throw new ScreenCaptureError('tool_failed', 'The screen capture came back with no size.');
    }

    const target = computeScaledSize(native.width, native.height, maxWidth);
    let finalImage = image;
    if (target.scaled) {
      const resized = image.resize({ width: target.width, height: target.height });
      // NativeImage.resize returns a new image; a capturer that
      // resizes in place and returns nothing is honored too.
      if (resized && typeof resized.toPNG === 'function') finalImage = resized;
    }
    const png = finalImage.toPNG();
    return {
      format: 'png',
      width: target.width,
      height: target.height,
      displayIndex,
      dataBase64: Buffer.from(png).toString('base64'),
    };
  }

  return captureScreen;
}

module.exports = {
  ScreenCaptureError,
  DEFAULT_DISPLAY_INDEX,
  DEFAULT_MAX_WIDTH,
  MIN_MAX_WIDTH,
  MAX_MAX_WIDTH,
  validateCaptureParams,
  describeCaptureRequest,
  computeScaledSize,
  createScreenCapture,
};
