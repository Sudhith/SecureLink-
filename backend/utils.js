/**
 * utils.js — shared helper utilities
 */

/**
 * Validate and normalise a URL string.
 * Returns { valid: boolean, message?: string, url?: string }
 */
export function validateURL(input) {
  if (!input || typeof input !== 'string') {
    return { valid: false, message: 'URL must be a non-empty string.' };
  }

  const trimmed = input.trim();

  if (trimmed.length > 2048) {
    return { valid: false, message: 'URL is too long (max 2048 characters).' };
  }

  // Add scheme if missing
  const withScheme = trimmed.startsWith('http://') || trimmed.startsWith('https://')
    ? trimmed
    : `https://${trimmed}`;

  let parsed;
  try {
    parsed = new URL(withScheme);
  } catch {
    return { valid: false, message: 'Invalid URL format. Example: https://example.com' };
  }

  // Block private/local addresses
  const host = parsed.hostname.toLowerCase();
  const blocklist = ['localhost', '127.0.0.1', '0.0.0.0', '::1'];
  if (blocklist.includes(host)) {
    return { valid: false, message: 'Scanning local/private addresses is not allowed.' };
  }

  // Block non-http(s) schemes
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { valid: false, message: 'Only http and https URLs are supported.' };
  }

  return { valid: true, url: withScheme };
}

/**
 * Sanitise a string for safe logging (strip control chars)
 */
export function sanitise(str) {
  return String(str).replace(/[^\x20-\x7E]/g, '?').slice(0, 500);
}
