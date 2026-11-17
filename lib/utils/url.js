/**
 * Return a safe, in-application redirect URL derived from `url`, or
 * `undefined` when `url` cannot be safely used.
 *
 * Redirect URLs are often sourced from untrusted input, such as the
 * `returnTo` property of a session.  Such values must not be allowed to
 * redirect the user agent to another application.  To that end, this function
 * accepts:
 *
 *   - path-relative URLs beginning with a single `/` (for example, `/login`)
 *   - absolute `http:` and `https:` URLs, preserving previous behavior
 *
 * Scheme-relative URLs (for example, `//example.com`), URLs containing
 * backslashes (which user agents interpret as path separators), and URLs
 * containing control characters are rejected, as are all other schemes.
 *
 * @param {String} url
 * @return {String}
 * @api public
 */
exports.sanitizeRedirect = function sanitizeRedirect(url) {
  if (typeof url != 'string') { return undefined; }
  
  // Strip surrounding whitespace, which user agents ignore when resolving a
  // URL but which can be used to smuggle a forbidden leading character past
  // naive checks.
  var value = url.replace(/^[\s\x00-\x1f\x7f]+|[\s\x00-\x1f\x7f]+$/g, '');
  if (!value) { return undefined; }
  
  // Control characters anywhere in the URL are not legal in a redirect target
  // and are indicative of an attempt to bypass filters.
  if (/[\x00-\x1f\x7f]/.test(value)) { return undefined; }
  
  // User agents treat backslashes as path separators, so values such as
  // `/\evil.example` navigate to a different origin.
  if (value.indexOf('\\') !== -1) { return undefined; }
  
  // A value beginning with `//` (or `/\`, rejected above) is scheme-relative
  // and resolves against the current scheme to another origin.
  if (value.charAt(0) == '/' && value.charAt(1) == '/') {
    return undefined;
  }
  
  // Path-relative URLs, beginning with a single `/`, always stay within the
  // application's origin.
  if (value.charAt(0) == '/') { return value; }
  
  // Absolute URLs were previously accepted without restriction.  Continue to
  // allow `http:` and `https:` URLs for backwards compatibility, while
  // rejecting every other scheme such as `javascript:` or `data:`.
  if (/^https?:\/\//i.test(value)) { return value; }
  
  return undefined;
};
