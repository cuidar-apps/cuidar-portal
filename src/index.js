/**
 * Serves the static portal and adds the security headers that the assets
 * layer cannot set on its own.
 */
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://esm.sh https://challenges.cloudflare.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: https:",
  "connect-src 'self' https://fftnffmttuzfftntzzhu.supabase.co https://challenges.cloudflare.com",
  "frame-src https://challenges.cloudflare.com",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join("; ");

const HEADERS = {
  "content-security-policy": CSP,
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "geolocation=(), microphone=(), camera=()",
};

export default {
  async fetch(request, env) {
    const res = await env.ASSETS.fetch(request);
    const out = new Response(res.body, res);
    for (const [k, v] of Object.entries(HEADERS)) out.headers.set(k, v);
    // HTML must not be edge-cached: a stale copy would be served without the
    // headers above and could pin an old build site-wide.
    if ((out.headers.get("content-type") || "").includes("text/html")) {
      out.headers.set("cache-control", "no-store, must-revalidate");
    }
    // The portal is a private app shell; keep it out of search indexes.
    if (!out.headers.has("x-robots-tag")) out.headers.set("x-robots-tag", "noindex, nofollow");
    return out;
  },
};
