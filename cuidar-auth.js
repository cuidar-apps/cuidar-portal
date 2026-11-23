/*
 * Cuidar SaaS — shared session across every app.
 *
 * Today every app receives its session as access_token/refresh_token in the URL
 * fragment, then stores it in its own localStorage. Eight origins therefore keep
 * eight independent sessions: refreshing one leaves the others stale, signing out
 * of one leaves the rest signed in, and opening an app directly shows nothing.
 *
 * This module replaces that with one cookie on the parent domain, so every app
 * under .cuidaradistancia.com shares a single session. It also keeps a bridge for
 * the old fragment links during the migration.
 *
 * Works as an ES module and as a classic script (window.CuidarAuth).
 */

const COOKIE_NAME = 'cuidar-saas-session';
const PARENT_DOMAIN = '.cuidaradistancia.com';
const MAX_COOKIE = 3000; // browsers reject >4096 bytes per cookie; encoding inflates the value

function cookieDomainFor(hostname) {
  if (!hostname) return null;
  const h = hostname.toLowerCase();
  return h === 'cuidaradistancia.com' || h.endsWith('.cuidaradistancia.com') ? PARENT_DOMAIN : null;
}

function isSharedHost(hostname) {
  return cookieDomainFor(hostname) !== null;
}

function readRaw(doc, name) {
  const parts = String(doc.cookie || '').split(';');
  for (const part of parts) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) {
      return decodeURIComponent(part.slice(idx + 1));
    }
  }
  return null;
}

function writeRaw(doc, name, value, opts) {
  const bits = [`${name}=${encodeURIComponent(value)}`, 'Path=/'];
  if (opts.domain) bits.push(`Domain=${opts.domain}`);
  bits.push(`Max-Age=${value === '' ? 0 : opts.maxAge}`);
  bits.push(`SameSite=${opts.sameSite}`);
  if (opts.secure) bits.push('Secure');
  doc.cookie = bits.join('; ');
}

/**
 * Storage adapter for supabase-js: createClient(url, key, { auth: { storage } }).
 * supabase passes a storage key ('sb-<ref>-auth-token'); we keep one shared cookie
 * so every app reads the same session.
 */
function createCookieStorage(options = {}) {
  const doc = options.document || (typeof document !== 'undefined' ? document : null);
  const hostname = options.hostname || (typeof location !== 'undefined' ? location.hostname : '');
  const domain = options.domain !== undefined ? options.domain : cookieDomainFor(hostname);
  const maxAge = options.maxAge || 60 * 60 * 24 * 30;
  const secure = options.secure !== false;
  const sameSite = options.sameSite || 'Lax';
  const name = options.name || COOKIE_NAME;

  if (!domain) {
    // Hosts that cannot share the parent cookie (pages.dev previews, workers.dev
    // aliases, localhost) keep a per-origin session instead of failing. A blank
    // page is never an acceptable outcome for a preview URL.
    const key = options.name || COOKIE_NAME;
    const fallback = (options.localStorage) || (typeof localStorage !== 'undefined' ? localStorage : null);
    if (!fallback) throw new Error('createCookieStorage: no cookie domain and no localStorage on ' + (hostname || 'this host'));
    if (typeof console !== 'undefined' && console.warn) {
      console.warn('[cuidar-auth] ' + (hostname || 'this host') + ' cannot share the session cookie; using per-origin storage.');
    }
    return {
      getItem() { return fallback.getItem(key); },
      setItem(_k, v) { fallback.setItem(key, String(v)); },
      removeItem() { fallback.removeItem(key); }
    };
  }

  function read() {
    const count = readRaw(doc, `${name}.count`);
    if (!count) {
      const single = readRaw(doc, name);
      return single === null ? null : single;
    }
    let out = '';
    for (let i = 0; i < Number(count); i++) {
      const part = readRaw(doc, `${name}.${i}`);
      if (part === null) return null; // partial write, treat as absent
      out += part;
    }
    return out;
  }

  function clear() {
    const count = readRaw(doc, `${name}.count`);
    if (count) {
      for (let i = 0; i < Number(count); i++) writeRaw(doc, `${name}.${i}`, '', { domain, maxAge, sameSite, secure });
    }
    writeRaw(doc, `${name}.count`, '', { domain, maxAge, sameSite, secure });
    writeRaw(doc, name, '', { domain, maxAge, sameSite, secure });
  }

  return {
    getItem() {
      return read();
    },
    setItem(_key, value) {
      const str = String(value);
      clear();
      if (str.length <= MAX_COOKIE) {
        writeRaw(doc, name, str, { domain, maxAge, sameSite, secure });
        return;
      }
      const chunks = [];
      for (let i = 0; i < str.length; i += MAX_COOKIE) chunks.push(str.slice(i, i + MAX_COOKIE));
      chunks.forEach((chunk, i) => writeRaw(doc, `${name}.${i}`, chunk, { domain, maxAge, sameSite, secure }));
      writeRaw(doc, `${name}.count`, String(chunks.length), { domain, maxAge, sameSite, secure });
    },
    removeItem() {
      clear();
    }
  };
}

/**
 * One-time bridge for the old fragment handoff: if the URL carries
 * #access_token=…&refresh_token=…, hand it to supabase once and strip the hash
 * so it never lands in history or a shared link.
 */
async function adoptLegacyHash(supabase, win = typeof window !== 'undefined' ? window : null) {
  if (!win || !win.location || !win.location.hash) return null;
  const params = new URLSearchParams(win.location.hash.replace(/^#/, ''));
  const access_token = params.get('access_token');
  const refresh_token = params.get('refresh_token');
  if (!access_token || !refresh_token) return null;
  const { data, error } = await supabase.auth.setSession({ access_token, refresh_token });
  try {
    win.history.replaceState(null, '', win.location.pathname + win.location.search);
  } catch (_) { /* history may be unavailable in tests */ }
  return error ? null : data.session;
}

/**
 * Sign-out that reaches every app: clear the shared cookie, then announce it on
 * localStorage, which fires `storage` events in the other open tabs of the same
 * origin and in same-origin iframes.
 */
async function signOutEverywhere(supabase, { storage, win = typeof window !== 'undefined' ? window : null } = {}) {
  try { await supabase.auth.signOut({ scope: 'global' }); } catch (_) { /* already invalid */ }
  if (storage && storage.removeItem) storage.removeItem();
  try { win.localStorage.setItem('cuidar-signout', String(Date.now())); } catch (_) {}
}

/**
 * Install the shared session into every Supabase client created on this page.
 *
 * Relying on each page to pass `storage` to createClient is what broke: the
 * Cuidadores page kept its own client with a localStorage key and silently saw
 * no session. This wraps createClient so a forgotten option cannot produce a
 * signed-out app on a host where the cookie exists.
 *
 * It intercepts the UMD assignment because this module loads before the CDN.
 */
function installSharedStorage(win) {
  if (!win || win.__cuidarAuthInstalled) return;
  let real = win.supabase;
  const wrap = (lib) => {
    if (!lib || typeof lib.createClient !== 'function' || lib.__cuidarWrapped) return lib;
    const original = lib.createClient.bind(lib);
    lib.createClient = function (url, key, options) {
      const opts = options || {};
      const auth = opts.auth || {};
      if (auth.storage) return original(url, key, opts);
      let storage;
      try { storage = createCookieStorage({ document: win.document, hostname: win.location && win.location.hostname }); }
      catch (e) { return original(url, key, opts); }
      return original(url, key, {
        ...opts,
        auth: { ...auth, storage, persistSession: true, autoRefreshToken: true, detectSessionInUrl: false }
      });
    };
    lib.__cuidarWrapped = true;
    return lib;
  };
  try {
    Object.defineProperty(win, 'supabase', {
      configurable: true,
      get() { return real; },
      set(v) { real = wrap(v); }
    });
  } catch (e) { real = wrap(real); }
  win.__cuidarAuthInstalled = true;
}

const CuidarAuthApi = { COOKIE_NAME, PARENT_DOMAIN, cookieDomainFor, isSharedHost, createCookieStorage, adoptLegacyHash, signOutEverywhere, installSharedStorage };


if (typeof window !== 'undefined') {
  window.CuidarAuth = CuidarAuthApi;
  installSharedStorage(window);
}
