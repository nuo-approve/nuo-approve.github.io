// Approvals: made with the approver's own passkey on the Approve page (approve/, served from its own GitHub Pages
// address, never by Cloudflare), checked by the staging Worker before it takes the nuo-live lock and again by the
// workflows that put the change live (live/nuo_live.mjs imports this same file; the Approve page carries a copy).
// No approval key lives in Cloudflare or GitHub: each approver's public key is in main's roles.json ("passkeys"),
// which only a pull request to main changes, and the private half never leaves their device.
// The signed text is one fixed form, never JSON: which site, which page, which staging commit, on which main commit,
// the page file's git blob before and after (so what the Approve page showed is exactly what goes live), who, when.
// The passkey signs a challenge of SHA-256(text). Once main moves past `base` the approval is spent.
export const MAX_AGE = 1800;
const enc = new TextEncoder();
const SHA = /^[0-9a-f]{40}$/, HASH = /^[0-9a-f]{64}$/, PAGE = /^[a-z-]+(?:\/[a-z-]+)?$/, REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
export const bytes = s => Uint8Array.from(atob(String(s).replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
export const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
export const b64url = b => b64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const sha256 = async b => new Uint8Array(await crypto.subtle.digest('SHA-256', typeof b === 'string' ? enc.encode(b) : b));

// The Approve page's origin, from nuo.config.json's approve_url, or null when it isn't one an approval can trust.
// The passkey answers any page on that origin, so it must be the Approve page's alone: a *.github.io address only at
// its root (the <org>.github.io repo of an org that holds nothing else; a project path like user.github.io/repo shares
// the origin with every other Pages repo of that account). A custom domain must not have its DNS on Cloudflare.
export function approveOrigin(url) {
  let u; try { u = new URL(url); } catch { return null; }
  if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash || u.port || u.hostname.endsWith('.')) return null;
  if (u.hostname.endsWith('.github.io') && u.pathname !== '/') return null;
  if (/\.(pages|workers)\.dev$/.test(u.hostname)) return null;  // Cloudflare's own addresses
  return u.origin;
}
// Text that can't be seen, or that turns text around on screen: refused in anything approved, so the Approve page
// shows what the bytes say
export const HIDDEN = /[\p{Cf}\p{Co}\u034F\u115F\u1160\u180E\u3164\uFE00-\uFE0F\uFFA0\u{E0100}-\u{E01EF}]/u;

// a: {repo, page, staging, base, was, now, approver, time}; null if any part is out of form
export function text(a) {
  if (!REPO.test(a.repo || '') || !PAGE.test(a.page || '') || ![a.staging, a.base, a.was, a.now].every(s => SHA.test(s || ''))
      || !HASH.test(a.approver || '') || !Number.isInteger(a.time) || a.time <= 0) return null;
  return ['nuo-approve-v2', a.repo, a.page, a.staging, a.base, a.was, a.now, a.approver, String(a.time)].join('\n');
}
export const challenge = async a => sha256(text(a));

// Who approved, as the SHA-256 of their sign-in email (lowercased): checkable against roles.json, never the email
export async function approverId(email) { return hex(await sha256(String(email).trim().toLowerCase())); }

// A file's git blob id from its text: what git, GitHub and the Approve page all compute from the same bytes
export async function blobSha(t) {
  const b = enc.encode(t), h = enc.encode(`blob ${b.length}\0`), all = new Uint8Array(h.length + b.length);
  all.set(h); all.set(b, h.length);
  return hex(await crypto.subtle.digest('SHA-1', all));
}

// A passkey's public key as roles.json holds it (SPKI, base64): P-256 (ES256) or Ed25519, nothing else
const P256 = '3059301306072a8648ce3d020106082a8648ce3d030107034200', ED = '302a300506032b6570032100';
export function keyKind(k) {
  let b; try { b = bytes(k); } catch { return null; }
  const h = hex(b);
  return h.startsWith(P256) && b.length === 91 ? 'ES256' : h.startsWith(ED) && b.length === 44 ? 'Ed25519' : null;
}

// What nuordinary reads out on the phone before adding a passkey to roles.json: 8 hex characters of SHA-256 over the
// whole key, so a key swapped on the way (by email, say) shows a different code
export async function fingerprint(k) { const h = hex(await sha256(bytes(k))); return h.slice(0, 4) + ' ' + h.slice(4, 8); }

// An ES256 signature comes as DER; Web Crypto wants r and s side by side, 32 bytes each
function raw(der) {
  const d = new Uint8Array(der); let i = 0;
  const take = () => { if (d[i++] !== 0x02) throw 0; const n = d[i++]; let v = d.slice(i, i + n); i += n;
    while (v.length > 32 && v[0] === 0) v = v.slice(1); if (v.length > 32) throw 0; const o = new Uint8Array(32); o.set(v, 32 - v.length); return o; };
  if (d[i++] !== 0x30 || d[i++] !== d.length - 2) throw 0;
  const r = take(), s = take(); if (i !== d.length) throw 0;
  const o = new Uint8Array(64); o.set(r); o.set(s, 32); return o;
}

// true only when x = {id, auth, client, sig} (base64url, as the Approve page hands them back) is this passkey's
// assertion over exactly approval a: a WebAuthn "get" from the Approve page's origin, not framed, for its host,
// the person present and verified (Face ID, Touch ID or the device's PIN), no older than maxAge, not from the future.
export async function assertion(key, a, x, { origin, now = Math.floor(Date.now() / 1000), maxAge = MAX_AGE } = {}) {
  const kind = keyKind(key), t = text(a);
  if (!kind || !t || !origin || !x || typeof x !== 'object' || ![x.auth, x.client, x.sig].every(s => typeof s === 'string' && /^[A-Za-z0-9_-]{1,4096}$/.test(s))) return false;
  if (a.time > now + 60 || now - a.time > maxAge) return false;
  try {
    const auth = bytes(x.auth), client = bytes(x.client), c = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(client));
    if (c.type !== 'webauthn.get' || c.origin !== origin || c.crossOrigin === true || c.topOrigin !== undefined) return false;
    if (c.challenge !== b64url(await sha256(t))) return false;
    if (auth.length < 37 || hex(auth.slice(0, 32)) !== hex(await sha256(new URL(origin).hostname))) return false;
    if ((auth[32] & 0x05) !== 0x05) return false;  // UP (present) and UV (verified)
    const signed = new Uint8Array(auth.length + 32); signed.set(auth); signed.set(await sha256(client), auth.length);
    const alg = kind === 'ES256' ? { name: 'ECDSA', namedCurve: 'P-256' } : { name: 'Ed25519' };
    const k = await crypto.subtle.importKey('spki', bytes(key), alg, false, ['verify']);
    const sig = kind === 'ES256' ? raw(bytes(x.sig)) : bytes(x.sig);
    return await crypto.subtle.verify(kind === 'ES256' ? { name: 'ECDSA', hash: 'SHA-256' } : { name: 'Ed25519' }, k, sig, signed);
  } catch { return false; }
}

// every text in a page file by its field path, as _editable.json names them
export function flat(d, pre = '', out = {}) {
  if (typeof d === 'string') out[pre] = d;
  else if (d && typeof d === 'object') for (const [k, v] of Object.entries(d)) flat(v, pre ? pre + '.' + k : k, out);
  return out;
}
// what changed in a page file, field by field: [{field, was, now}] (null for a field that is new or gone)
export function fields(wasText, nowText) {
  const was = flat(JSON.parse(wasText ?? '{}')), now = flat(JSON.parse(nowText));
  return [...new Set([...Object.keys(was), ...Object.keys(now)])].filter(k => was[k] !== now[k]).map(k => ({ field: k, was: was[k] ?? null, now: now[k] ?? null }));
}
