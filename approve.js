// The Approve page: the one place a Nuo approval is made, and where an approver sets up their passkey. It is served
// from its own GitHub Pages address (nuo-approve.github.io, the only repo of its own organisation, published from main
// by pull request), so nothing that serves a site's staging copy, Cloudflare included, can change what it shows or
// what it signs. A Pages site under a person's account would share its address with all their other Pages repos.
// A site's staging editor opens it and hands it, by postMessage, what to approve: the page file's text before and
// after, and the commits. That is untrusted data. This page works out the git blob of each text itself, shows the
// field-by-field change from those same bytes, and asks the passkey to sign exactly those blobs (sign.js text()):
// main's code refuses the approval unless they are the live page and the staged one. So what is shown here is what
// goes live; a hostile opener can only drop the answer. Text is only ever set as text, never as markup.
import { text, challenge, blobSha, fields, fingerprint, b64, b64url, bytes, HIDDEN } from './sign.js';
import { SITES } from './sites.js';
// a character that can't be seen or that turns text around, shown as its code instead (main refuses them anyway)
const plainly = t => t.replace(new RegExp(HIDDEN.source, 'gu'), c => `[U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}]`);

const main = document.getElementById('nuo-approve');
const mk = (tag, attrs = {}, t) => { const e = document.createElement(tag); for (const k in attrs) e.setAttribute(k, attrs[k]); if (t != null) e.textContent = t; return e; };
const show = (...n) => { main.replaceChildren(...n); const h = main.querySelector('h1'); if (h) { h.tabIndex = -1; h.focus(); } };
const line = (t, cls) => mk('p', cls ? { class: cls } : {}, t);
const button = (t, f, cls) => { const b = mk('button', { type: 'button', class: cls || '' }, t); b.addEventListener('click', f); return b; };

// never inside another page: a frame could cover what this page shows
if (window.top !== window.self) { document.documentElement.replaceChildren(); throw new Error('framed'); }

let from = null;  // the opener's origin, one of SITES, fixed by its one request
const reply = m => { try { window.opener.postMessage(m, from); } catch {} };
if (window.opener) {
  window.addEventListener('message', e => {
    if (from || !SITES.includes(e.origin) || e.source !== window.opener || !e.data || typeof e.data !== 'object') return;
    from = e.origin;
    if (e.data.kind === 'setup') setup(e.data);
    else if (e.data.kind === 'approve') approve(e.data).catch(() => show(mk('h1', {}, 'Nuo Approve'), line('This request could not be read. Nothing was approved. Close this window and press Approve again.', 'bad')));
  });
  for (const o of SITES) window.opener.postMessage({ nuo: 'approve-ready' }, o);  // reaches the opener only if it is one of SITES
}

function setup(d) {
  const name = String(d.name || '').trim().slice(0, 80) || 'Approver';
  const go = button('Set up my passkey', async () => {
    go.disabled = true; err.textContent = '';
    try {
      const c = await navigator.credentials.create({ publicKey: {
        rp: { id: location.hostname, name: 'Nuo Approve' }, user: { id: crypto.getRandomValues(new Uint8Array(16)), name, displayName: name },
        challenge: crypto.getRandomValues(new Uint8Array(32)), pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }],
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' }, attestation: 'none', timeout: 120000 } });
      const spki = c.response.getPublicKey && c.response.getPublicKey();
      if (!spki) throw new Error('no key');
      const key = b64(spki), out = JSON.stringify({ id: c.id, key });
      const pre = mk('pre', { class: 'key', tabindex: '0', 'aria-label': 'Your passkey’s public half' }, out);
      const copy = button('Copy', () => navigator.clipboard.writeText(out).then(() => { copy.textContent = 'Copied'; }, () => { copy.textContent = 'Select the text and copy it'; }));
      show(mk('h1', {}, 'Your passkey is ready'), line('Send this line to nuordinary. It is only the public half: the passkey itself never leaves your device.'),
        pre, copy, line('Before nuordinary switches it on, they will call you and read out a check code. Say yes only if it is:'),
        mk('p', { class: 'check' }, await fingerprint(key)), line('You can close this window.'));
    } catch { go.disabled = false; err.textContent = 'The passkey wasn’t set up. Try again, and use Face ID, Touch ID or your device’s PIN when asked.'; }
  });
  const err = line('', 'bad');
  show(mk('h1', {}, 'Set up your passkey'),
    line(`This is how you approve changes to your site before they go live. Asked by ${from}.`),
    line('Your phone or laptop makes the passkey and keeps it. You will use Face ID, Touch ID or your device’s PIN each time you approve.'),
    go, err);
}

async function approve(d) {
  const ap = d.approval || {}, was = await blobSha(String(d.was_text)), now = await blobSha(String(d.now_text));
  const a = { repo: ap.repo, page: ap.page, staging: ap.staging, base: ap.base, was, now, approver: ap.approver, time: ap.time };
  if (!text(a) || typeof d.was_text !== 'string' || typeof d.now_text !== 'string') throw new Error('not an approval');
  const f = fields(d.was_text, d.now_text), ids = (Array.isArray(d.passkeys) ? d.passkeys : []).filter(x => typeof x === 'string');
  const dl = mk('dl', { class: 'facts' });
  for (const [k, v] of [['Site', a.repo], ['Page', a.page], ['Asked by', from]]) { dl.append(mk('dt', {}, k), mk('dd', {}, v)); }
  const list = mk('ol', { class: 'changes' });
  for (const x of f) {
    const li = mk('li'); li.append(mk('h2', {}, x.field), mk('p', { class: 'label' }, 'Now on the live site'), mk('p', { class: 'was' }, x.was == null ? '(nothing)' : plainly(x.was)),
      mk('p', { class: 'label' }, 'Goes live'), mk('p', { class: 'now' }, x.now == null ? '(nothing)' : plainly(x.now)));
    list.append(li);
  }
  const err = line('', 'bad');
  if (!f.length) { show(mk('h1', {}, `Nothing changes on ${a.page}`), dl, line('Close this window.')); return; }
  const yes = button('Approve with my passkey', async () => {
    yes.disabled = true; err.textContent = '';
    try {
      const c = await navigator.credentials.get({ publicKey: { challenge: await challenge(a), rpId: location.hostname, userVerification: 'required', timeout: 120000,
        allowCredentials: ids.map(id => ({ type: 'public-key', id: bytes(id) })) } });
      const r = c.response;
      reply({ kind: 'signed', passkey: { id: c.id, auth: b64url(r.authenticatorData), client: b64url(r.clientDataJSON), sig: b64url(r.signature) } });
      show(mk('h1', {}, 'Approved'), line(`Back in the editor, ${a.page} is on its way to the live site. You can close this window.`));
      setTimeout(() => window.close(), 1500);
    } catch { yes.disabled = false; err.textContent = 'The passkey didn’t answer, so nothing was approved. Try again, or close this window.'; }
  }, 'go');
  const no = button('Cancel', () => { reply({ kind: 'cancel' }); window.close(); });
  show(mk('h1', {}, `Approve ${a.page} for the live site`), dl,
    line(f.length === 1 ? 'One change. These are the exact words that go live:' : `${f.length} changes. These are the exact words that go live:`),
    list, line('Your passkey signs this page with these words and nothing else.'), mk('div', { class: 'act' }, null), err);
  main.querySelector('.act').append(yes, no);
}
