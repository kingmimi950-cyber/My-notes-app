(function(){
  'use strict';

  const API = '/api';
  let token = localStorage.getItem('fn_token') || null;
  let userEmail = localStorage.getItem('fn_email') || null;
  let cryptoSalt = localStorage.getItem('fn_salt') || null;

  let entries = [];
  let selectedId = null;
  let searchQuery = '';
  let activeTag = null;
  let dateFilter = null; // 'YYYY-MM-DD'
  let saveTimer = null;
  let previewMode = false;
  let authMode = 'login'; // or 'register'

  // In-memory only — never persisted.
  let sessionKey = null;               // CryptoKey, once passphrase is verified
  const decryptedCache = {};           // entryId -> { title, body }
  const pendingUnlockErrors = {};      // entryId -> error message shown once

  let calState = new Date();

  // ===================================================================
  // Crypto helpers (Web Crypto — passphrase never leaves the browser)
  // ===================================================================
  function hexToBytes(hex){
    const bytes = new Uint8Array(hex.length / 2);
    for(let i=0;i<hex.length;i+=2) bytes[i/2] = parseInt(hex.substr(i,2),16);
    return bytes;
  }
  function bufToB64(buf){
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }
  function b64ToBuf(b64){
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for(let i=0;i<bin.length;i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }
  async function deriveKey(passphrase){
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(passphrase), {name:'PBKDF2'}, false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name:'PBKDF2', salt: hexToBytes(cryptoSalt), iterations:100000, hash:'SHA-256' },
      keyMaterial,
      { name:'AES-GCM', length:256 },
      false,
      ['encrypt','decrypt']
    );
  }
  async function encryptPayload(key, obj){
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode(JSON.stringify(obj));
    const cipherBuf = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, data);
    return { data: bufToB64(cipherBuf), iv: bufToB64(iv) };
  }
  async function decryptPayload(key, dataB64, ivB64){
    const cipherBuf = b64ToBuf(dataB64);
    const iv = new Uint8Array(b64ToBuf(ivB64));
    const plainBuf = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, cipherBuf);
    return JSON.parse(new TextDecoder().decode(plainBuf));
  }

  // ===================================================================
  // API helpers
  // ===================================================================
  async function api(path, opts = {}){
    const headers = Object.assign({}, opts.headers || {});
    if(!(opts.body instanceof FormData)) headers['Content-Type'] = 'application/json';
    if(token) headers['Authorization'] = 'Bearer ' + token;
    const res = await fetch(API + path, Object.assign({}, opts, { headers }));
    const isJson = (res.headers.get('content-type') || '').includes('application/json');
    const body = isJson ? await res.json() : null;
    if(!res.ok) throw new Error((body && body.error) || 'Request failed');
    return body;
  }

  // ===================================================================
  // Auth
  // ===================================================================
  const authScreen = document.getElementById('authScreen');
  const appRoot = document.getElementById('appRoot');
  const authForm = document.getElementById('authForm');
  const authError = document.getElementById('authError');
  const authSub = document.getElementById('authSub');
  const authSubmit = document.getElementById('authSubmit');
  const authSwitchText = document.getElementById('authSwitchText');
  const authSwitchBtn = document.getElementById('authSwitchBtn');

  function setAuthMode(mode){
    authMode = mode;
    authError.textContent = '';
    if(mode === 'login'){
      authSub.textContent = 'Sign in to your journal';
      authSubmit.textContent = 'Sign in';
      authSwitchText.textContent = 'New here?';
      authSwitchBtn.textContent = 'Create an account';
    } else {
      authSub.textContent = 'Start your journal';
      authSubmit.textContent = 'Create account';
      authSwitchText.textContent = 'Already have an account?';
      authSwitchBtn.textContent = 'Sign in';
    }
  }
  authSwitchBtn.addEventListener('click', () => setAuthMode(authMode === 'login' ? 'register' : 'login'));

  authForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    authError.textContent = '';
    const email = document.getElementById('authEmail').value.trim();
    const password = document.getElementById('authPassword').value;
    authSubmit.disabled = true;
    try{
      const path = authMode === 'login' ? '/auth/login' : '/auth/register';
      const res = await api(path, { method:'POST', body: JSON.stringify({ email, password }) });
      token = res.token; userEmail = res.email; cryptoSalt = res.cryptoSalt;
      localStorage.setItem('fn_token', token);
      localStorage.setItem('fn_email', userEmail);
      localStorage.setItem('fn_salt', cryptoSalt);
      await boot();
    }catch(e){
      authError.textContent = e.message;
    }finally{
      authSubmit.disabled = false;
    }
  });

  document.getElementById('logoutBtn').addEventListener('click', () => {
    confirmDialog('Sign out of Fieldnotes on this device?', () => {
      localStorage.removeItem('fn_token');
      localStorage.removeItem('fn_email');
      localStorage.removeItem('fn_salt');
      token = null; userEmail = null; cryptoSalt = null; sessionKey = null;
      entries = []; selectedId = null;
      Object.keys(decryptedCache).forEach(k => delete decryptedCache[k]);
      appRoot.classList.add('hidden');
      authScreen.classList.remove('hidden');
      authForm.reset();
      setAuthMode('login');
    }, 'Sign out', false);
  });

  // ===================================================================
  // Theme
  // ===================================================================
  function applyTheme(theme){
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('fn_theme', theme);
  }
  document.getElementById('themeToggle').addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    applyTheme(current === 'dark' ? 'light' : 'dark');
  });
  applyTheme(localStorage.getItem('fn_theme') || 'dark');

  // ===================================================================
  // Entry helpers
  // ===================================================================
  function formatDate(ts){
    return new Date(ts).toLocaleDateString(undefined, { month:'short', day:'numeric', year:'numeric' });
  }
  function formatDateShort(ts){
    return new Date(ts).toLocaleDateString(undefined, { month:'short', day:'numeric' });
  }
  function dayKey(ts){
    const d = new Date(ts);
    return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
  }
  function escapeHtml(str){
    const div = document.createElement('div');
    div.textContent = str == null ? '' : str;
    return div.innerHTML;
  }
  function wordCount(text){
    const t = (text||'').trim();
    return t ? t.split(/\s+/).length : 0;
  }
  function displayFields(e){
    // Returns the plaintext-visible {title, body} for an entry, using
    // the decrypted cache when available, or placeholders when locked.
    if(!e.encrypted) return { title: e.title, body: e.body, locked:false };
    if(decryptedCache[e.id]) return { title: decryptedCache[e.id].title, body: decryptedCache[e.id].body, locked:false };
    return { title: '', body: '', locked:true };
  }

  async function tryOpportunisticDecrypt(){
    if(!sessionKey) return;
    for(const e of entries){
      if(e.encrypted && !decryptedCache[e.id]){
        try{
          const payload = await decryptPayload(sessionKey, e.body, e.iv);
          decryptedCache[e.id] = { title: payload.title, body: payload.body };
        }catch(err){ /* wrong key for this entry's era — leave locked */ }
      }
    }
  }

  async function loadEntries(){
    entries = await api('/entries');
    await tryOpportunisticDecrypt();
  }

  function allTags(){
    const s = new Set();
    entries.forEach(e => e.tags.forEach(t => s.add(t)));
    return Array.from(s).sort();
  }

  function filteredEntries(){
    return entries.filter(e => {
      if(activeTag && !e.tags.includes(activeTag)) return false;
      if(dateFilter && dayKey(e.created) !== dateFilter) return false;
      if(searchQuery){
        const q = searchQuery.toLowerCase();
        const { title, body, locked } = displayFields(e);
        if(locked) return false; // can't search inside content we can't read
        return title.toLowerCase().includes(q) || body.toLowerCase().includes(q);
      }
      return true;
    }).sort((a,b) => b.updated - a.updated);
  }

  // ===================================================================
  // Entry CRUD
  // ===================================================================
  async function createEntry(){
    const now = Date.now();
    const optimistic = { id:'tmp-'+now, title:'', body:'', tags:[], attachments:[], encrypted:false, iv:null, created:now, updated:now };
    entries.unshift(optimistic);
    selectedId = optimistic.id;
    render();
    try{
      const saved = await api('/entries', { method:'POST', body: JSON.stringify({ title:'', body:'', tags:[], attachments:[] }) });
      const idx = entries.findIndex(x => x.id === optimistic.id);
      entries[idx] = saved;
      selectedId = saved.id;
      render();
      focusTitle();
    }catch(e){
      entries = entries.filter(x => x.id !== optimistic.id);
      selectedId = null;
      render();
      confirmDialog('Could not create entry: ' + e.message, () => {}, 'OK', false);
    }
  }

  async function persistEntry(id, patch){
    const e = entries.find(x => x.id === id);
    if(!e) return;
    Object.assign(e, patch, { updated: Date.now() });
    try{
      const saved = await api('/entries/' + id, { method:'PUT', body: JSON.stringify(patch) });
      Object.assign(e, saved);
      return true;
    }catch(err){
      return false;
    }
  }

  async function deleteEntry(id){
    entries = entries.filter(x => x.id !== id);
    delete decryptedCache[id];
    if(selectedId === id) selectedId = null;
    renderSidebarOnly();
    renderPage();
    try{ await api('/entries/' + id, { method:'DELETE' }); }
    catch(e){ /* already removed from UI; a background sync would restore it */ }
  }

  // ===================================================================
  // Rendering — sidebar
  // ===================================================================
  function renderSidebarOnly(){
    const list = document.getElementById('entryList');
    const items = filteredEntries();

    document.getElementById('entryCount').textContent = entries.length === 1 ? '1 entry' : entries.length + ' entries';
    document.getElementById('userEmailLabel').textContent = userEmail || '';

    const banner = document.getElementById('dateFilterBanner');
    if(dateFilter){
      banner.classList.remove('hidden');
      document.getElementById('dateFilterLabel').textContent = new Date(dateFilter + 'T00:00:00').toLocaleDateString(undefined, { month:'short', day:'numeric', year:'numeric' });
    } else {
      banner.classList.add('hidden');
    }

    if(items.length === 0){
      list.innerHTML = entries.length === 0
        ? `<div class="empty-list">No entries yet.<br>Start with “New entry.”</div>`
        : `<div class="empty-list">Nothing matches here.</div>`;
    } else {
      list.innerHTML = items.map(e => {
        const { title, body, locked } = displayFields(e);
        const displayTitle = locked ? 'Locked entry' : (title.trim() || 'Untitled');
        const preview = locked ? '' : body.trim().slice(0,80).replace(/\n/g,' ');
        const lockIcon = e.encrypted ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>` : '';
        const tagsHtml = (!locked && e.tags.length) ? `<div class="tags">${e.tags.map(t=>`<span>#${escapeHtml(t)}</span>`).join('')}</div>` : '';
        return `
          <div class="entry-item ${e.id === selectedId ? 'selected' : ''}" data-id="${e.id}" tabindex="0" role="button">
            <div class="row1">
              <span class="title">${lockIcon}${escapeHtml(displayTitle)}</span>
              <span class="date">${formatDateShort(e.updated)}</span>
            </div>
            ${preview ? `<div class="preview">${escapeHtml(preview)}</div>` : ''}
            ${tagsHtml}
          </div>`;
      }).join('');
    }

    list.querySelectorAll('.entry-item').forEach(el => {
      el.addEventListener('click', () => {
        selectedId = el.dataset.id;
        previewMode = false;
        render();
        if(window.innerWidth <= 820) closeSidebar();
      });
      el.addEventListener('keydown', ev => { if(ev.key === 'Enter') el.click(); });
    });

    const tagFilterEl = document.getElementById('tagFilter');
    const tags = allTags();
    tagFilterEl.innerHTML = tags.map(t => `<button class="tag-chip ${activeTag===t?'active':''}" data-tag="${escapeHtml(t)}">#${escapeHtml(t)}</button>`).join('');
    tagFilterEl.querySelectorAll('.tag-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const t = chip.dataset.tag;
        activeTag = activeTag === t ? null : t;
        renderSidebarOnly();
      });
    });
  }

  // ===================================================================
  // Rendering — main page / editor
  // ===================================================================
  function renderPage(){
    const page = document.getElementById('page');
    const e = entries.find(x => x.id === selectedId);

    if(!e){
      page.innerHTML = `
        <div class="no-selection">
          <div class="mark">§</div>
          <h2>Nothing open</h2>
          <p>Choose an entry from the list, or start a fresh page.</p>
        </div>`;
      return;
    }

    const { title, body, locked } = displayFields(e);

    if(locked){
      renderLockedPaper(e);
      return;
    }

    const attachmentsHtml = e.attachments.length ? `
      <div class="attachment-gallery">
        ${e.attachments.map(url => `
          <div class="attachment-thumb" data-url="${escapeHtml(url)}">
            <img src="${escapeHtml(url)}" alt="">
            <button aria-label="Remove photo">×</button>
          </div>`).join('')}
      </div>` : '';

    page.innerHTML = `
      <div class="paper">
        <div class="paper-head">
          <span class="stamp">${formatDate(e.created)}</span>
          <div class="head-actions">
            <button class="icon-btn neutral ${e.encrypted ? 'active' : ''}" id="lockBtn" title="${e.encrypted ? 'Unlock entry' : 'Lock this entry'}" aria-label="Toggle lock">
              ${e.encrypted
                ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>`
                : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V8a4 4 0 0 1 7.4-2"/></svg>`}
            </button>
            <button class="icon-btn" id="deleteBtn" aria-label="Delete entry" title="Delete entry">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
            </button>
          </div>
        </div>
        <textarea class="title-input" id="titleInput" placeholder="Untitled" rows="1" maxlength="140">${escapeHtml(title)}</textarea>
        <div class="tags-input-row" id="tagsRow">
          ${e.tags.map(t => `<span class="tag-pill" data-tag="${escapeHtml(t)}">#${escapeHtml(t)}<button aria-label="Remove tag ${escapeHtml(t)}">×</button></span>`).join('')}
          <input type="text" class="tag-input" id="tagInput" placeholder="+ tag">
        </div>
        <div class="editor-toolbar">
          <button class="toolbar-btn ${!previewMode?'active':''}" id="writeTab">Write</button>
          <button class="toolbar-btn ${previewMode?'active':''}" id="previewTab">Preview</button>
          <button class="toolbar-btn" id="photoBtn">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg>
            Photo
          </button>
          <input type="file" id="photoInput" accept="image/*" class="hidden">
        </div>
        ${previewMode
          ? `<div class="body-preview" id="bodyPreview">${renderMarkdown(body)}</div>`
          : `<textarea class="body-input" id="bodyInput" placeholder="Begin writing… Markdown supported.">${escapeHtml(body)}</textarea>`
        }
        ${attachmentsHtml}
        <div class="paper-foot">
          <span class="wordcount" id="wordcount">${wordCount(body)} words</span>
          <span class="savestate" id="savestate">Saved</span>
        </div>
      </div>
    `;

    autoGrow(document.getElementById('titleInput'));
    wireEditorEvents(e);
  }

  function renderMarkdown(text){
    if(!window.marked || !window.DOMPurify) return escapeHtml(text).replace(/\n/g,'<br>');
    const raw = marked.parse(text || '');
    return DOMPurify.sanitize(raw);
  }

  function renderLockedPaper(e){
    const page = document.getElementById('page');
    const errMsg = pendingUnlockErrors[e.id] || '';
    page.innerHTML = `
      <div class="paper">
        <div class="paper-head">
          <span class="stamp">${formatDate(e.created)}</span>
          <div class="head-actions">
            <button class="icon-btn" id="deleteBtn" aria-label="Delete entry" title="Delete entry">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
            </button>
          </div>
        </div>
        <div class="locked-view">
          <div class="lock-icon"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg></div>
          <p>This entry is locked. Enter your passphrase to view it.</p>
          <div class="lock-error">${escapeHtml(errMsg)}</div>
          <input type="password" id="unlockInput" placeholder="Passphrase" autocomplete="off">
          <button class="unlock-btn" id="unlockBtn">Unlock</button>
        </div>
      </div>`;

    document.getElementById('deleteBtn').addEventListener('click', () => {
      confirmDialog(`Delete this locked entry? This can't be undone.`, () => deleteEntry(e.id));
    });
    const doUnlock = async () => {
      const pass = document.getElementById('unlockInput').value;
      if(!pass) return;
      delete pendingUnlockErrors[e.id];
      try{
        const key = await deriveKey(pass);
        const payload = await decryptPayload(key, e.body, e.iv);
        sessionKey = key;
        decryptedCache[e.id] = { title: payload.title, body: payload.body };
        await tryOpportunisticDecrypt();
        renderSidebarOnly();
        renderPage();
      }catch(err){
        pendingUnlockErrors[e.id] = 'Incorrect passphrase — try again.';
        renderLockedPaper(e);
      }
    };
    document.getElementById('unlockBtn').addEventListener('click', doUnlock);
    document.getElementById('unlockInput').addEventListener('keydown', ev => { if(ev.key === 'Enter') doUnlock(); });
    document.getElementById('unlockInput').focus();
  }

  function wireEditorEvents(e){
    const titleEl = document.getElementById('titleInput');
    const bodyEl = document.getElementById('bodyInput');

    if(titleEl){
      titleEl.addEventListener('input', ev => { autoGrow(ev.target); scheduleSave(e, { title: ev.target.value, body: bodyEl ? bodyEl.value : (decryptedCache[e.id]?.body ?? e.body) }); });
    }
    if(bodyEl){
      bodyEl.addEventListener('input', ev => {
        document.getElementById('wordcount').textContent = wordCount(ev.target.value) + ' words';
        scheduleSave(e, { title: titleEl.value, body: ev.target.value });
      });
    }

    document.getElementById('deleteBtn').addEventListener('click', () => {
      const { title } = displayFields(e);
      confirmDialog(`Delete “${title.trim() || 'Untitled'}”? This can't be undone.`, () => deleteEntry(e.id));
    });

    document.getElementById('lockBtn').addEventListener('click', () => toggleLock(e));

    document.getElementById('writeTab').addEventListener('click', () => { previewMode = false; renderPage(); });
    document.getElementById('previewTab').addEventListener('click', () => { previewMode = true; renderPage(); });

    const photoBtn = document.getElementById('photoBtn');
    const photoInput = document.getElementById('photoInput');
    photoBtn.addEventListener('click', () => photoInput.click());
    photoInput.addEventListener('change', () => handlePhotoUpload(e, photoInput));

    document.querySelectorAll('.attachment-thumb button').forEach(btn => {
      btn.addEventListener('click', (ev) => {
        const url = ev.target.closest('.attachment-thumb').dataset.url;
        removeAttachment(e, url);
      });
    });

    const tagInput = document.getElementById('tagInput');
    tagInput.addEventListener('keydown', (ev) => {
      if(ev.key === 'Enter'){
        ev.preventDefault();
        const val = tagInput.value.trim().toLowerCase().replace(/[^a-z0-9\-_]/g,'');
        if(val && !e.tags.includes(val)){
          e.tags.push(val);
          persistEntry(e.id, { tags: e.tags });
          renderPage(); renderSidebarOnly();
        }
        tagInput.value = '';
      } else if(ev.key === 'Backspace' && tagInput.value === '' && e.tags.length){
        e.tags.pop();
        persistEntry(e.id, { tags: e.tags });
        renderPage(); renderSidebarOnly();
      }
    });
    document.querySelectorAll('#tagsRow .tag-pill button').forEach(btn => {
      btn.addEventListener('click', (ev) => {
        const tag = ev.target.closest('.tag-pill').dataset.tag;
        e.tags = e.tags.filter(t => t !== tag);
        persistEntry(e.id, { tags: e.tags });
        renderPage(); renderSidebarOnly();
      });
    });
  }

  // ===================================================================
  // Save (handles both plaintext and encrypted entries)
  // ===================================================================
  function scheduleSave(e, plaintextPatch){
    const badge = document.getElementById('savestate');
    if(badge){ badge.textContent = 'Saving…'; badge.classList.remove('error'); badge.classList.add('show'); }
    clearTimeout(saveTimer);
    saveTimer = setTimeout(async () => {
      let ok;
      if(e.encrypted && sessionKey){
        decryptedCache[e.id] = { title: plaintextPatch.title, body: plaintextPatch.body };
        try{
          const { data, iv } = await encryptPayload(sessionKey, { title: plaintextPatch.title, body: plaintextPatch.body });
          ok = await persistEntry(e.id, { title:'', body: data, iv, encrypted:true });
        }catch(err){ ok = false; }
      } else {
        ok = await persistEntry(e.id, { title: plaintextPatch.title, body: plaintextPatch.body });
      }
      renderSidebarOnly();
      const b = document.getElementById('savestate');
      if(b){
        if(ok){ b.textContent = 'Saved'; setTimeout(()=>b.classList.remove('show'),900); }
        else { b.textContent = 'Could not save — check connection'; b.classList.add('error'); }
      }
    }, 500);
  }

  // ===================================================================
  // Lock / unlock toggling
  // ===================================================================
  async function toggleLock(e){
    if(e.encrypted){
      // Unlock permanently: requires the content already be decrypted in-session.
      const cached = decryptedCache[e.id];
      if(!cached){ renderPage(); return; } // shouldn't happen from an unlocked view
      const ok = await persistEntry(e.id, { title: cached.title, body: cached.body, encrypted:false, iv:null });
      if(ok){ renderPage(); renderSidebarOnly(); }
      return;
    }

    // Locking for the first time this session — establish the passphrase.
    if(!sessionKey){
      passphraseSetupDialog(async (key) => {
        sessionKey = key;
        await lockEntryWithKey(e, key);
      });
    } else {
      await lockEntryWithKey(e, sessionKey);
    }
  }

  async function lockEntryWithKey(e, key){
    const current = displayFields(e);
    const { data, iv } = await encryptPayload(key, { title: current.title, body: current.body });
    const ok = await persistEntry(e.id, { title:'', body: data, iv, encrypted:true });
    if(ok){
      decryptedCache[e.id] = { title: current.title, body: current.body };
      renderPage(); renderSidebarOnly();
    }
  }

  function passphraseSetupDialog(onReady){
    const overlay = document.createElement('div');
    overlay.className = 'overlay';
    overlay.innerHTML = `
      <div class="confirm-box">
        <p>Set a passphrase to lock entries with. It's used only in your browser to encrypt this entry — Fieldnotes never sees it, and it can't be recovered if you forget it.</p>
        <div class="field"><input type="password" id="pass1" placeholder="Passphrase" autocomplete="new-password"></div>
        <div class="field"><input type="password" id="pass2" placeholder="Confirm passphrase" autocomplete="new-password"></div>
        <div class="hint" id="passHint"></div>
        <div class="row">
          <button id="cancelBtn">Cancel</button>
          <button class="primary" id="confirmBtn">Lock entry</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    overlay.querySelector('#cancelBtn').addEventListener('click', () => overlay.remove());
    overlay.querySelector('#confirmBtn').addEventListener('click', async () => {
      const p1 = overlay.querySelector('#pass1').value;
      const p2 = overlay.querySelector('#pass2').value;
      if(p1.length < 6){ overlay.querySelector('#passHint').textContent = 'Use at least 6 characters.'; return; }
      if(p1 !== p2){ overlay.querySelector('#passHint').textContent = "Passphrases don't match."; return; }
      const key = await deriveKey(p1);
      overlay.remove();
      onReady(key);
    });
  }

  // ===================================================================
  // Photo uploads
  // ===================================================================
  async function handlePhotoUpload(e, input){
    const file = input.files[0];
    if(!file) return;
    const badge = document.getElementById('savestate');
    if(badge){ badge.textContent = 'Uploading photo…'; badge.classList.add('show'); }
    try{
      const form = new FormData();
      form.append('photo', file);
      const res = await api('/upload', { method:'POST', body: form });
      e.attachments = [...e.attachments, res.url];
      await persistEntry(e.id, { attachments: e.attachments });
      renderPage();
    }catch(err){
      confirmDialog('Could not upload photo: ' + err.message, () => {}, 'OK', false);
    }finally{
      input.value = '';
    }
  }

  async function removeAttachment(e, url){
    e.attachments = e.attachments.filter(u => u !== url);
    await persistEntry(e.id, { attachments: e.attachments });
    renderPage();
  }

  // ===================================================================
  // Calendar
  // ===================================================================
  document.getElementById('calendarBtn').addEventListener('click', () => openCalendar());

  function openCalendar(){
    calState = dateFilter ? new Date(dateFilter + 'T00:00:00') : new Date();
    renderCalendarModal();
  }

  function renderCalendarModal(){
    const overlay = document.createElement('div');
    overlay.className = 'overlay';
    overlay.id = 'calOverlay';

    const year = calState.getFullYear();
    const month = calState.getMonth();
    const firstDay = new Date(year, month, 1);
    const startOffset = firstDay.getDay();
    const daysInMonth = new Date(year, month+1, 0).getDate();
    const monthLabel = calState.toLocaleDateString(undefined, { month:'long', year:'numeric' });

    const entryDays = new Set(entries.map(e => dayKey(e.created)));
    const todayKey = dayKey(Date.now());

    let cells = '';
    for(let i=0;i<startOffset;i++) cells += `<button class="cal-day" disabled></button>`;
    for(let d=1; d<=daysInMonth; d++){
      const key = `${year}-${String(month+1).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
      const has = entryDays.has(key);
      cells += `<button class="cal-day in-month ${key===todayKey?'today':''}" data-key="${key}">${d}${has ? '<span class="dot"></span>' : ''}</button>`;
    }

    overlay.innerHTML = `
      <div class="calendar-box">
        <div class="calendar-nav">
          <button id="calPrev" aria-label="Previous month">‹</button>
          <span class="label">${monthLabel}</span>
          <button id="calNext" aria-label="Next month">›</button>
        </div>
        <div class="calendar-grid">
          ${['S','M','T','W','T','F','S'].map(d=>`<div class="wd">${d}</div>`).join('')}
          ${cells}
        </div>
      </div>`;
    document.body.appendChild(overlay);
    overlay.addEventListener('click', ev => { if(ev.target === overlay) overlay.remove(); });
    overlay.querySelector('#calPrev').addEventListener('click', () => { calState = new Date(year, month-1, 1); overlay.remove(); renderCalendarModal(); });
    overlay.querySelector('#calNext').addEventListener('click', () => { calState = new Date(year, month+1, 1); overlay.remove(); renderCalendarModal(); });
    overlay.querySelectorAll('.cal-day.in-month').forEach(btn => {
      btn.addEventListener('click', () => {
        dateFilter = btn.dataset.key;
        overlay.remove();
        renderSidebarOnly();
      });
    });
  }

  document.getElementById('clearDateFilter').addEventListener('click', () => {
    dateFilter = null;
    renderSidebarOnly();
  });

  // ===================================================================
  // Export
  // ===================================================================
  document.getElementById('exportBtn').addEventListener('click', async () => {
    if(entries.length === 0){ confirmDialog('No entries to export yet.', () => {}, 'OK', false); return; }
    await tryOpportunisticDecrypt();
    const skippedLocked = entries.some(e => e.encrypted && !decryptedCache[e.id]);
    const sorted = [...entries].sort((a,b) => a.created - b.created);
    let md = `# Fieldnotes export\n\n_${entries.length} ${entries.length===1?'entry':'entries'} — exported ${new Date().toLocaleString()}_\n\n`;
    if(skippedLocked) md += `_Note: some locked entries were skipped because they haven't been unlocked this session._\n\n`;
    md += `---\n\n`;
    sorted.forEach(e => {
      const { title, body, locked } = displayFields(e);
      if(locked) return;
      md += `## ${title.trim() || 'Untitled'}\n\n`;
      md += `*${formatDate(e.created)}*`;
      if(e.tags.length) md += `  ·  ${e.tags.map(t=>'#'+t).join(' ')}`;
      md += `\n\n${body}\n\n---\n\n`;
    });
    const blob = new Blob([md], { type:'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `fieldnotes-export-${new Date().toISOString().slice(0,10)}.md`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  });

  // ===================================================================
  // Misc UI helpers
  // ===================================================================
  function autoGrow(el){ el.style.height='auto'; el.style.height = el.scrollHeight+'px'; }
  function focusTitle(){ setTimeout(() => { const t=document.getElementById('titleInput'); if(t) t.focus(); }, 30); }
  function closeSidebar(){ document.getElementById('sidebar').classList.remove('open'); }
  function toggleSidebar(){ document.getElementById('sidebar').classList.toggle('open'); }

  function confirmDialog(message, onConfirm, confirmLabel = 'Delete', danger = true){
    const overlay = document.createElement('div');
    overlay.className = 'overlay';
    overlay.innerHTML = `
      <div class="confirm-box">
        <p>${message}</p>
        <div class="row">
          <button id="cancelBtn">${confirmLabel === 'OK' ? 'Close' : 'Cancel'}</button>
          ${confirmLabel !== 'OK' ? `<button class="${danger?'danger':'primary'}" id="confirmBtn">${confirmLabel}</button>` : ''}
        </div>
      </div>`;
    document.body.appendChild(overlay);
    overlay.querySelector('#cancelBtn').addEventListener('click', () => { overlay.remove(); if(confirmLabel==='OK') onConfirm(); });
    const cb = overlay.querySelector('#confirmBtn');
    if(cb) cb.addEventListener('click', () => { overlay.remove(); onConfirm(); });
    overlay.addEventListener('click', ev => { if(ev.target === overlay) overlay.remove(); });
  }

  function render(){ renderSidebarOnly(); renderPage(); }

  document.getElementById('newEntryBtn').addEventListener('click', createEntry);
  document.getElementById('menuToggle').addEventListener('click', toggleSidebar);
  document.getElementById('searchInput').addEventListener('input', ev => { searchQuery = ev.target.value; renderSidebarOnly(); });

  document.addEventListener('keydown', ev => {
    if((ev.metaKey||ev.ctrlKey) && ev.key.toLowerCase()==='k'){ ev.preventDefault(); document.getElementById('searchInput').focus(); }
    if((ev.metaKey||ev.ctrlKey) && ev.key.toLowerCase()==='n'){ ev.preventDefault(); createEntry(); }
  });

  // ===================================================================
  // Boot
  // ===================================================================
  async function boot(){
    authScreen.classList.add('hidden');
    appRoot.classList.remove('hidden');
    document.getElementById('userEmailLabel').textContent = userEmail || '';
    try{
      await loadEntries();
    }catch(e){
      // token likely expired/invalid
      localStorage.removeItem('fn_token'); localStorage.removeItem('fn_email'); localStorage.removeItem('fn_salt');
      token = null;
      appRoot.classList.add('hidden');
      authScreen.classList.remove('hidden');
      return;
    }
    selectedId = entries.length ? entries[0].id : null;
    render();
  }

  if(token && cryptoSalt){
    boot();
  } else {
    setAuthMode('login');
  }
})();
