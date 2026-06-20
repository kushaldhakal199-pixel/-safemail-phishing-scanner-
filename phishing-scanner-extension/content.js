/**
 * SafeMail Pro v4.0 — Content Script
 * Shows result banner for EVERY email: green=safe, orange=medium, red=high
 * No external API calls. All local, instant.
 */

class SafeMailScanner {
  constructor() {
    this.scanner          = new PhishingScanner();
    this.currentEmailId   = null;
    this.dismissedMap     = new Map();
    this.suspiciousLinks  = new Map();
    this.linkClickHandler = null;
    this.scanTimeout      = null;
    this.observer         = null;
    this.provider         = null;
    this.selectors        = null;
    this.init();
  }

  init() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => setTimeout(() => this.boot(), 1200));
    } else {
      setTimeout(() => this.boot(), 1200);
    }
  }

  boot() {
    this.provider  = this.detectProvider();
    this.selectors = this.getSelectors(this.provider);
    setTimeout(() => this.scan(), 1500);
    this.setupObserver();
    this.setupLinkGuard();
    setInterval(() => this.scan(), 3500);
  }

  // ── Provider detection ─────────────────────────────────────────────
  detectProvider() {
    const h = window.location.hostname;
    if (h.includes('mail.google.com'))                                  return 'gmail';
    if (h.includes('outlook.live.com') || h.includes('outlook.office')) return 'outlook';
    if (h.includes('mail.yahoo.com'))                                   return 'yahoo';
    if (h.includes('mail.proton.me') || h.includes('protonmail.ch'))   return 'protonmail';
    if (h.includes('mail.zoho.com'))                                    return 'zoho';
    if (h.includes('fastmail.com'))                                     return 'fastmail';
    if (h.includes('yandex.'))                                          return 'yandex';
    if (h.includes('mail.aol.com'))                                     return 'aol';
    if (h.includes('icloud.com'))                                       return 'icloud';
    return 'generic';
  }

  getSelectors(p) {
    const map = {
      gmail:      { container: '[role="main"]', body: '.a3s, [role="article"], .ii.gt', sender: '[email], .gD', subject: '.hP, h2[data-thread-perm-id]', attach: '[data-attachment-id], .aZo, [aria-label*="Attachment"]', replyTo: null },
      outlook:    { container: '[role="main"]', body: '[role="article"], .ms-font-m',  sender: '[title*="@"], .ms-Persona-primaryText', subject: '[role="heading"]', attach: '[aria-label*="Attachment"]', replyTo: '[title*="Reply-To"]' },
      yahoo:      { container: '#main, [data-test-id="message-list-container"]', body: '[data-test-id="message-view-body"]', sender: '[data-test-id="message-from"] span', subject: '[data-test-id="message-subject"]', attach: '[data-test-id="message-attachments"] [aria-label]', replyTo: null },
      protonmail: { container: '.conversation-view', body: '.message-content, [data-testid="message-body"]', sender: '.sender-name, [data-testid="sender-name"]', subject: '.message-subject, [data-testid="message-subject"]', attach: '.attachment-item', replyTo: null },
      zoho:       { container: '#mailcontent', body: '.mail-content, .readdiv', sender: '.from-addr, [title*="@"]', subject: '.mail-subject, h2', attach: '.attachment, .att-name', replyTo: '.reply-to-addr' },
      fastmail:   { container: '.v-Section-sidebar--detail', body: '.v-Message-body', sender: '.v-MailboxMessageDetail-from [href*="mailto:"]', subject: '.v-MailboxMessageDetail-subject', attach: '.v-Attachment', replyTo: null },
      yandex:     { container: '.nb-content', body: '.letter__body', sender: '.letter-contact', subject: '.letter__subject', attach: '.ns-view-compose-attachments-wrap a', replyTo: null },
      aol:        { container: '#main-content', body: '.msg-body', sender: '.from', subject: '.subject, h2', attach: '.attachments [aria-label]', replyTo: null },
      icloud:     { container: '.ui-dockable-panel-content', body: '.mime-component-body', sender: '.from-field-value', subject: '.subject-field-value', attach: '.attachment-container [aria-label]', replyTo: null },
      generic:    { container: '[role="main"], body', body: '[role="article"], .email-body, .message-body', sender: '[email], [title*="@"], .from', subject: '[role="heading"], h1, h2', attach: '[aria-label*="ttachment"]', replyTo: null }
    };
    return map[p] || map.generic;
  }

  setupObserver() {
    this.observer = new MutationObserver((mutations) => {
      let changed = mutations.some(m =>
        (m.type === 'childList' && m.addedNodes.length > 0) ||
        (m.type === 'attributes' && (m.target.hasAttribute?.('data-message-id') || m.target.classList?.contains('a3s')))
      );
      clearTimeout(this.scanTimeout);
      this.scanTimeout = setTimeout(() => this.scan(), changed ? 350 : 900);
    });
    const root = document.querySelector(this.selectors?.container || 'body') || document.body;
    this.observer.observe(root, { childList: true, subtree: true, attributes: true, attributeFilter: ['data-message-id', 'class'] });
    if (root !== document.body) this.observer.observe(document.body, { childList: true, subtree: false });
  }

  // ── Scan trigger ───────────────────────────────────────────────────
  scan() {
    chrome.storage.local.get(['enabled'], ({ enabled }) => {
      if (enabled === false) return;
      this.doScan();
    });
  }

  doScan() {
    const data = this.extractData();
    if (!data) return;

    const changed = this.currentEmailId !== data.id;
    if (changed) {
      if (this.currentEmailId) this.dismissedMap.delete(this.currentEmailId);
      this.currentEmailId = data.id;
    }

    const result = this.scanner.scanEmail(data);
    result.subject  = data.subject;
    result.provider = this.provider;

    // Build suspicious link map
    this.suspiciousLinks.clear();
    (result.links || []).forEach(l => { if (l.score > 0) this.suspiciousLinks.set(l.url.toLowerCase(), l); });

    // Show banner for ALL emails (safe = green, medium = orange, high = red)
    const isDismissed = this.dismissedMap.get(data.id);
    if (changed || !isDismissed) {
      this.showBanner(result, data);
    }

    this.setupLinkGuard();

    if (changed) {
      this.notifyBackground(result);
    }
  }

  notifyBackground(result) {
    try {
      chrome.runtime.sendMessage({ action: 'scanResult', data: result }).catch(() => {});
      chrome.runtime.sendMessage({ action: 'updateBadge', riskLevel: result.riskLevel }).catch(() => {});
    } catch (_) {}
  }

  // ── Data extraction ────────────────────────────────────────────────
  extractData() {
    try {
      const sender      = this.extractSender();
      const subject     = this.extractSubject();
      const content     = this.extractContent();
      const links       = this.extractLinks();
      const attachments = this.extractAttachments();
      const headers     = this.extractHeaders();

      if (!sender.email && !sender.displayName && content.trim().length < 20 && links.length === 0) return null;

      return {
        id: this.genId(sender, subject),
        sender, subject, content, links, attachments, headers
      };
    } catch (_) { return null; }
  }

  extractSender() {
    const s = { displayName: '', email: '' };
    const sel = this.selectors?.sender || '[email], [title*="@"]';
    for (const q of sel.split(',').map(x => x.trim())) {
      const el = document.querySelector(q);
      if (!el) continue;
      s.email       = el.getAttribute('email') || (el.getAttribute('href') || '').replace('mailto:', '') || '';
      s.displayName = el.textContent.trim();
      const tm = (el.getAttribute('title') || '').match(/([^\s<>]+@[^\s<>]+)/);
      if (!s.email && tm) s.email = tm[1];
      if (s.email || s.displayName) break;
    }
    if (!s.email) {
      const areas = ['[role="banner"]', '.mail-header', '.msg-header', '.letter-header'];
      for (const q of areas) {
        const el = document.querySelector(q);
        if (!el) continue;
        const m = (el.textContent || '').match(/([^\s<>]+@[^\s<>]+)/);
        if (m) { s.email = m[1]; break; }
      }
    }
    return s;
  }

  extractSubject() {
    const sel = this.selectors?.subject || 'h1, h2, [role="heading"]';
    for (const q of sel.split(',').map(x => x.trim())) {
      const el = document.querySelector(q);
      if (el) { const t = (el.textContent || '').trim(); if (t) return t; }
    }
    return '';
  }

  extractContent() {
    const sel = this.selectors?.body || '[role="article"], .email-body';
    for (const q of sel.split(',').map(x => x.trim())) {
      const el = document.querySelector(q);
      if (el) { const c = (el.textContent || '').trim(); if (c.length > 10) return c; }
    }
    return '';
  }

  extractLinks() {
    // Collect attachment URLs first so we don't double-count files as links
    const attUrls = new Set();
    document.querySelectorAll('a[download]').forEach(a => {
      const href = a.getAttribute('href') || '';
      if (href) attUrls.add(href);
    });

    return [...document.querySelectorAll('a[href]')]
      .map(a => ({ url: a.getAttribute('href') || '', displayText: a.textContent.trim(), el: a }))
      .filter(l => {
        if (!l.url) return false;
        if (l.url.startsWith('#') || l.url.startsWith('javascript:') || l.url.startsWith('mailto:')) return false;
        if (this.isNavLink(l.url)) return false;
        // Skip if it's a download link (handled as attachment)
        if (l.el.hasAttribute('download')) return false;
        if (attUrls.has(l.url)) return false;
        // Skip if url or link text looks like a filename with extension
        const isFilename = /\.[a-zA-Z0-9]{1,5}$/.test(l.displayText.trim()) && !/^https?:\/\//.test(l.displayText.trim());
        if (isFilename && l.el.hasAttribute('download')) return false;
        return true;
      })
      .map(l => ({ url: this.resolveUrl(l.url), displayText: l.displayText }));
  }

  extractAttachments() {
    const atts    = [];
    const seen    = new Set();

    const addAtt = (name, extra = {}) => {
      const clean = (name || '').trim();
      // Must have a filename with an extension, skip empty or just-a-dot names
      if (!clean || !clean.includes('.') || clean.endsWith('.')) return;
      // Skip if it looks like a full URL without a filename
      if (/^https?:\/\/[^/]+\/?$/.test(clean)) return;
      const key = clean.toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      atts.push({ name: clean, fileName: clean, type: this.getExt(clean), size: extra.size || 0, ...extra });
    };

    // 1. Provider attachment DOM elements
    const sel = this.selectors?.attach || '[aria-label*="ttachment"]';
    document.querySelectorAll(sel).forEach(el => {
      // Try multiple name sources
      const name = el.getAttribute('title')
        || el.getAttribute('aria-label')
        || el.querySelector('[title]')?.getAttribute('title')
        || el.querySelector('.aZp, .ms-Link, .attachment-name')?.textContent.trim()
        || el.textContent.trim();
      addAtt(name);
    });

    // 2. Any <a download> link — these are always attachments regardless of extension
    document.querySelectorAll('a[download]').forEach(a => {
      const dlName = a.getAttribute('download');
      const href   = a.getAttribute('href') || '';
      const text   = a.textContent.trim();
      // Prefer the download attribute name, then text, then extract from URL
      const name = dlName || text || href.split('/').pop()?.split('?')[0] || '';
      addAtt(name, { url: href });
    });

    // 3. Links whose text IS a filename (e.g. "report.txt", "photo.png")
    //    These appear in webmail as inline attachment links
    document.querySelectorAll('a[href]').forEach(a => {
      const text = a.textContent.trim();
      const href = a.getAttribute('href') || '';
      // Text looks like a filename: has extension, no spaces, reasonable length
      const looksLikeFile = /^[^\s\/\\]{1,120}\.[a-zA-Z0-9]{1,10}$/.test(text);
      if (looksLikeFile && !this.isNavLink(href)) {
        addAtt(text, { url: href });
        return;
      }
      // URL itself ends with a filename pattern
      const urlFile = href.split('/').pop()?.split('?')[0] || '';
      const urlHasExt = /^[^\s]{2,120}\.[a-zA-Z0-9]{1,10}$/.test(urlFile)
        && !/^(html|htm|php|asp|aspx|jsp|cgi)$/i.test(urlFile.split('.').pop());
      if (urlHasExt && !this.isNavLink(href) && !a.hasAttribute('download')) {
        addAtt(urlFile, { url: href });
      }
    });

    // 4. Gmail attachment chips — catch by data attributes
    document.querySelectorAll('[data-attachment-id], [data-before-paste-value]').forEach(el => {
      const name = el.querySelector('.aZp')?.textContent?.trim()
        || el.getAttribute('aria-label')
        || el.textContent.trim();
      addAtt(name);
    });

    return atts;
  }

  extractHeaders() {
    const h = {};
    const rtSel = this.selectors?.replyTo;
    if (rtSel) { const el = document.querySelector(rtSel); if (el) h.replyTo = el.textContent.trim(); }
    if (!h.replyTo) {
      const area = document.querySelector('[role="banner"], .mail-header, .msg-header');
      if (area) {
        const m = (area.textContent || '').match(/Reply-To[:\s]+([^\s<>]+@[^\s<>]+)/i);
        if (m) h.replyTo = m[1];
      }
    }
    return h;
  }

  genId(sender, subject) {
    const viewEl = document.querySelector('[data-message-id], [data-testid="message-body"]');
    return `${sender.email}-${subject}-${window.location.href}-${viewEl?.getAttribute('data-message-id') || ''}`.substring(0, 150);
  }

  isNavLink(href) {
    return /^(#|javascript:|mailto:|https?:\/\/(mail\.(google|yahoo|proton|zoho)\.com|outlook\.|fastmail\.|yandex\.|mail\.aol\.|icloud\.com))/.test(href);
  }

  resolveUrl(href) {
    try { return new URL(href, window.location.href).href; } catch (_) { return href; }
  }

  getExt(name) {
    const i = name.lastIndexOf('.');
    return i === -1 ? '' : name.substring(i).toLowerCase();
  }

  // ── BANNER ─────────────────────────────────────────────────────────
  showBanner(result, data) {
    const old = document.getElementById('sm-banner');
    if (old) old.remove();

    const risk = result.riskLevel;

    const THEME = {
      safe:   { accent: '#16a34a', light: '#f0fdf4', border: '#bbf7d0', icon: 'shield-check', label: 'Safe',        sub: 'No threats detected' },
      medium: { accent: '#d97706', light: '#fffbeb', border: '#fde68a', icon: 'shield-exclamation', label: 'Medium Risk', sub: 'Suspicious indicators found' },
      high:   { accent: '#dc2626', light: '#fef2f2', border: '#fecaca', icon: 'shield-x',      label: 'High Risk',  sub: 'Phishing or malware detected' }
    }[risk];

    const score     = result.score;
    const scoreMax  = 20;
    const scorePct  = Math.min(100, Math.round((score / scoreMax) * 100));
    const cats      = (result.categories || []);
    const issues    = (result.issues || []);
    const riskyLinks= (result.links || []).filter(l => l.score > 0);
    const riskyAtts = (result.attachments || []).filter(a => a.score > 0);
    const safeAtts  = (result.attachments || []).filter(a => a.score === 0);
    const iocs      = (result.iocs || []);

    // Build inner sections
    let body = '';

    if (risk !== 'safe') {
      // Category pills
      if (cats.length) {
        body += `<div class="sm-cats">${cats.map(c => `<span class="sm-cat">${this.esc(c)}</span>`).join('')}</div>`;
      }

      // Issues
      if (issues.length) {
        body += `<div class="sm-section">
          <div class="sm-sec-hd"><i class="sm-icon-dot"></i>Issues detected (${issues.length})</div>
          <ul class="sm-list">${issues.slice(0, 6).map(i => `<li>${this.esc(i)}</li>`).join('')}</ul>
        </div>`;
      }

      // Risky links
      if (riskyLinks.length) {
        body += `<div class="sm-section">
          <div class="sm-sec-hd"><i class="sm-icon-dot"></i>Suspicious links (${riskyLinks.length})</div>
          <div class="sm-link-list">${riskyLinks.slice(0, 4).map(l => `
            <div class="sm-link-item">
              <code>${this.esc(l.url.substring(0, 65))}${l.url.length > 65 ? '…' : ''}</code>
              <span class="sm-link-tag">${this.esc(l.issues[0] || '')}</span>
            </div>`).join('')}
          </div>
        </div>`;
      }

      // Dangerous attachments
      if (riskyAtts.length) {
        body += `<div class="sm-section">
          <div class="sm-sec-hd"><i class="sm-icon-dot"></i>Dangerous attachments (${riskyAtts.length})</div>
          <div class="sm-att-list">${riskyAtts.map(a => `
            <div class="sm-att-item sm-att-${a.riskLevel}">
              <span class="sm-att-name">${this.esc(a.fileName)}</span>
              <span class="sm-att-badge">${a.riskLevel.toUpperCase()}</span>
              <div class="sm-att-detail">${this.esc(a.issues[0] || '')}</div>
            </div>`).join('')}
          </div>
        </div>`;
      }

      // IOCs
      if (iocs.length) {
        body += `<div class="sm-section">
          <div class="sm-sec-hd"><i class="sm-icon-dot"></i>IOCs</div>
          <div class="sm-ioc-list">${iocs.slice(0, 4).map(ioc => `
            <div class="sm-ioc-row"><span class="sm-ioc-type">${this.esc(ioc.type)}</span><code>${this.esc(ioc.value)}</code>${ioc.note ? `<span class="sm-ioc-note">${this.esc(ioc.note)}</span>` : ''}</div>
          `).join('')}</div>
        </div>`;
      }

    } else {
      // SAFE — still show what was scanned so user knows it worked
      body = `<p class="sm-safe-msg">This email passed all security checks. No threats detected.</p>`;

      if (result.attachments && result.attachments.length > 0) {
        body += `<div class="sm-section">
          <div class="sm-sec-hd"><i class="sm-icon-dot"></i>Attachments scanned (${result.attachments.length})</div>
          <div class="sm-att-list">${result.attachments.map(a => `
            <div class="sm-att-item sm-att-scanned">
              <span class="sm-att-name">${this.esc(a.fileName)}</span>
              <span class="sm-att-badge sm-att-badge-safe">SAFE</span>
              <div class="sm-att-detail">No threats detected</div>
            </div>`).join('')}
          </div>
        </div>`;
      }

      if (result.links && result.links.length > 0) {
        body += `<p class="sm-safe-links">${result.links.length} link${result.links.length !== 1 ? 's' : ''} scanned — all clear</p>`;
      }
    }

    const wrap = document.createElement('div');
    wrap.id = 'sm-banner';
    wrap.setAttribute('role', 'status');
    wrap.innerHTML = `
      <div class="sm-bar" style="--sm-accent:${THEME.accent};--sm-light:${THEME.light};--sm-border:${THEME.border}">
        <div class="sm-toprow">
          <div class="sm-left">
            <div class="sm-iconbox sm-iconbox-${risk}">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                ${risk === 'safe'
                  ? '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9,12 11,14 15,10"/>'
                  : risk === 'medium'
                  ? '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'
                  : '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>'}
              </svg>
            </div>
            <div class="sm-title-block">
              <span class="sm-label sm-label-${risk}">${THEME.label}</span>
              <span class="sm-sublabel">${THEME.sub}</span>
            </div>
          </div>
          <div class="sm-right">
            ${risk !== 'safe' ? `<div class="sm-scorepill sm-scorepill-${risk}">Score ${score.toFixed(1)}</div>` : `<div class="sm-scorepill sm-scorepill-safe">Score 0</div>`}
            <button class="sm-toggle" id="sm-toggle-btn" aria-label="Toggle details">${risk !== 'safe' ? '▾' : '▸'}</button>
            <button class="sm-dismiss" id="sm-dismiss-btn" aria-label="Dismiss">✕</button>
          </div>
        </div>
        ${risk !== 'safe' ? `
        <div class="sm-scorebar-track">
          <div class="sm-scorebar-fill sm-scorebar-${risk}" style="width:${scorePct}%"></div>
        </div>` : ''}
        <div class="sm-body" id="sm-body" ${risk !== 'safe' ? '' : 'style="display:none"'}>
          ${body}
        </div>
        <div class="sm-foot">SafeMail Pro · ${this.providerLabel(this.provider)} · All scanning is 100% local</div>
      </div>`;

    // Insert at top of email view
    const target = document.querySelector(this.selectors?.container || 'body');
    if (target) target.insertBefore(wrap, target.firstChild);
    else document.body.insertBefore(wrap, document.body.firstChild);

    // Toggle expand/collapse
    const toggleBtn = wrap.querySelector('#sm-toggle-btn');
    const bodyEl    = wrap.querySelector('#sm-body');
    toggleBtn.addEventListener('click', () => {
      const open = bodyEl.style.display !== 'none';
      bodyEl.style.display = open ? 'none' : 'block';
      toggleBtn.textContent = open ? '▸' : '▾';
    });

    // Dismiss
    wrap.querySelector('#sm-dismiss-btn').addEventListener('click', () => {
      this.dismissedMap.set(data.id, true);
      wrap.remove();
    });
  }

  providerLabel(p) {
    return { gmail: 'Gmail', outlook: 'Outlook', yahoo: 'Yahoo Mail', protonmail: 'ProtonMail', zoho: 'Zoho Mail', fastmail: 'Fastmail', yandex: 'Yandex Mail', aol: 'AOL Mail', icloud: 'iCloud Mail' }[p] || p;
  }

  // ── Link guard (click intercept) ───────────────────────────────────
  setupLinkGuard() {
    if (this.linkClickHandler) document.body.removeEventListener('click', this.linkClickHandler, true);
    this.linkClickHandler = (e) => {
      let el = e.target;
      while (el && el.tagName !== 'A') el = el.parentElement;
      if (!el || el.tagName !== 'A') return;
      const href = el.getAttribute('href');
      if (!href || this.isNavLink(href)) return;
      let url;
      try { url = this.resolveUrl(href).toLowerCase(); } catch (_) { return; }
      const analysis = this.suspiciousLinks.get(url);
      if (analysis && analysis.score > 0) {
        e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation();
        this.showLinkModal(url, analysis, () => window.open(href, el.target || '_self'));
      }
    };
    document.body.addEventListener('click', this.linkClickHandler, true);
  }

  // ── Link warning modal ─────────────────────────────────────────────
  showLinkModal(url, analysis, onConfirm) {
    const old = document.getElementById('sm-link-modal');
    if (old) old.remove();
    const isHigh = analysis.score >= 7;
    const m = document.createElement('div');
    m.id = 'sm-link-modal';
    m.innerHTML = `
      <div class="sml-backdrop">
        <div class="sml-box">
          <div class="sml-head sml-head-${isHigh ? 'high' : 'medium'}">
            <span>SafeMail Pro — Link Warning</span>
            <button class="sml-x" id="sml-close">✕</button>
          </div>
          <div class="sml-body">
            <div class="sml-risk-label sml-risk-${isHigh ? 'high' : 'medium'}">${isHigh ? '⛔ High Risk Link' : '⚠️ Suspicious Link'}</div>
            <p class="sml-msg">You are about to visit a potentially dangerous website.</p>
            <div class="sml-url-box"><code>${this.esc(url.substring(0, 72))}${url.length > 72 ? '…' : ''}</code></div>
            <div class="sml-issues">
              <strong>Issues found:</strong>
              <ul>${analysis.issues.map(i => `<li>${this.esc(i)}</li>`).join('')}</ul>
            </div>
            <div class="sml-btns">
              <button class="sml-btn-cancel" id="sml-cancel">← Stay Safe</button>
              <button class="sml-btn-proceed sml-btn-${isHigh ? 'high' : 'medium'}" id="sml-go">Proceed Anyway</button>
            </div>
          </div>
        </div>
      </div>`;
    document.body.appendChild(m);
    const close = () => m.remove();
    m.querySelector('#sml-close').onclick  = close;
    m.querySelector('#sml-cancel').onclick = close;
    m.querySelector('#sml-go').onclick     = () => { close(); onConfirm(); };
    m.querySelector('.sml-backdrop').addEventListener('click', e => { if (e.target === m.querySelector('.sml-backdrop')) close(); });
    const esc = e => { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', esc); } };
    document.addEventListener('keydown', esc);
  }

  esc(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }
}

if (typeof PhishingScanner !== 'undefined') {
  new SafeMailScanner();
} else {
  window.addEventListener('load', () => { if (typeof PhishingScanner !== 'undefined') new SafeMailScanner(); });
}
