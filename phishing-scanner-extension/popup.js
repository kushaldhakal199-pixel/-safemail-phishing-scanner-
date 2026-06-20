document.addEventListener('DOMContentLoaded', async () => {

  // Tabs
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(b => b.classList.remove('on'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('on'));
      btn.classList.add('on');
      document.getElementById('p-' + btn.dataset.t).classList.add('on');
      if (btn.dataset.t === 'history') renderHistory();
    });
  });

  // Load storage
  const s = await chrome.storage.local.get([
    'enabled','scanStats','showNotifications','notifyHighOnly',
    'riskThreshold','showSafeBanner','linkIntercept','threatHistory'
  ]);

  const stats   = s.scanStats || { scanned:0, threats:0, highRisk:0, mediumRisk:0, safe:0 };
  const enabled = s.enabled !== false;

  // Stats
  document.getElementById('sScanned').textContent = stats.scanned    || 0;
  document.getElementById('sSafe').textContent    = stats.safe       || 0;
  document.getElementById('sMed').textContent     = stats.mediumRisk || 0;
  document.getElementById('sHigh').textContent    = stats.highRisk   || 0;

  // Settings
  document.getElementById('sNotif').checked     = s.showNotifications !== false;
  document.getElementById('sHighOnly').checked  = s.notifyHighOnly === true;
  document.getElementById('sShowSafe').checked  = s.showSafeBanner !== false;
  document.getElementById('sLinkBlock').checked = s.linkIntercept !== false;
  document.getElementById('sThresh').value      = s.riskThreshold || 'medium';

  applyStatus(enabled);

  // Render history immediately on load
  renderHistory();

  // Toggle scanner
  document.getElementById('toggleBtn').addEventListener('click', async () => {
    const cur  = (await chrome.storage.local.get('enabled')).enabled !== false;
    const next = !cur;
    await chrome.storage.local.set({ enabled: next });
    applyStatus(next);
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) chrome.tabs.reload(tab.id);
  });

  // History
  async function renderHistory() {
    const { threatHistory = [] } = await chrome.storage.local.get(['threatHistory']);
    const list = document.getElementById('histList');
    if (!threatHistory.length) {
      list.innerHTML = `<div class="empty"><span class="empty-icon">📭</span>No threats detected yet</div>`;
      return;
    }
    list.innerHTML = [...threatHistory].reverse().slice(0, 50).map(r => {
      const cats = (r.categories || []).map(c => `<span class="hi-cat">${esc(c)}</span>`).join('');
      const prov = r.provider && r.provider !== 'unknown' ? `<span class="hi-cat">${esc(r.provider)}</span>` : '';
      return `<div class="hi ${r.riskLevel}">
        <div class="hi-top">
          <span class="hi-badge ${r.riskLevel}">${r.riskLevel === 'high' ? '🔴 High' : '🟠 Medium'} · ${r.score.toFixed(1)}/20</span>
          <span class="hi-time">${ago(r.timestamp)}</span>
        </div>
        <div class="hi-who">${esc(r.sender || 'Unknown sender')}</div>
        <div class="hi-subj">${esc(r.subject || '(no subject)')}</div>
        ${r.issues?.[0] ? `<div class="hi-issue">↳ ${esc(r.issues[0])}</div>` : ''}
        <div class="hi-cats">${cats}${prov}</div>
      </div>`;
    }).join('');
  }

  document.getElementById('clearBtn').addEventListener('click', async () => {
    if (!confirm('Clear all history and statistics?')) return;
    await chrome.runtime.sendMessage({ action: 'clearAll' });
    ['sScanned','sSafe','sMed','sHigh'].forEach(id => document.getElementById(id).textContent = '0');
    renderHistory();
  });

  document.getElementById('exportBtn').addEventListener('click', async () => {
    const r = await chrome.runtime.sendMessage({ action: 'exportHistory' });
    if (!r?.data) return;
    const blob = new Blob([JSON.stringify(r.data, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement('a'), { href: url, download: 'safemail-threats-' + new Date().toISOString().slice(0,10) + '.json' });
    a.click(); URL.revokeObjectURL(url);
  });

  // Save settings
  document.getElementById('saveBtn').addEventListener('click', async () => {
    await chrome.storage.local.set({
      showNotifications: document.getElementById('sNotif').checked,
      notifyHighOnly:    document.getElementById('sHighOnly').checked,
      showSafeBanner:    document.getElementById('sShowSafe').checked,
      linkIntercept:     document.getElementById('sLinkBlock').checked,
      riskThreshold:     document.getElementById('sThresh').value
    });
    const btn = document.getElementById('saveBtn');
    btn.textContent = '✓ Saved!'; btn.className = 'btn b-green';
    setTimeout(() => { btn.textContent = 'Save Settings'; btn.className = 'btn b-dark'; }, 1800);
  });

  // Helpers
  function applyStatus(on) {
    const pill = document.getElementById('statusPill');
    const txt  = document.getElementById('statusTxt');
    const btn  = document.getElementById('toggleBtn');
    pill.className = 'status-pill ' + (on ? 'sp-on' : 'sp-off');
    txt.textContent = on ? 'Active' : 'Disabled';
    btn.textContent = on ? 'Disable Scanner' : 'Enable Scanner';
    btn.className   = 'btn ' + (on ? 'b-toggle-on' : 'b-toggle-off');
  }

  function ago(ts) {
    const d = Date.now() - ts, m = Math.floor(d/60000), h = Math.floor(m/60), dy = Math.floor(h/24);
    return dy > 0 ? dy+'d ago' : h > 0 ? h+'h ago' : m > 0 ? m+'m ago' : 'just now';
  }

  function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
});
