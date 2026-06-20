/**
 * SafeMail Pro v4.0 — Background Service Worker
 * No external API calls. Local scanning only.
 */

chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  if (reason === 'install') {
    await chrome.storage.local.set({
      enabled:           true,
      showNotifications: true,
      notifyHighOnly:    false,
      riskThreshold:     'medium',
      scanStats:         { scanned: 0, threats: 0, highRisk: 0, mediumRisk: 0, safe: 0 },
      threatHistory:     []
    });
  }
  setupContextMenu();
});

chrome.runtime.onStartup.addListener(setupContextMenu);

function setupContextMenu() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: 'sm-check-link', title: '🛡️ Check this link — SafeMail Pro', contexts: ['link'] });
  });
}

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId !== 'sm-check-link') return;
  const url = info.linkUrl || '';
  let verdict = '✅ Looks clean — no obvious threats detected.';
  try {
    const u    = new URL(url);
    const host = u.hostname.toLowerCase();
    const shorteners = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','rb.gy','tiny.cc','cutt.ly'];
    if (u.protocol === 'http:') verdict = '⚠️ Insecure HTTP link — data is not encrypted.';
    else if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) verdict = '🚨 Link uses a raw IP address — highly suspicious.';
    else if (shorteners.some(s => host === s || host.endsWith('.' + s))) verdict = '⚠️ URL shortener — real destination is hidden.';
  } catch (_) { verdict = '⚠️ Malformed URL — could not parse.'; }
  chrome.notifications.create(`sm-ctx-${Date.now()}`, {
    type: 'basic', iconUrl: 'icons/icon128.png',
    title: '🛡️ SafeMail Pro — Link Check',
    message: url.substring(0, 60) + '\n\n' + verdict,
    priority: verdict.startsWith('🚨') ? 2 : 1
  });
});

// ── Message Router ────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
  (async () => {
    try {
      switch (req.action) {
        case 'scanResult':
          await handleScanResult(req.data, sender.tab);
          sendResponse({ ok: true });
          break;
        case 'updateBadge':
          setBadge(req.riskLevel, sender.tab?.id);
          sendResponse({ ok: true });
          break;
        case 'getStats':
          const s = await chrome.storage.local.get(['scanStats', 'threatHistory']);
          sendResponse({ ok: true, data: { ...s.scanStats, recentThreats: (s.threatHistory || []).slice(-5).reverse() } });
          break;
        case 'getHistory':
          const h = await chrome.storage.local.get(['threatHistory']);
          sendResponse({ ok: true, data: (h.threatHistory || []).slice(-(req.limit || 50)).reverse() });
          break;
        case 'exportHistory':
          const exp = await chrome.storage.local.get(['threatHistory', 'scanStats']);
          sendResponse({ ok: true, data: { exportedAt: new Date().toISOString(), version: '4.0', stats: exp.scanStats, threats: exp.threatHistory } });
          break;
        case 'clearAll':
          await chrome.storage.local.set({ threatHistory: [], scanStats: { scanned: 0, threats: 0, highRisk: 0, mediumRisk: 0, safe: 0 } });
          sendResponse({ ok: true });
          break;
        default:
          sendResponse({ ok: false });
      }
    } catch (e) {
      sendResponse({ ok: false, error: e.message });
    }
  })();
  return true;
});

// ── Scan result handler ───────────────────────────────────────────────
async function handleScanResult(result, tab) {
  const { enabled = true, showNotifications = true, notifyHighOnly = false } =
    await chrome.storage.local.get(['enabled', 'showNotifications', 'notifyHighOnly']);
  if (!enabled) return;

  // Update stats
  const { scanStats = { scanned: 0, threats: 0, highRisk: 0, mediumRisk: 0, safe: 0 } } =
    await chrome.storage.local.get(['scanStats']);
  scanStats.scanned++;
  if (result.riskLevel === 'high')   { scanStats.threats++; scanStats.highRisk++; }
  else if (result.riskLevel === 'medium') { scanStats.threats++; scanStats.mediumRisk++; }
  else scanStats.safe++;
  await chrome.storage.local.set({ scanStats });

  // Store in history
  if (result.riskLevel !== 'safe') {
    const { threatHistory = [] } = await chrome.storage.local.get(['threatHistory']);
    threatHistory.push({
      id:          Date.now(),
      timestamp:   Date.now(),
      riskLevel:   result.riskLevel,
      score:       result.score,
      provider:    result.provider || 'unknown',
      subject:     result.subject || '',
      sender:      result.sender?.email || '',
      categories:  result.categories || [],
      issues:      (result.issues || []).slice(0, 5),
      iocs:        (result.iocs || []).slice(0, 5),
      url:         tab?.url || ''
    });
    if (threatHistory.length > 200) threatHistory.splice(0, threatHistory.length - 200);
    await chrome.storage.local.set({ threatHistory });
  }

  // Browser notification
  if (showNotifications && result.riskLevel !== 'safe') {
    const skip = notifyHighOnly && result.riskLevel !== 'high';
    if (!skip) sendNotification(result);
  }
}

function sendNotification(result) {
  const isHigh = result.riskLevel === 'high';
  const subj   = result.subject ? '"' + result.subject.substring(0, 45) + (result.subject.length > 45 ? '…' : '') + '"' : 'an email';
  const cats   = (result.categories || []).join(', ');
  const issue  = result.issues?.[0] || 'Suspicious indicators detected';

  chrome.notifications.create(`sm-${Date.now()}`, {
    type:               'basic',
    iconUrl:            'icons/icon128.png',
    title:              `🛡️ SafeMail Pro — ${isHigh ? '🔴 HIGH RISK' : '🟠 MEDIUM RISK'}`,
    message:            `In ${subj}\n• ${issue}${cats ? '\nType: ' + cats : ''}`,
    priority:           isHigh ? 2 : 1,
    requireInteraction: isHigh
  });
}

chrome.notifications.onClicked.addListener((id) => {
  if (!id.startsWith('sm-')) return;
  chrome.notifications.clear(id);
  const emailHosts = ['mail.google.com','outlook.','mail.yahoo.com','mail.proton.me','mail.zoho.com','fastmail.com','yandex.','mail.aol.com','icloud.com'];
  chrome.tabs.query({}, tabs => {
    const t = tabs.find(t => emailHosts.some(h => t.url?.includes(h)));
    if (t) { chrome.tabs.update(t.id, { active: true }); chrome.windows.update(t.windowId, { focused: true }); }
  });
});

// ── Badge ──────────────────────────────────────────────────────────────
function setBadge(risk, tabId) {
  if (!tabId) return;
  const colors = { high: '#dc2626', medium: '#d97706', safe: '#16a34a' };
  const texts  = { high: '!!!', medium: '!', safe: '' };
  chrome.action.setBadgeText({ text: texts[risk] ?? '', tabId });
  chrome.action.setBadgeBackgroundColor({ color: colors[risk] ?? '#888', tabId });
}

// ── Cleanup ────────────────────────────────────────────────────────────
chrome.alarms.create('cleanup', { periodInMinutes: 1440 });
chrome.alarms.onAlarm.addListener(async ({ name }) => {
  if (name !== 'cleanup') return;
  const { threatHistory = [] } = await chrome.storage.local.get(['threatHistory']);
  const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
  await chrome.storage.local.set({ threatHistory: threatHistory.filter(r => r.timestamp > cutoff) });
});

const emailHosts = ['mail.google.com','outlook.','mail.yahoo.com','mail.proton.me','mail.zoho.com','fastmail.com','yandex.','mail.aol.com','icloud.com'];
chrome.tabs.onUpdated.addListener((tabId, { status }, tab) => {
  if (status !== 'complete') return;
  if (!emailHosts.some(h => tab.url?.includes(h))) chrome.action.setBadgeText({ text: '', tabId });
});
