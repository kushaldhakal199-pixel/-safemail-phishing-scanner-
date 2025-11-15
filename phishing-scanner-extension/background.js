/**
 * Background Service Worker
 * Handles background tasks, storage, statistics, and API calls
 */

// Listen for extension installation
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('Phishing Email Scanner installed');
    
    // Set default settings
    chrome.storage.local.set({
      enabled: true,
      riskThreshold: 'medium',
      showNotifications: true,
      scanStats: {
        scanned: 0,
        threats: 0,
        highRisk: 0,
        mediumRisk: 0
      }
    });
  }
});

// Unified message listener for all actions
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Handle scan results
  if (request.action === 'scanResult') {
    handleScanResult(request.data, sender.tab?.url);
    sendResponse({ success: true });
  }
  
  // Handle badge updates
  if (request.action === 'updateBadge') {
    updateBadge(request.riskLevel, sender.tab?.id);
    sendResponse({ success: true });
  }
  
  // Handle statistics updates
  if (request.action === 'updateStats') {
    updateStatistics(request.stats);
    sendResponse({ success: true });
  }
  
  return true; // Keep message channel open for async response
});

// Handle scan results
async function handleScanResult(scanResult, url) {
  try {
    // Update statistics
    await updateStatistics({
      scanned: 1,
      threats: scanResult.riskLevel !== 'safe' ? 1 : 0,
      highRisk: scanResult.riskLevel === 'high' ? 1 : 0,
      mediumRisk: scanResult.riskLevel === 'medium' ? 1 : 0
    });
    
    // Store scan history for risky emails
    if (scanResult.riskLevel !== 'safe') {
      await storeScanResult(scanResult, url);
    }
    
    console.log('Phishing scan result:', {
      riskLevel: scanResult.riskLevel,
      score: scanResult.score,
      issues: scanResult.issues.length
    });
  } catch (error) {
    console.error('Error handling scan result:', error);
  }
}

// Update statistics
async function updateStatistics(newStats) {
  try {
    const { scanStats = { scanned: 0, threats: 0, highRisk: 0, mediumRisk: 0 } } = 
      await chrome.storage.local.get(['scanStats']);
    
    // Increment statistics
    scanStats.scanned = (scanStats.scanned || 0) + (newStats.scanned || 0);
    scanStats.threats = (scanStats.threats || 0) + (newStats.threats || 0);
    scanStats.highRisk = (scanStats.highRisk || 0) + (newStats.highRisk || 0);
    scanStats.mediumRisk = (scanStats.mediumRisk || 0) + (newStats.mediumRisk || 0);
    
    await chrome.storage.local.set({ scanStats });
  } catch (error) {
    console.error('Error updating statistics:', error);
  }
}

// Store scan results (optional feature)
async function storeScanResult(scanResult, url) {
  try {
    const { scanHistory = [] } = await chrome.storage.local.get(['scanHistory']);
    
    scanHistory.push({
      timestamp: Date.now(),
      riskLevel: scanResult.riskLevel,
      score: scanResult.score,
      url: url || 'unknown',
      issues: scanResult.issues.slice(0, 3), // Store top 3 issues
      linksCount: scanResult.links?.length || 0
    });
    
    // Keep only last 100 scans
    if (scanHistory.length > 100) {
      scanHistory.shift();
    }
    
    await chrome.storage.local.set({ scanHistory });
  } catch (error) {
    console.error('Error storing scan result:', error);
  }
}

// Optional: Check domain reputation via API
async function checkDomainReputation(domain) {
  // This is a placeholder - in production, you'd call a real API
  // Example: VirusTotal, Google Safe Browsing, etc.
  
  // For now, return a mock response
  return {
    reputation: 'unknown',
    isMalicious: false
  };
}

// Update badge based on scan results
function updateBadge(riskLevel, tabId) {
  if (!tabId) return;
  
  const badgeColors = {
    high: '#dc3545',
    medium: '#fd7e14',
    safe: '#28a745'
  };
  
  chrome.action.setBadgeText({
    text: riskLevel === 'safe' ? '' : '!',
    tabId: tabId
  });
  
  chrome.action.setBadgeBackgroundColor({
    color: badgeColors[riskLevel] || '#666',
    tabId: tabId
  });
}

// Clean up old scan history periodically
chrome.alarms.create('cleanupHistory', { periodInMinutes: 60 * 24 }); // Daily

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'cleanupHistory') {
    cleanupOldHistory();
  }
});

async function cleanupOldHistory() {
  try {
    const { scanHistory = [] } = await chrome.storage.local.get(['scanHistory']);
    const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
    
    const recentHistory = scanHistory.filter(scan => scan.timestamp > oneWeekAgo);
    
    await chrome.storage.local.set({ scanHistory: recentHistory });
    console.log(`Cleaned up scan history. Kept ${recentHistory.length} recent scans.`);
  } catch (error) {
    console.error('Error cleaning up history:', error);
  }
}

// Handle tab updates to clear badge when leaving email pages
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete') {
    const isEmailPage = tab.url && (
      tab.url.includes('mail.google.com') || 
      tab.url.includes('outlook.')
    );
    
    if (!isEmailPage) {
      // Clear badge when not on email page
      chrome.action.setBadgeText({ text: '', tabId: tabId });
    }
  }
});

// Export functions for testing (if needed)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    updateStatistics,
    storeScanResult,
    updateBadge,
    cleanupOldHistory
  };
}

