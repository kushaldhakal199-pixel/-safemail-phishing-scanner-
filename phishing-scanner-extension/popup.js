/**
 * Popup Script
 * Handles extension popup UI
 */

document.addEventListener('DOMContentLoaded', async () => {
  const statusDiv = document.getElementById('status');
  const toggleBtn = document.getElementById('toggleBtn');
  const scannedCount = document.getElementById('scannedCount');
  const threatsCount = document.getElementById('threatsCount');

  // Load settings
  const { enabled = true, scanStats = { scanned: 0, threats: 0 } } = 
    await chrome.storage.local.get(['enabled', 'scanStats']);

  // Update UI
  updateStatus(enabled);
  scannedCount.textContent = scanStats.scanned || 0;
  threatsCount.textContent = scanStats.threats || 0;

  // Toggle button handler
  toggleBtn.addEventListener('click', async () => {
    const newState = !enabled;
    await chrome.storage.local.set({ enabled: newState });
    updateStatus(newState);
    
    // Reload current tab to apply changes
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
      chrome.tabs.reload(tab.id);
    }
  });

  function updateStatus(isEnabled) {
    if (isEnabled) {
      statusDiv.className = 'status active';
      statusDiv.textContent = '✓ Scanner Active';
      toggleBtn.textContent = 'Disable Scanner';
    } else {
      statusDiv.className = 'status inactive';
      statusDiv.textContent = '✗ Scanner Disabled';
      toggleBtn.textContent = 'Enable Scanner';
    }
  }
});

