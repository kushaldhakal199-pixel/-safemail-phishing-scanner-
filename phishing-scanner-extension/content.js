/**
 * Content Script - Interacts with Gmail/Outlook DOM
 * Extracts email data and injects warning banners
 */

class EmailContentExtractor {
  constructor() {
    this.scanner = new PhishingScanner();
    this.scannedEmails = new Set();
    this.dismissedWarnings = new Map(); // Track dismissed warnings per email ID
    this.currentEmailId = null; // Track current email being viewed
    this.currentScanResult = null; // Store current scan result for link checking
    this.suspiciousLinks = new Map(); // Map of URL -> link analysis data
    this.observer = null;
    this.init();
  }

  init() {
    // Wait for page to load - Gmail loads dynamically
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        // Additional delay for Gmail's dynamic loading
        setTimeout(() => this.startScanning(), 1000);
      });
    } else {
      // Gmail might still be loading, add a small delay
      setTimeout(() => this.startScanning(), 1000);
    }
  }

  startScanning() {
    // Detect email service
    const isGmail = window.location.hostname.includes('mail.google.com');
    const isOutlook = window.location.hostname.includes('outlook.');

    if (isGmail) {
      this.setupGmail();
    } else if (isOutlook) {
      this.setupOutlook();
    }

    // Initial scan after a delay (Gmail loads slowly)
    setTimeout(() => {
      this.scanCurrentEmail();
    }, 1500);

    // Set up mutation observer for dynamic content
    this.setupObserver();

    // Set up link interception immediately
    this.setupLinkInterception();

    // Periodic scan as fallback (every 3 seconds) in case mutation observer misses changes
    this.periodicScanInterval = setInterval(() => {
      this.scanCurrentEmail();
    }, 3000);
  }

  setupGmail() {
    // Gmail-specific selectors (updated for current Gmail interface)
    this.selectors = {
      emailContainer: '[role="main"]',
      emailView: '[data-message-id], .nH.if, .aDP, [role="main"] > div > div',
      sender: '[email], span[email], .gD, .go',
      subject: 'h2[data-thread-perm-id], h2[data-thread-id], .hP',
      body: '.a3s, [role="article"], .ii.gt, .a3s.aXjCH, .Am.Al.editable',
      links: 'a[href]'
    };
  }

  setupOutlook() {
    // Outlook-specific selectors
    this.selectors = {
      emailContainer: '[role="main"]',
      emailView: '[aria-label*="Message"]',
      sender: '[title*="@"]',
      subject: '[role="heading"]',
      body: '[role="article"], .ms-fontColor-neutralPrimary',
      links: 'a[href]'
    };
  }

  setupObserver() {
    // Watch for email view changes
    this.observer = new MutationObserver((mutations) => {
      // Check if email view was removed (user navigated away)
      const currentEmailView = document.querySelector(this.selectors?.emailView || '[data-message-id], [aria-label*="Message"]');
      if (!currentEmailView && this.currentEmailId) {
        // Email view removed - clear current email tracking
        // This ensures warnings show again when email is reopened
        this.currentEmailId = null;
      }

      // Check for significant DOM changes that indicate email view change
      let shouldScan = false;
      for (const mutation of mutations) {
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
          // New nodes added - might be email content
          shouldScan = true;
        }
        if (mutation.type === 'attributes') {
          // Attribute changes might indicate email view change
          const target = mutation.target;
          if (target.hasAttribute('data-message-id') || 
              target.hasAttribute('data-thread-id') ||
              target.classList.contains('a3s') ||
              target.classList.contains('nH')) {
            shouldScan = true;
          }
        }
      }

      // Debounce scanning but scan more aggressively
      clearTimeout(this.scanTimeout);
      this.scanTimeout = setTimeout(() => {
        this.scanCurrentEmail();
      }, shouldScan ? 300 : 800); // Faster scan if significant changes detected
    });

    // Observe the main container and body for Gmail's dynamic loading
    const container = document.querySelector(this.selectors.emailContainer || 'body');
    const body = document.body;
    
    if (container) {
      this.observer.observe(container, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['data-message-id', 'data-thread-id', 'class']
      });
    }
    
    // Also observe body for Gmail's dynamic content
    if (body && body !== container) {
      this.observer.observe(body, {
        childList: true,
        subtree: false // Only direct children to avoid performance issues
      });
    }
  }

  scanCurrentEmail() {
    // Check if extension is enabled
    chrome.storage.local.get(['enabled'], (result) => {
      if (result.enabled === false) {
        return; // Extension is disabled
      }
      this.performScan();
    });
  }

  performScan() {
    const emailData = this.extractEmailData();
    if (!emailData) {
      // No email data found - might be on inbox view
      return;
    }

    // Check if email changed - this includes reopening the same email
    const emailChanged = this.currentEmailId !== emailData.id;
    
    if (emailChanged) {
      // Email view changed - clear dismissed status for the previous email
      // This ensures warnings show again when:
      // 1. Opening a different email
      // 2. Reopening the same email (email ID changes when view changes)
      if (this.currentEmailId) {
        // Clear dismissed status for previous email
        this.dismissedWarnings.delete(this.currentEmailId);
      }
      this.currentEmailId = emailData.id;
    }

    // Always scan the email (don't skip if already scanned)
    // This allows re-scanning if user closes and reopens the same email
    const scanResult = this.scanner.scanEmail(emailData);
    
    // Store scan result for link click interception
    this.currentScanResult = scanResult;
    
    // Build suspicious links map for quick lookup
    this.suspiciousLinks.clear();
    if (scanResult.links && scanResult.links.length > 0) {
      scanResult.links.forEach(link => {
        if (link.score > 0) {
          this.suspiciousLinks.set(link.url.toLowerCase(), link);
        }
      });
    }
    
    // Mark as scanned (for logging purposes, but don't prevent re-scanning)
    if (!this.scannedEmails.has(emailData.id)) {
      this.scannedEmails.add(emailData.id);
    }

    // Display warning if risk detected
    // Always show warning if email view changed (new email or reopened email)
    // Also show if same view but warning was never dismissed
    const isDismissed = this.dismissedWarnings.get(emailData.id);
    
    // Show warning if:
    // 1. Risk level is not safe (has some risk)
    // 2. Email view changed (user opened different email or reopened same email) - always show
    // 3. Same email view but warning was never dismissed
    if (scanResult.riskLevel !== 'safe' && (emailChanged || !isDismissed)) {
      this.displayWarning(scanResult, emailData);
    }

    // Set up link click interception
    this.setupLinkInterception();

    // Send scan result to background script for statistics and badge updates
    // Only send if email changed to avoid duplicate counts
    if (emailChanged) {
      this.sendScanResultToBackground(scanResult);
    }
  }

  // Send scan results to background script
  sendScanResultToBackground(scanResult) {
    try {
      // Send scan result for statistics
      chrome.runtime.sendMessage({
        action: 'scanResult',
        data: scanResult
      }).catch(err => {
        // Ignore errors if background script is not available
        console.debug('Could not send scan result to background:', err);
      });

      // Update badge
      chrome.runtime.sendMessage({
        action: 'updateBadge',
        riskLevel: scanResult.riskLevel
      }).catch(err => {
        // Ignore errors if background script is not available
        console.debug('Could not update badge:', err);
      });
    } catch (error) {
      // Silently fail if messaging is not available
      console.debug('Error sending message to background:', error);
    }
  }

  extractEmailData() {
    try {
      const sender = this.extractSender();
      const subject = this.extractSubject();
      const content = this.extractContent();
      const links = this.extractLinks();
      const attachments = this.extractAttachments();

      // Check if we're actually viewing an email (not just inbox)
      // Gmail shows email view when we have content or links
      const hasEmailContent = content.trim().length > 20 || links.length > 0 || attachments.length > 0;
      const hasSender = sender.email || sender.displayName;

      if (!hasEmailContent && !hasSender) {
        // Probably on inbox view, not an email
        return null;
      }

      const data = {
        id: this.generateEmailId(),
        sender: sender,
        subject: subject,
        content: content,
        links: links,
        attachments: attachments
      };

      // Return data if we have at least sender or content
      if (data.sender.email || data.content.trim().length > 0 || data.links.length > 0 || data.attachments.length > 0) {
        return data;
      }
      return null;
    } catch (e) {
      console.error('Error extracting email data:', e);
      return null;
    }
  }

  extractSender() {
    const sender = {
      displayName: '',
      email: ''
    };

    // Try multiple Gmail selectors
    const gmailSelectors = [
      '[email]',
      'span[email]',
      '.gD[email]',
      '.go[email]',
      '.g2[email]'
    ];

    for (const selector of gmailSelectors) {
      const senderElement = document.querySelector(selector);
      if (senderElement) {
        sender.email = senderElement.getAttribute('email') || '';
        sender.displayName = senderElement.textContent.trim() || senderElement.innerText.trim() || '';
        if (sender.email) break;
      }
    }

    // Try Outlook format
    if (!sender.email) {
      const senderElement = document.querySelector('[title*="@"]');
      if (senderElement) {
        const title = senderElement.getAttribute('title') || '';
        const emailMatch = title.match(/([^\s<>]+@[^\s<>]+)/);
        if (emailMatch) {
          sender.email = emailMatch[1];
        }
        sender.displayName = senderElement.textContent.trim() || '';
      }
    }

    // Fallback: look for email patterns in text (Gmail)
    if (!sender.email) {
      const emailPattern = /([^\s<>]+@[^\s<>]+)/;
      const senderSections = [
        '[role="banner"]',
        '.gD',
        '.go',
        '.g2',
        '.hP',
        '.ms-Persona-primaryText'
      ];
      
      for (const sectionSelector of senderSections) {
        const senderSection = document.querySelector(sectionSelector);
        if (senderSection) {
          const text = senderSection.textContent || senderSection.innerText || '';
          const match = text.match(emailPattern);
          if (match) {
            sender.email = match[1];
            sender.displayName = text.replace(emailPattern, '').trim();
            break;
          }
        }
      }
    }

    return sender;
  }

  extractSubject() {
    // Try multiple Gmail subject selectors
    const gmailSubjectSelectors = [
      'h2[data-thread-perm-id]',
      'h2[data-thread-id]',
      '.hP',
      'h2.hP',
      '[data-thread-perm-id]'
    ];

    for (const selector of gmailSubjectSelectors) {
      const subject = document.querySelector(selector);
      if (subject) {
        const text = subject.textContent || subject.innerText || '';
        if (text.trim()) {
          return text.trim();
        }
      }
    }

    // Outlook
    const subject = document.querySelector('[role="heading"]');
    if (subject) {
      return (subject.textContent || subject.innerText || '').trim();
    }

    return '';
  }

  extractContent() {
    // Get email body content - try multiple Gmail selectors
    const bodySelectors = [
      '.a3s', // Gmail classic
      '.a3s.aXjCH', // Gmail updated
      '.Am.Al.editable', // Gmail editable content
      '.ii.gt', // Gmail alternative
      '[role="article"]', // Both Gmail and Outlook
      '.ms-fontColor-neutralPrimary', // Outlook
      '.nH.if' // Gmail message body
    ];

    for (const selector of bodySelectors) {
      const body = document.querySelector(selector);
      if (body) {
        const content = body.textContent || body.innerText || '';
        if (content.trim().length > 10) { // Only return if meaningful content
          return content;
        }
      }
    }

    return '';
  }

  extractLinks() {
    const links = [];
    const linkElements = document.querySelectorAll(this.selectors.links || 'a[href]');

    linkElements.forEach(link => {
      const href = link.getAttribute('href');
      if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
        // Skip navigation links
        if (this.isNavigationLink(href)) return;

        links.push({
          url: this.resolveUrl(href),
          displayText: link.textContent.trim() || link.innerText.trim()
        });
      }
    });

    return links;
  }

  extractAttachments() {
    const attachments = [];

    // Gmail attachment selectors
    const gmailAttachmentSelectors = [
      '[data-attachment-id]',
      '.aZo', // Gmail attachment container
      '.aZp', // Gmail attachment name
      '[aria-label*="Attachment"]',
      '.aQH'  // Gmail attachment
    ];

    // Outlook attachment selectors
    const outlookAttachmentSelectors = [
      '[aria-label*="Attachment"]',
      '.ms-Attachment',
      '[data-attachment-id]'
    ];

    // Try Gmail selectors first
    let attachmentElements = [];
    for (const selector of gmailAttachmentSelectors) {
      attachmentElements = document.querySelectorAll(selector);
      if (attachmentElements.length > 0) break;
    }

    // Try Outlook selectors if Gmail didn't work
    if (attachmentElements.length === 0) {
      for (const selector of outlookAttachmentSelectors) {
        attachmentElements = document.querySelectorAll(selector);
        if (attachmentElements.length > 0) break;
      }
    }

    // Extract attachment information
    attachmentElements.forEach(element => {
      try {
        // Get file name
        let fileName = '';
        const nameElement = element.querySelector('[title], .aZp, .ms-Link');
        if (nameElement) {
          fileName = nameElement.getAttribute('title') || 
                     nameElement.textContent.trim() || 
                     nameElement.innerText.trim();
        } else {
          fileName = element.getAttribute('aria-label') || 
                     element.textContent.trim() || 
                     element.innerText.trim();
        }

        // Get file size if available
        let fileSize = 0;
        const sizeElement = element.querySelector('.aYx, .ms-Attachment-size');
        if (sizeElement) {
          const sizeText = sizeElement.textContent || sizeElement.innerText || '';
          fileSize = this.parseFileSize(sizeText);
        }

        // Get file type from extension
        const fileType = this.getFileTypeFromName(fileName);

        if (fileName) {
          attachments.push({
            name: fileName,
            fileName: fileName,
            type: fileType,
            size: fileSize,
            element: element
          });
        }
      } catch (e) {
        console.debug('Error extracting attachment:', e);
      }
    });

    // Also check for attachment links in email content
    const attachmentLinks = document.querySelectorAll('a[href*="attachment"], a[href*="download"], a[download]');
    attachmentLinks.forEach(link => {
      const href = link.getAttribute('href') || '';
      const downloadAttr = link.getAttribute('download') || '';
      const linkText = link.textContent.trim() || link.innerText.trim();
      
      // Extract filename from href or download attribute
      let fileName = downloadAttr || linkText;
      if (!fileName && href) {
        const urlMatch = href.match(/([^\/\?]+\.(exe|apk|zip|rar|pdf|doc|docx|bat|scr|vbs|js|jar|msi|dmg|pkg|deb|rpm))(\?|$)/i);
        if (urlMatch) {
          fileName = urlMatch[1];
        }
      }

      if (fileName && !attachments.find(a => a.name === fileName)) {
        attachments.push({
          name: fileName,
          fileName: fileName,
          type: this.getFileTypeFromName(fileName),
          size: 0,
          isLink: true,
          url: href
        });
      }
    });

    return attachments;
  }

  parseFileSize(sizeText) {
    if (!sizeText) return 0;
    
    const sizeMatch = sizeText.match(/([\d.]+)\s*(KB|MB|GB|bytes?)/i);
    if (!sizeMatch) return 0;

    const value = parseFloat(sizeMatch[1]);
    const unit = sizeMatch[2].toUpperCase();

    switch (unit) {
      case 'GB': return value * 1024 * 1024 * 1024;
      case 'MB': return value * 1024 * 1024;
      case 'KB': return value * 1024;
      default: return value;
    }
  }

  getFileTypeFromName(fileName) {
    if (!fileName) return '';
    const lastDot = fileName.lastIndexOf('.');
    if (lastDot === -1) return '';
    return fileName.substring(lastDot + 1).toLowerCase();
  }

  isNavigationLink(href) {
    // Filter out Gmail/Outlook internal links
    const navigationPatterns = [
      /^https?:\/\/(mail\.google\.com|outlook\.)/,
      /^#/,
      /^javascript:/,
      /^mailto:/
    ];

    return navigationPatterns.some(pattern => pattern.test(href));
  }

  resolveUrl(href) {
    try {
      // Resolve relative URLs
      return new URL(href, window.location.href).href;
    } catch (e) {
      return href;
    }
  }

  generateEmailId() {
    // Generate unique ID based on current email
    // Include URL hash/fragment to detect when same email is reopened
    const sender = this.extractSender().email;
    const subject = this.extractSubject();
    const url = window.location.href;
    // Use a more stable ID that changes when email view changes
    // This helps detect when user closes and reopens the same email
    const emailViewElement = document.querySelector(this.selectors?.emailView || '[data-message-id], [aria-label*="Message"]');
    const viewId = emailViewElement ? (emailViewElement.getAttribute('data-message-id') || emailViewElement.getAttribute('aria-label') || '') : '';
    
    // Combine all to create unique ID that changes when email view changes
    return `${sender}-${subject}-${url}-${viewId}`.substring(0, 150);
  }

  displayWarning(scanResult, emailData) {
    // Remove existing warning if any
    const existingWarning = document.getElementById('phishing-scanner-warning');
    if (existingWarning) {
      existingWarning.remove();
    }

    // Create warning banner
    const warning = document.createElement('div');
    warning.id = 'phishing-scanner-warning';
    warning.className = `phishing-warning phishing-${scanResult.riskLevel}`;

    // Get risk level display text and icon
    const riskLevels = {
      'high': { text: 'HIGH RISK', icon: '🔴', color: '#dc3545' },
      'medium': { text: 'MEDIUM RISK', icon: '🟠', color: '#fd7e14' },
      'safe': { text: 'SAFE', icon: '🟢', color: '#28a745' }
    };
    
    const riskInfo = riskLevels[scanResult.riskLevel] || { text: scanResult.riskLevel.toUpperCase(), icon: '⚠️', color: '#666' };

    // Build warning content with prominent risk level display
    let warningHTML = `
      <div class="phishing-warning-header">
        <span class="phishing-icon">${riskInfo.icon}</span>
        <div class="phishing-risk-info">
          <div style="display: flex; align-items: center; gap: 8px;">
            <strong class="phishing-risk-title">SafeMail:</strong>
            <span class="phishing-risk-level" style="color: ${riskInfo.color}; font-weight: bold; font-size: 18px; text-shadow: 0 1px 2px rgba(0,0,0,0.2);">
              ${riskInfo.text}
            </span>
          </div>
          <div style="font-size: 11px; opacity: 0.9; margin-top: 2px;">Phishing Risk Detected</div>
        </div>
        <button class="phishing-close" title="Dismiss warning (will show again when you reopen this email)">×</button>
      </div>
      <div class="phishing-warning-body">
        <p style="margin-bottom: 12px;">
          <strong>Risk Score:</strong> 
          <span style="font-size: 20px; font-weight: bold; color: ${riskInfo.color}; margin-left: 8px;">
            ${scanResult.score.toFixed(1)}/20
          </span>
        </p>
        ${scanResult.issues.length > 0 ? '<p style="margin-bottom: 8px;"><strong>Issues Found:</strong></p><ul class="phishing-issues">' : '<p>No specific issues detected, but risk indicators present.</p>'}
    `;

    // Add issues
    if (scanResult.issues.length > 0) {
      scanResult.issues.slice(0, 5).forEach(issue => {
        warningHTML += `<li>${this.escapeHtml(issue)}</li>`;
      });
      warningHTML += `</ul>`;
    }

    // Add link details if any
    if (scanResult.links && scanResult.links.length > 0) {
      const riskyLinks = scanResult.links.filter(l => l.score > 0);
      if (riskyLinks.length > 0) {
        warningHTML += `<div class="phishing-links"><strong>Suspicious Links:</strong><ul>`;
        riskyLinks.slice(0, 3).forEach(link => {
          warningHTML += `<li><code>${this.escapeHtml(link.url.substring(0, 60))}</code> - ${link.issues.join(', ')}</li>`;
        });
        warningHTML += `</ul></div>`;
      }
    }

    // Add attachment/malware details if any
    if (scanResult.attachments && scanResult.attachments.length > 0) {
      const riskyAttachments = scanResult.attachments.filter(a => a.score > 0);
      if (riskyAttachments.length > 0) {
        warningHTML += `<div class="phishing-attachments" style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #e0e0e0;"><strong style="color: #dc3545;">🚨 MALWARE/PAYLOAD DETECTED:</strong><ul style="margin-top: 8px;">`;
        riskyAttachments.forEach(attachment => {
          const riskBadge = attachment.riskLevel === 'high' ? '🔴 HIGH RISK' : '🟠 MEDIUM RISK';
          warningHTML += `<li style="margin: 8px 0;">
            <strong>${this.escapeHtml(attachment.fileName)}</strong> 
            <span style="color: ${attachment.riskLevel === 'high' ? '#dc3545' : '#fd7e14'}; font-weight: bold;">(${riskBadge})</span><br>
            <span style="font-size: 12px; color: #666;">${attachment.issues.join(' | ')}</span>
          </li>`;
        });
        warningHTML += `</ul></div>`;
      }
    }

    warningHTML += `</div>`;

    warning.innerHTML = warningHTML;

    // Insert warning at the top of email view
    const emailContainer = document.querySelector(this.selectors.emailView || this.selectors.emailContainer || 'body');
    if (emailContainer) {
      emailContainer.insertBefore(warning, emailContainer.firstChild);
    } else {
      document.body.insertBefore(warning, document.body.firstChild);
    }

    // Add click handler for close button
    // When closed, mark as dismissed for THIS email only
    // But it will show again when user reopens the same email (email ID changes)
    const closeButton = warning.querySelector('.phishing-close');
    closeButton.addEventListener('click', () => {
      // Mark this email's warning as dismissed
      this.dismissedWarnings.set(emailData.id, true);
      warning.remove();
    });
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  setupLinkInterception() {
    // Use event delegation on document body for better compatibility with dynamic content
    // Remove old listener if exists
    if (this.linkClickHandler) {
      document.body.removeEventListener('click', this.linkClickHandler, true);
    }
    
    // Create new handler
    this.linkClickHandler = (event) => {
      // Find the closest link element
      let linkElement = event.target;
      while (linkElement && linkElement.tagName !== 'A') {
        linkElement = linkElement.parentElement;
      }
      
      if (linkElement && linkElement.tagName === 'A') {
        this.handleLinkClick(event, linkElement);
      }
    };
    
    // Add event listener in capture phase to intercept early
    document.body.addEventListener('click', this.linkClickHandler, true);
  }

  handleLinkClick(event, linkElement) {
    const href = linkElement.getAttribute('href');
    if (!href) return;

    // Skip navigation links
    if (this.isNavigationLink(href)) return;

    // Resolve URL
    let targetUrl;
    try {
      targetUrl = this.resolveUrl(href).toLowerCase();
    } catch (e) {
      return; // Invalid URL, let it proceed
    }

    // Check if this is a suspicious link
    const linkAnalysis = this.suspiciousLinks.get(targetUrl);
    
    if (linkAnalysis && linkAnalysis.score > 0) {
      // Prevent default navigation
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();

      // Show warning modal
      this.showLinkWarningModal(targetUrl, linkAnalysis, () => {
        // User confirmed - allow navigation
        window.open(href, linkElement.target || '_self');
      });

      return false;
    }
  }

  showLinkWarningModal(url, linkAnalysis, onConfirm) {
    // Remove existing modal if any
    const existingModal = document.getElementById('safemail-link-warning-modal');
    if (existingModal) {
      existingModal.remove();
    }

    // Create modal overlay
    const modal = document.createElement('div');
    modal.id = 'safemail-link-warning-modal';
    modal.className = 'safemail-modal-overlay';
    
    const riskLevel = linkAnalysis.score >= 7 ? 'high' : 'medium';
    const riskColor = riskLevel === 'high' ? '#dc3545' : '#fd7e14';
    const riskText = riskLevel === 'high' ? 'HIGH RISK' : 'MEDIUM RISK';

    modal.innerHTML = `
      <div class="safemail-modal-content">
        <div class="safemail-modal-header" style="background-color: ${riskColor};">
          <div class="safemail-modal-logo">
            <span style="font-size: 24px;">🛡️</span>
            <strong style="margin-left: 8px;">SafeMail Warning</strong>
          </div>
          <button class="safemail-modal-close">×</button>
        </div>
        <div class="safemail-modal-body">
          <div class="safemail-warning-icon" style="color: ${riskColor};">
            ⚠️
          </div>
          <h3 style="color: ${riskColor}; margin: 12px 0;">Suspicious Link Detected: ${riskText}</h3>
          <p style="margin: 12px 0; font-weight: 500;">You are about to visit a potentially dangerous website:</p>
          <div class="safemail-url-display">
            <code>${this.escapeHtml(url.substring(0, 60))}${url.length > 60 ? '...' : ''}</code>
          </div>
          <div class="safemail-issues-list">
            <strong>Issues Found:</strong>
            <ul>
              ${linkAnalysis.issues.map(issue => `<li>${this.escapeHtml(issue)}</li>`).join('')}
            </ul>
          </div>
          <div class="safemail-modal-buttons">
            <button class="safemail-btn-cancel">Cancel</button>
            <button class="safemail-btn-proceed" style="background-color: ${riskColor};">
              Proceed Anyway
            </button>
          </div>
        </div>
      </div>
    `;

    // Store callback
    window.safemailConfirmCallback = onConfirm;

    // Add to page
    document.body.appendChild(modal);

    // Add event listeners
    const closeBtn = modal.querySelector('.safemail-modal-close');
    const cancelBtn = modal.querySelector('.safemail-btn-cancel');
    const proceedBtn = modal.querySelector('.safemail-btn-proceed');

    const closeModal = () => {
      modal.remove();
      window.safemailConfirmCallback = null;
    };

    closeBtn.addEventListener('click', closeModal);
    cancelBtn.addEventListener('click', closeModal);
    
    proceedBtn.addEventListener('click', () => {
      modal.remove();
      if (window.safemailConfirmCallback) {
        window.safemailConfirmCallback();
        window.safemailConfirmCallback = null;
      }
    });

    // Close on overlay click
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.remove();
        window.safemailConfirmCallback = null;
      }
    });

    // Close on Escape key
    const escapeHandler = (e) => {
      if (e.key === 'Escape' && document.getElementById('safemail-link-warning-modal')) {
        document.getElementById('safemail-link-warning-modal').remove();
        window.safemailConfirmCallback = null;
        document.removeEventListener('keydown', escapeHandler);
      }
    };
    document.addEventListener('keydown', escapeHandler);
  }
}

// Initialize when script loads
if (typeof PhishingScanner !== 'undefined') {
  new EmailContentExtractor();
} else {
  // Wait for scanner.js to load
  window.addEventListener('load', () => {
    if (typeof PhishingScanner !== 'undefined') {
      new EmailContentExtractor();
    }
  });
}

