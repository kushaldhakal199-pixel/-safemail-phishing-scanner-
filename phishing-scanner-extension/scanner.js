/**
 * Phishing Email Scanner
 * Core detection logic for phishing attempts
 */

class PhishingScanner {
  constructor() {
    // Suspicious keywords
    this.suspiciousKeywords = [
      'urgent', 'verify', 'suspended', 'locked', 'expired', 'confirm',
      'update', 'security', 'alert', 'warning', 'immediately', 'action required',
      'click here', 'verify account', 'password reset', 'account disabled',
      'suspended account', 'verify identity', 'unusual activity', 'limited time',
      'act now', 'click below', 'verify now', 'confirm your identity'
    ];

    // URL shortening services
    this.urlShorteners = [
      'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
      'short.link', 'is.gd', 'v.gd', 'rebrand.ly', 'cutt.ly', 'shorturl.at'
    ];

    // Free email services (often used for impersonation)
    this.freeEmailServices = [
      'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
      'mail.com', 'protonmail.com', 'yandex.com', 'zoho.com', 'icloud.com'
    ];

    // Common lookalike character substitutions
    this.lookalikeChars = {
      'o': ['0', 'o'],
      'i': ['1', 'i', 'l'],
      'a': ['@', 'a'],
      'e': ['3', 'e'],
      's': ['5', 's'],
      'g': ['9', 'g']
    };

    // Known legitimate domains (can be expanded)
    this.knownLegitimateDomains = [
      'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com',
      'ebay.com', 'facebook.com', 'twitter.com', 'linkedin.com', 'github.com'
    ];

    // Dangerous file extensions (malware/payload)
    this.dangerousExtensions = [
      '.exe', '.bat', '.cmd', '.com', '.scr', '.vbs', '.js', '.jar',
      '.apk', '.deb', '.rpm', '.msi', '.dmg', '.pkg', '.app',
      '.ps1', '.sh', '.py', '.pl', '.rb', '.php'
    ];

    // Suspicious file extensions (often used for malware)
    this.suspiciousExtensions = [
      '.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.img',
      '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm'
    ];

    // Malicious patterns in file names
    this.maliciousFileNamePatterns = [
      /invoice/i, /payment/i, /receipt/i, /document/i, /scan/i,
      /urgent/i, /important/i, /readme/i, /install/i, /update/i,
      /\.exe\.(pdf|doc|jpg|png)$/i, // Double extension trick
      /^[a-z0-9]{8,}\.(exe|bat|scr|vbs)$/i // Random name + dangerous ext
    ];

    // PDF malicious patterns (JavaScript, embedded files, etc.)
    this.pdfMaliciousPatterns = [
      /\/JavaScript/i,
      /\/JS\s/i,
      /\/OpenAction/i,
      /\/Launch/i,
      /\/URI\s/i,
      /\/GoToR/i,
      /\/RichMedia/i,
      /\/EmbeddedFile/i
    ];

    // DOC/DOCX malicious patterns (macros, embedded objects)
    this.docMaliciousPatterns = [
      /vba/i,
      /macro/i,
      /oleobject/i,
      /embedded/i,
      /automat/i,
      /wscript/i,
      /shell/i,
      /powershell/i
    ];
  }

  /**
   * Main scan function - analyzes email and returns risk assessment
   */
  scanEmail(emailData) {
    const results = {
      riskLevel: 'safe', // safe, medium, high
      score: 0,
      issues: [],
      links: [],
      sender: null
    };

    // Analyze sender
    if (emailData.sender) {
      results.sender = this.analyzeSender(emailData.sender);
      results.score += results.sender.score;
      results.issues.push(...results.sender.issues);
    }

    // Analyze links
    if (emailData.links && emailData.links.length > 0) {
      emailData.links.forEach(link => {
        const linkAnalysis = this.analyzeLink(link);
        results.links.push(linkAnalysis);
        results.score += linkAnalysis.score;
        results.issues.push(...linkAnalysis.issues);
      });
    }

    // Analyze content
    if (emailData.content) {
      const contentAnalysis = this.analyzeContent(emailData.content);
      results.score += contentAnalysis.score;
      results.issues.push(...contentAnalysis.issues);
    }

    // Analyze attachments (files)
    if (emailData.attachments && emailData.attachments.length > 0) {
      emailData.attachments.forEach(attachment => {
        const attachmentAnalysis = this.analyzeAttachment(attachment);
        results.score += attachmentAnalysis.score;
        results.issues.push(...attachmentAnalysis.issues);
        if (!results.attachments) results.attachments = [];
        results.attachments.push(attachmentAnalysis);
      });
    }

    // Determine risk level
    if (results.score >= 10) {
      results.riskLevel = 'high';
    } else if (results.score >= 5) {
      results.riskLevel = 'medium';
    } else {
      results.riskLevel = 'safe';
    }

    return results;
  }

  /**
   * Analyze sender information
   */
  analyzeSender(sender) {
    const analysis = {
      score: 0,
      issues: [],
      displayName: sender.displayName || '',
      email: sender.email || '',
      domain: this.extractDomain(sender.email || '')
    };

    // Check for display name spoofing
    if (sender.displayName && sender.email) {
      const displayDomain = this.extractDomainFromDisplayName(sender.displayName);
      const emailDomain = analysis.domain;
      
      if (displayDomain && emailDomain && displayDomain !== emailDomain) {
        // Check if display name claims to be from a different domain
        if (this.knownLegitimateDomains.some(legit => 
          displayDomain.includes(legit) && !emailDomain.includes(legit)
        )) {
          analysis.score += 8;
          analysis.issues.push('Display name spoofing detected - name claims different domain than email');
        }
      }
    }

    // Check if using free email service for business impersonation
    if (analysis.domain) {
      const isFreeEmail = this.freeEmailServices.some(service => 
        analysis.domain.toLowerCase().includes(service)
      );
      
      if (isFreeEmail && sender.displayName) {
        // Check if display name suggests a business
        const businessKeywords = ['support', 'security', 'admin', 'noreply', 'service', 'team'];
        const hasBusinessKeyword = businessKeywords.some(keyword => 
          sender.displayName.toLowerCase().includes(keyword)
        );
        
        if (hasBusinessKeyword) {
          analysis.score += 3;
          analysis.issues.push('Free email service used with business-like display name');
        }
      }
    }

    // Check for suspicious email patterns
    if (analysis.email) {
      // Check for random-looking email addresses
      const randomPattern = /^[a-z0-9]{8,}@/i;
      if (randomPattern.test(analysis.email) && !analysis.domain.includes('gmail')) {
        analysis.score += 2;
        analysis.issues.push('Suspicious random-looking email address');
      }
    }

    return analysis;
  }

  /**
   * Analyze individual link
   */
  analyzeLink(link) {
    const analysis = {
      url: link.url || '',
      displayText: link.displayText || '',
      score: 0,
      issues: []
    };

    if (!analysis.url) return analysis;

    try {
      const url = new URL(analysis.url);
      const domain = url.hostname.toLowerCase();

      // Check for non-HTTPS
      if (url.protocol !== 'https:') {
        analysis.score += 5;
        analysis.issues.push('Non-HTTPS URL detected');
      }

      // Check for IP address instead of domain
      const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (ipPattern.test(domain)) {
        analysis.score += 8;
        analysis.issues.push('IP address used instead of domain name');
      }

      // Check for URL shorteners
      if (this.urlShorteners.some(shortener => domain.includes(shortener))) {
        analysis.score += 4;
        analysis.issues.push('URL shortening service detected');
      }

      // Check for lookalike domains
      const lookalikeCheck = this.checkLookalikeDomain(domain);
      if (lookalikeCheck.isLookalike) {
        analysis.score += 7;
        analysis.issues.push(`Possible lookalike domain: ${lookalikeCheck.reason}`);
      }

      // Check for mismatched display text vs URL
      if (analysis.displayText) {
        const displayDomain = this.extractDomainFromText(analysis.displayText);
        if (displayDomain && domain !== displayDomain && 
            !domain.includes(displayDomain) && !displayDomain.includes(domain)) {
          // Check if display text claims to be a legitimate domain
          if (this.knownLegitimateDomains.some(legit => 
            displayDomain.includes(legit) && !domain.includes(legit)
          )) {
            analysis.score += 9;
            analysis.issues.push(`Link text shows "${displayDomain}" but URL points to "${domain}"`);
          }
        }
      }

      // Check for suspicious subdomains
      const subdomainCount = (domain.match(/\./g) || []).length;
      if (subdomainCount > 3) {
        analysis.score += 2;
        analysis.issues.push('Suspicious number of subdomains');
      }

      // Check for typosquatting patterns
      if (this.checkTyposquatting(domain)) {
        analysis.score += 6;
        analysis.issues.push('Possible typosquatting detected');
      }

    } catch (e) {
      // Invalid URL
      analysis.score += 3;
      analysis.issues.push('Invalid or malformed URL');
    }

    return analysis;
  }

  /**
   * Analyze email content
   */
  analyzeContent(content) {
    const analysis = {
      score: 0,
      issues: []
    };

    const lowerContent = content.toLowerCase();

    // Check for suspicious keywords
    const foundKeywords = this.suspiciousKeywords.filter(keyword => 
      lowerContent.includes(keyword.toLowerCase())
    );

    if (foundKeywords.length > 0) {
      analysis.score += Math.min(foundKeywords.length * 0.5, 5);
      analysis.issues.push(`Suspicious keywords found: ${foundKeywords.slice(0, 5).join(', ')}`);
    }

    // Check for excessive urgency
    const urgencyWords = ['urgent', 'immediately', 'asap', 'right now', 'act now'];
    const urgencyCount = urgencyWords.filter(word => lowerContent.includes(word)).length;
    if (urgencyCount >= 2) {
      analysis.score += 3;
      analysis.issues.push('Excessive urgency language detected');
    }

    // Check for poor grammar/spelling (basic check)
    const commonTypos = ['recieve', 'seperate', 'occured', 'accomodate'];
    const typoCount = commonTypos.filter(typo => lowerContent.includes(typo)).length;
    if (typoCount > 0) {
      analysis.score += 1;
      analysis.issues.push('Possible spelling errors detected');
    }

    return analysis;
  }

  /**
   * Check for lookalike domains
   */
  checkLookalikeDomain(domain) {
    for (const legitDomain of this.knownLegitimateDomains) {
      // Check for character substitutions
      const variations = this.generateLookalikeVariations(legitDomain);
      if (variations.some(variation => domain.includes(variation) || variation.includes(domain))) {
        return {
          isLookalike: true,
          reason: `Similar to ${legitDomain} with character substitution`
        };
      }

      // Check for added/removed characters
      if (this.isSimilarDomain(domain, legitDomain)) {
        return {
          isLookalike: true,
          reason: `Similar to ${legitDomain} (possible typosquatting)`
        };
      }
    }

    return { isLookalike: false };
  }

  /**
   * Generate lookalike variations of a domain
   */
  generateLookalikeVariations(domain) {
    const variations = [];
    const chars = domain.split('');

    chars.forEach((char, index) => {
      if (this.lookalikeChars[char]) {
        this.lookalikeChars[char].forEach(sub => {
          if (sub !== char) {
            const variation = [...chars];
            variation[index] = sub;
            variations.push(variation.join(''));
          }
        });
      }
    });

    return variations;
  }

  /**
   * Check if two domains are similar (typosquatting)
   */
  isSimilarDomain(domain1, domain2) {
    // Simple Levenshtein-like check
    const longer = domain1.length > domain2.length ? domain1 : domain2;
    const shorter = domain1.length > domain2.length ? domain2 : domain1;

    if (longer.length - shorter.length > 2) return false;

    // Check if one is contained in the other with small differences
    if (longer.includes(shorter) || shorter.includes(longer)) {
      return true;
    }

    // Count character differences
    let differences = 0;
    const minLength = Math.min(domain1.length, domain2.length);
    for (let i = 0; i < minLength; i++) {
      if (domain1[i] !== domain2[i]) differences++;
    }
    differences += Math.abs(domain1.length - domain2.length);

    return differences <= 2 && minLength >= 5;
  }

  /**
   * Check for typosquatting patterns
   */
  checkTyposquatting(domain) {
    // Remove common TLDs for comparison
    const domainWithoutTld = domain.replace(/\.(com|net|org|co|io|gov|edu)$/, '');
    
    for (const legitDomain of this.knownLegitimateDomains) {
      const legitWithoutTld = legitDomain.replace(/\.(com|net|org|co|io|gov|edu)$/, '');
      if (this.isSimilarDomain(domainWithoutTld, legitWithoutTld)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Extract domain from email address
   */
  extractDomain(email) {
    if (!email) return '';
    const match = email.match(/@([^\s<>]+)/);
    return match ? match[1].toLowerCase() : '';
  }

  /**
   * Extract domain from display name or text
   */
  extractDomainFromDisplayName(text) {
    // Look for domain-like patterns in display name
    const domainPattern = /([a-z0-9-]+\.(com|net|org|co|io|gov|edu))/i;
    const match = text.match(domainPattern);
    return match ? match[1].toLowerCase() : null;
  }

  /**
   * Extract domain from link text
   */
  extractDomainFromText(text) {
    try {
      // Try to parse as URL
      if (text.startsWith('http://') || text.startsWith('https://')) {
        const url = new URL(text);
        return url.hostname.toLowerCase();
      }
      // Look for domain pattern
      const domainPattern = /([a-z0-9-]+\.(com|net|org|co|io|gov|edu))/i;
      const match = text.match(domainPattern);
      return match ? match[1].toLowerCase() : null;
    } catch (e) {
      return null;
    }
  }

  /**
   * Analyze email attachment for malware/payload
   */
  analyzeAttachment(attachment) {
    const analysis = {
      fileName: attachment.name || attachment.fileName || '',
      fileType: attachment.type || '',
      fileSize: attachment.size || 0,
      score: 0,
      issues: [],
      riskLevel: 'safe'
    };

    if (!analysis.fileName) {
      return analysis;
    }

    const fileName = analysis.fileName.toLowerCase();
    const fileExtension = this.getFileExtension(fileName);

    // Check for dangerous file extensions
    if (this.dangerousExtensions.includes(fileExtension)) {
      analysis.score += 10;
      analysis.riskLevel = 'high';
      
      if (fileExtension === '.apk') {
        analysis.issues.push('⚠️ APK file detected - Android applications can contain malware');
      } else if (fileExtension === '.exe') {
        analysis.issues.push('⚠️ EXE file detected - Executable files can contain malware or viruses');
      } else if (['.bat', '.cmd', '.vbs', '.ps1'].includes(fileExtension)) {
        analysis.issues.push(`⚠️ ${fileExtension.toUpperCase()} script file detected - Scripts can execute malicious code`);
      } else {
        analysis.issues.push(`⚠️ Dangerous file type detected: ${fileExtension.toUpperCase()} - Can contain malware`);
      }
    }

    // Check for suspicious file extensions
    if (this.suspiciousExtensions.includes(fileExtension)) {
      analysis.score += 3;
      if (analysis.riskLevel === 'safe') analysis.riskLevel = 'medium';
      analysis.issues.push(`⚠️ Suspicious archive file: ${fileExtension.toUpperCase()} - May contain hidden malware`);
    }

    // Check for double extension trick (e.g., document.pdf.exe)
    const doubleExtPattern = /\.(pdf|doc|docx|xls|xlsx|jpg|png|gif)\.(exe|bat|scr|vbs|js|jar|apk)$/i;
    if (doubleExtPattern.test(fileName)) {
      analysis.score += 12;
      analysis.riskLevel = 'high';
      analysis.issues.push('🚨 DOUBLE EXTENSION TRICK detected - File appears safe but is actually executable malware');
    }

    // Check for malicious file name patterns
    for (const pattern of this.maliciousFileNamePatterns) {
      if (pattern.test(fileName)) {
        if (this.dangerousExtensions.includes(fileExtension)) {
          analysis.score += 5;
          analysis.issues.push(`⚠️ Suspicious file name pattern with dangerous extension: "${fileName}"`);
        }
      }
    }

    // Check for PDF files (potential for embedded malware)
    if (fileExtension === '.pdf') {
      analysis.score += 2;
      if (analysis.riskLevel === 'safe') analysis.riskLevel = 'medium';
      analysis.issues.push('⚠️ PDF file detected - PDFs can contain embedded JavaScript or malicious content');
      
      // Check file content if available
      if (attachment.content || attachment.text) {
        const pdfContent = (attachment.content || attachment.text).toLowerCase();
        for (const pattern of this.pdfMaliciousPatterns) {
          if (pattern.test(pdfContent)) {
            analysis.score += 8;
            analysis.riskLevel = 'high';
            analysis.issues.push('🚨 PDF contains potentially malicious JavaScript or embedded objects');
            break;
          }
        }
      }
    }

    // Check for DOC/DOCX files (potential for macros)
    if (['.doc', '.docx', '.docm', '.dotm'].includes(fileExtension)) {
      analysis.score += 3;
      if (analysis.riskLevel === 'safe') analysis.riskLevel = 'medium';
      analysis.issues.push('⚠️ Word document detected - Documents can contain malicious macros or embedded objects');
      
      // Check file content if available
      if (attachment.content || attachment.text) {
        const docContent = (attachment.content || attachment.text).toLowerCase();
        for (const pattern of this.docMaliciousPatterns) {
          if (pattern.test(docContent)) {
            analysis.score += 10;
            analysis.riskLevel = 'high';
            analysis.issues.push('🚨 Document contains potentially malicious macros or embedded code');
            break;
          }
        }
      }
    }

    // Check for suspiciously large files (potential payload)
    if (analysis.fileSize > 10 * 1024 * 1024) { // > 10MB
      if (this.dangerousExtensions.includes(fileExtension)) {
        analysis.score += 4;
        analysis.issues.push(`⚠️ Large file size (${(analysis.fileSize / 1024 / 1024).toFixed(1)}MB) with dangerous extension - Possible payload`);
      }
    }

    // Check for random-looking file names (common in malware)
    const randomNamePattern = /^[a-z0-9]{12,}\.(exe|bat|scr|vbs|js|jar|apk)$/i;
    if (randomNamePattern.test(fileName)) {
      analysis.score += 6;
      if (analysis.riskLevel === 'safe') analysis.riskLevel = 'medium';
      analysis.issues.push('⚠️ Random-looking file name with dangerous extension - Common malware pattern');
    }

    return analysis;
  }

  /**
   * Get file extension from filename
   */
  getFileExtension(fileName) {
    const lastDot = fileName.lastIndexOf('.');
    if (lastDot === -1) return '';
    return fileName.substring(lastDot).toLowerCase();
  }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = PhishingScanner;
}

