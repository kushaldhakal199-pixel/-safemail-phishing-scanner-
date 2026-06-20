/**
 * SafeMail Pro v4.0 — Deep Scan Engine
 * Scans every email the moment it opens. Reports SAFE or threat level.
 * No external APIs — 100% local, instant results.
 */

class PhishingScanner {
  constructor() {

    this.suspiciousKeywords = [
      'urgent','verify','suspended','locked','expired','confirm','update',
      'security alert','warning','immediately','action required','click here',
      'verify account','password reset','account disabled','verify identity',
      'unusual activity','limited time','act now','verify now',
      'confirm your identity','your account has been','we noticed',
      'sign in to restore','access will be terminated','temporary hold',
      'validate your account','billing information','payment declined',
      'invoice attached','wire transfer','bank account details','send gift card',
      'gift card codes','purchase itunes','purchase google play',
      'do not forward','do not share','keep this confidential',
      'tax refund','irs notice','delivery failed','parcel held',
      'customs fee','your mailbox is full','quota exceeded',
      'click the link below','your account will be','we have detected',
      'your information','kindly update','dear customer','dear user',
      'dear valued','we are writing to inform'
    ];

    this.becKeywords = [
      'wire transfer','bank account','urgent payment','ceo request',
      'executive request','do not discuss','keep confidential',
      'acquisition','new vendor','new bank details','change payment',
      'update banking','gift card','itunes card','google play card',
      'steam card','target gift card','western union','moneygram',
      'send funds','transfer funds','process payment'
    ];

    this.urlShorteners = [
      'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','buff.ly','short.link',
      'is.gd','v.gd','rebrand.ly','cutt.ly','shorturl.at','tiny.cc','rb.gy',
      'shorte.st','adf.ly','bc.vc','mcaf.ee','fb.me','lnkd.in','wp.me',
      'amzn.to','ift.tt','cli.gs','su.pr','tr.im','snurl.com','po.st',
      'youtu.be','ow.ly','dlvr.it','buff.ly','ht.ly','j.mp'
    ];

    this.freeEmailServices = [
      'gmail.com','yahoo.com','hotmail.com','outlook.com','aol.com',
      'mail.com','protonmail.com','yandex.com','zoho.com','icloud.com',
      'gmx.com','tutanota.com','mail.ru','qq.com','163.com','126.com',
      'sina.com','live.com','msn.com','me.com','inbox.com','fastmail.com',
      'hushmail.com','mailfence.com','runbox.com','dispostable.com',
      'guerrillamail.com','tempmail.com','throwam.com','mailinator.com',
      'sharklasers.com','10minutemail.com','trashmail.com','yopmail.com',
      'maildrop.cc','spamgourmet.com','spamgourmet.org'
    ];

    this.knownLegitimateDomains = [
      'google.com','microsoft.com','apple.com','amazon.com','paypal.com',
      'ebay.com','facebook.com','twitter.com','linkedin.com','github.com',
      'netflix.com','instagram.com','whatsapp.com','dropbox.com','adobe.com',
      'salesforce.com','zoom.us','slack.com','stripe.com','shopify.com',
      'godaddy.com','cloudflare.com','bankofamerica.com','chase.com',
      'wellsfargo.com','citi.com','americanexpress.com','dhl.com',
      'fedex.com','ups.com','usps.com','irs.gov','gov.uk','canada.ca',
      'twitter.com','tiktok.com','youtube.com','reddit.com','discord.com',
      'steam.com','epicgames.com','ea.com','blizzard.com','roblox.com',
      'twitch.tv','spotify.com','apple.com','samsung.com','hp.com',
      'dell.com','lenovo.com','nvidia.com','amd.com','intel.com'
    ];

    // EXECUTABLE & DANGEROUS — HIGH RISK
    this.executableExtensions = [
      '.exe','.bat','.cmd','.com','.scr','.pif','.cpl','.inf',
      '.msi','.msp','.mst',
      '.ps1','.psm1','.psd1',  // PowerShell
      '.vbs','.vbe','.wsh','.wsf', // VBScript/Windows Script
      '.hta',                  // HTML Application (runs as admin)
      '.jse','.js',            // JScript
      '.jar','.jnlp',          // Java
      '.apk','.aab',           // Android
      '.ipa',                  // iOS sideload
      '.deb','.rpm',           // Linux packages
      '.dmg','.pkg','.app',    // macOS
      '.sh','.bash','.zsh','.ksh', // Shell scripts
      '.py','.pyw','.pyc',     // Python
      '.rb','.pl','.php',      // Scripting
      '.lnk','.url',           // Shortcuts (can execute payload)
      '.reg',                  // Registry modification
      '.iso','.img','.vhd','.vhdx', // Disk images (can autorun)
      '.chm',                  // Compiled HTML Help (scriptable)
      '.xbap',                 // XAML Browser App
      '.gadget'                // Windows Gadget
    ];

    // SUSPICIOUS ARCHIVES & MACRO-ENABLED DOCS — MEDIUM RISK
    this.suspiciousExtensions = [
      '.zip','.rar','.7z','.tar','.gz','.bz2','.xz','.cab','.ace',
      '.docm','.dotm','.xlsm','.xltm','.xlam','.pptm','.potm','.ppam',
      '.xlsb',  // Excel binary (macros hidden)
    ];

    // MAGIC BYTES for executable detection by content (first bytes)
    // Useful when extension is spoofed (e.g. evil.pdf is actually an EXE)
    this.magicBytes = {
      'MZ':         { type: 'Windows EXE/DLL', risk: 'high' },
      'PK\x03\x04': { type: 'ZIP/APK/JAR', risk: 'medium' },
      '7z\xBC\xAF': { type: '7-Zip archive', risk: 'medium' },
      'Rar!':        { type: 'RAR archive', risk: 'medium' },
      '\x7FELF':     { type: 'Linux ELF executable', risk: 'high' },
      '\xCA\xFE\xBA\xBE': { type: 'Java class / Mach-O fat binary', risk: 'high' },
      '\xFE\xED\xFA\xCE': { type: 'macOS Mach-O 32-bit', risk: 'high' },
      '\xFE\xED\xFA\xCF': { type: 'macOS Mach-O 64-bit', risk: 'high' },
      '\xCE\xFA\xED\xFE': { type: 'macOS Mach-O (LE)', risk: 'high' },
      '\xCF\xFA\xED\xFE': { type: 'macOS Mach-O 64 (LE)', risk: 'high' },
      'ANDROIDBIN':  { type: 'Android binary', risk: 'high' }
    };

    this.homoglyphs = {
      '\u0430':'a','\u0435':'e','\u043E':'o','\u0440':'p','\u0441':'c',
      '\u0445':'x','\u0443':'y','\u0456':'i','\u04CF':'l','\u0458':'j',
      '\u03BF':'o','\u03C1':'p','\u03B1':'a','\u03B5':'e','\u03BD':'v',
      '\u0AB0':'r','\u0561':'a','\u0578':'o','\u057D':'s',
      '0':'o','1':'l','3':'e','4':'a','5':'s','7':'t','8':'b','@':'a'
    };

    this.lookalikeChars = {
      'o':['0'],'i':['1','l'],'a':['@'],'e':['3'],'s':['5'],'g':['9'],'t':['7'],'b':['8']
    };
  }

  // ── MAIN SCAN ──────────────────────────────────────────────────────
  scanEmail(emailData) {
    const result = {
      riskLevel: 'safe',
      score: 0,
      issues: [],
      categories: [],
      links: [],
      attachments: [],
      sender: null,
      iocs: [],
      scannedAt: Date.now()
    };

    if (emailData.sender) {
      const s = this.analyzeSender(emailData.sender, emailData.headers || {});
      result.sender = s;
      result.score += s.score;
      result.issues.push(...s.issues);
      result.iocs.push(...(s.iocs || []));
      if (s.category) result.categories.push(s.category);
    }

    (emailData.links || []).forEach(link => {
      const l = this.analyzeLink(link);
      result.links.push(l);
      result.score += l.score;
      result.issues.push(...l.issues);
      if (l.ioc) result.iocs.push(l.ioc);
    });

    if (emailData.content) {
      const c = this.analyzeContent(emailData.content, emailData.subject || '');
      result.score += c.score;
      result.issues.push(...c.issues);
      if (c.isBEC) result.categories.push('BEC Fraud');
      if (c.isPhishing) result.categories.push('Phishing');
    }

    (emailData.attachments || []).forEach(att => {
      const a = this.analyzeAttachment(att);
      result.attachments.push(a);
      result.score += a.score;
      result.issues.push(...a.issues);
      if (a.score >= 10) result.categories.push('Malware');
    });

    // De-duplicate
    result.issues     = [...new Set(result.issues)];
    result.categories = [...new Set(result.categories)];

    if (result.score >= 10)     result.riskLevel = 'high';
    else if (result.score >= 5) result.riskLevel = 'medium';
    else                        result.riskLevel = 'safe';

    return result;
  }

  // ── SENDER ─────────────────────────────────────────────────────────
  analyzeSender(sender, headers) {
    const r = {
      score: 0, issues: [], iocs: [], category: null,
      displayName: sender.displayName || '',
      email: sender.email || '',
      domain: this.extractDomain(sender.email || '')
    };

    // Display name spoofing
    if (sender.displayName && sender.email) {
      const dd = this.extractDomainFromText(sender.displayName);
      const ed = r.domain;
      if (dd && ed && dd !== ed && this.knownLegitimateDomains.some(l => dd.includes(l) && !ed.includes(l))) {
        r.score += 8;
        r.issues.push('Sender display name claims to be ' + dd + ' but email is from ' + ed);
        r.category = 'Spoofing';
        r.iocs.push({ type: 'Domain', value: ed, note: 'Spoofed sender' });
      }
    }

    // Free email pretending to be business
    if (r.domain && this.freeEmailServices.some(s => r.domain.includes(s))) {
      const bizTerms = ['support','security','admin','noreply','no-reply','service',
                        'team','billing','helpdesk','alert','account','update','verify','info'];
      if (bizTerms.some(t => r.displayName.toLowerCase().includes(t))) {
        r.score += 4;
        r.issues.push('Business-like name "' + r.displayName + '" sent from free email service (' + r.domain + ')');
      }
    }

    // Homoglyph in domain
    const normalized = this.normalizeHomoglyphs(r.domain);
    if (normalized !== r.domain) {
      r.score += 7;
      r.issues.push('Unicode/homoglyph characters in sender domain: ' + r.domain);
      r.category = 'Spoofing';
    }

    // Reply-To mismatch
    if (headers.replyTo) {
      const rd = this.extractDomain(headers.replyTo);
      if (rd && rd !== r.domain && !rd.includes(r.domain) && !r.domain.includes(rd)) {
        r.score += 6;
        r.issues.push('Reply-To goes to different domain: ' + rd + ' (email from: ' + r.domain + ')');
        r.category = r.category || 'BEC Fraud';
      }
    }

    // High entropy domain (DGA / randomly generated)
    const base = r.domain.split('.')[0] || '';
    if (base.length >= 8 && this.entropy(base) > 3.5) {
      r.score += 3;
      r.issues.push('Randomly-generated sender domain detected: ' + r.domain);
    }

    // Typosquatting
    if (this.checkTyposquatting(r.domain)) {
      r.score += 5;
      r.issues.push('Sender domain resembles a known brand (typosquatting): ' + r.domain);
      r.category = r.category || 'Spoofing';
    }

    return r;
  }

  // ── LINKS ──────────────────────────────────────────────────────────
  analyzeLink(link) {
    const r = { url: link.url || '', displayText: link.displayText || '', score: 0, issues: [], ioc: null };
    if (!r.url) return r;

    try {
      const u = new URL(r.url);
      const d = u.hostname.toLowerCase();

      if (u.protocol !== 'https:') { r.score += 5; r.issues.push('Insecure HTTP link (not encrypted)'); }

      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(d)) {
        r.score += 8; r.issues.push('Link uses raw IP address: ' + d);
        r.ioc = { type: 'IP', value: d, note: 'Direct IP link' };
      }

      if (this.urlShorteners.some(s => d === s || d.endsWith('.' + s))) {
        r.score += 4; r.issues.push('URL shortener hides real destination (' + d + ')');
      }

      const norm = this.normalizeHomoglyphs(d);
      if (norm !== d) { r.score += 9; r.issues.push('Homoglyph/Unicode spoofing in URL: ' + d); r.ioc = { type: 'Domain', value: d, note: 'Homoglyph domain' }; }

      const lk = this.checkLookalikeDomain(d);
      if (lk.is) { r.score += 7; r.issues.push('Lookalike domain: ' + lk.reason); r.ioc = r.ioc || { type: 'Domain', value: d, note: lk.reason }; }

      if (this.checkTyposquatting(d)) { r.score += 5; r.issues.push('Typosquatting: ' + d + ' resembles a known brand'); }

      if (r.displayText) {
        const td = this.extractDomainFromText(r.displayText);
        if (td && td !== d && !d.includes(td) && !td.includes(d) &&
            this.knownLegitimateDomains.some(l => td.includes(l) && !d.includes(l))) {
          r.score += 9; r.issues.push('Link says "' + td + '" but actually goes to "' + d + '"');
        }
      }

      if ((d.match(/\./g) || []).length > 3) { r.score += 2; r.issues.push('Suspicious deep subdomain: ' + d); }

      const baseDom = d.split('.').slice(-2, -1)[0] || '';
      if (baseDom.length >= 8 && this.entropy(baseDom) > 3.5) { r.score += 3; r.issues.push('High-entropy URL domain (possible DGA): ' + d); }

      if (r.url.startsWith('data:')) { r.score += 8; r.issues.push('Data URI link detected (common in phishing pages)'); }

      const encodedCount = (r.url.match(/%[0-9a-f]{2}/gi) || []).length;
      if (encodedCount > 6) { r.score += 3; r.issues.push('Heavily URL-encoded link (obfuscation attempt)'); }

    } catch (_) { r.score += 3; r.issues.push('Malformed URL: ' + r.url.substring(0, 50)); }

    return r;
  }

  // ── CONTENT ────────────────────────────────────────────────────────
  analyzeContent(content, subject) {
    const r = { score: 0, issues: [], isBEC: false, isPhishing: false };
    const txt = (content + ' ' + subject).toLowerCase();

    const found = this.suspiciousKeywords.filter(k => txt.includes(k));
    if (found.length > 0) {
      r.score += Math.min(found.length * 0.5, 4);
      r.issues.push('Phishing keywords: ' + found.slice(0, 4).join(', '));
      r.isPhishing = true;
    }

    const bec = this.becKeywords.filter(k => txt.includes(k));
    if (bec.length >= 2) {
      r.score += 6; r.isBEC = true;
      r.issues.push('BEC indicators: ' + bec.slice(0, 3).join(', '));
    }

    const urgency = ['urgent','immediately','asap','right now','act now','expires today','within 24 hours','last chance','respond immediately'];
    if (urgency.filter(w => txt.includes(w)).length >= 2) { r.score += 3; r.issues.push('Excessive urgency language (pressure tactic)'); }

    const cred = ['enter your password','enter your credentials','login to verify','sign in to restore',
                  'provide your account','confirm your ssn','social security','date of birth','mother maiden'];
    if (cred.some(c => txt.includes(c))) { r.score += 5; r.issues.push('Credential harvesting phrases detected'); r.isPhishing = true; }

    const fin = ['bank account number','routing number','swift code','iban','wire transfer',
                 'western union','moneygram','bitcoin wallet','send btc','cryptocurrency'];
    const finFound = fin.filter(f => txt.includes(f));
    if (finFound.length > 0) { r.score += 4; r.issues.push('Financial fraud language: ' + finFound.slice(0, 2).join(', ')); }

    const typos = ['recieve','seperate','occured','accomodate','sucessful','beleive','wierd','priviledge'];
    if (typos.some(t => txt.includes(t))) { r.score += 1; r.issues.push('Spelling errors (common in phishing)'); }

    return r;
  }

  // ── ATTACHMENTS — Deep File Scanning ──────────────────────────────
  analyzeAttachment(att) {
    const r = {
      fileName: att.name || att.fileName || '',
      fileType: att.type || '',
      fileSize: att.size || 0,
      score: 0, issues: [], riskLevel: 'safe',
      detectionMethod: []
    };
    if (!r.fileName) return r;

    const fn  = r.fileName.toLowerCase();
    const ext = this.getExt(fn);

    // ── 0. Extension-spoofing / rename trick detection ──────────────
    // Catch: file.txt renamed to file.png, file.exe renamed to file.jpg, etc.
    // The MIME type or declared fileType doesn't match the extension shown.
    const declaredMime = (att.type || att.mimeType || '').toLowerCase();

    // Map of extensions to what MIME they SHOULD have
    const expectedMime = {
      '.png':  'image/png',   '.jpg':  'image/jpeg', '.jpeg': 'image/jpeg',
      '.gif':  'image/gif',   '.bmp':  'image/bmp',  '.webp': 'image/webp',
      '.svg':  'image/svg',   '.ico':  'image/x-icon',
      '.txt':  'text/plain',  '.csv':  'text/csv',   '.log':  'text/plain',
      '.pdf':  'application/pdf',
      '.mp3':  'audio/mpeg',  '.mp4':  'video/mp4',  '.wav':  'audio/wav',
      '.zip':  'application/zip', '.rar': 'application/x-rar',
      '.docx': 'application/vnd.openxmlformats', '.xlsx': 'application/vnd.openxmlformats'
    };

    // Known image/text/media extensions — safe by themselves
    const harmlessExtensions = [
      '.png','.jpg','.jpeg','.gif','.bmp','.webp','.svg','.ico',
      '.txt','.csv','.log','.md','.xml','.json','.html','.htm',
      '.mp3','.mp4','.wav','.avi','.mkv','.mov','.flac','.ogg',
      '.ttf','.woff','.woff2','.otf'
    ];

    if (harmlessExtensions.includes(ext)) {
      // Check if MIME type contradicts the extension (rename trick)
      if (declaredMime && expectedMime[ext]) {
        const expectedPartial = expectedMime[ext];
        if (!declaredMime.includes(expectedPartial.split('/')[1]) &&
            !declaredMime.includes(expectedPartial.split('/')[0])) {
          r.score += 8; r.riskLevel = 'high';
          r.issues.push('FILE RENAME TRICK: Extension is ' + ext.toUpperCase() + ' but MIME type is "' + declaredMime + '" — file may be disguised');
          r.detectionMethod.push('MIME mismatch: ' + ext + ' vs ' + declaredMime);
        }
      }

      // Even without MIME info: flag if filename pattern is suspicious
      // e.g. "invoice.png", "document.txt", "receipt.jpg" — common lure names
      const lureNames = ['invoice','payment','receipt','document','order','statement',
                         'contract','agreement','notification','alert','warning','urgent',
                         'important','confidential','scan','report','update','readme'];
      const baseName = fn.replace(ext, '');
      if (lureNames.some(l => baseName.includes(l))) {
        r.score += 4; r.riskLevel = r.riskLevel === 'safe' ? 'medium' : r.riskLevel;
        r.issues.push('Suspicious lure filename: "' + r.fileName + '" — attackers rename malicious files as documents/images');
        r.detectionMethod.push('Lure filename');
      }

      // If it's a plain text file disguised as image or vice versa
      const textExts  = ['.txt','.csv','.log','.md','.xml','.json'];
      const imageExts = ['.png','.jpg','.jpeg','.gif','.bmp','.webp'];
      if (textExts.includes(ext) || imageExts.includes(ext)) {
        // Check content if available — plain text content in an "image" is very suspicious
        if (att.content && imageExts.includes(ext)) {
          // Image files should start with specific magic bytes, not readable text
          const startsWithText = /^[a-zA-Z<{\[#"'\/\s]/.test(att.content.substring(0, 20));
          if (startsWithText) {
            r.score += 7; r.riskLevel = 'high';
            r.issues.push('Content mismatch: "' + r.fileName + '" claims to be an image but contains text/script data');
            r.detectionMethod.push('Content-extension mismatch');
          }
        }
      }

      // If no issues found for a harmless extension, give score 0 (truly safe)
      // but still return with riskLevel set correctly
      if (r.score === 0) {
        r.riskLevel = 'safe';
      }
      // Don't return early — still run double extension check below
    }

    // ── 1. Magic byte check (if content available) ──────────────────
    if (att.content || att.bytes) {
      const content = att.content || att.bytes;
      for (const [sig, meta] of Object.entries(this.magicBytes)) {
        if (content.startsWith(sig) || content.includes(sig)) {
          if (meta.risk === 'high') {
            r.score += 12; r.riskLevel = 'high';
            r.issues.push('MAGIC BYTES: File is a ' + meta.type + ' regardless of extension');
            r.detectionMethod.push('Magic bytes: ' + meta.type);
          } else {
            r.score += 4;
            if (r.riskLevel === 'safe') r.riskLevel = 'medium';
            r.issues.push('File signature: ' + meta.type);
            r.detectionMethod.push('Magic bytes: ' + meta.type);
          }
          break;
        }
      }
    }

    // ── 2. Extension-based detection ───────────────────────────────
    if (this.executableExtensions.includes(ext)) {
      const extDetails = {
        '.exe': 'Windows executable — can install malware or ransomware',
        '.bat': 'Batch script — executes system commands',
        '.cmd': 'Command script — executes system commands',
        '.ps1': 'PowerShell script — common malware delivery vector',
        '.vbs': 'VBScript — frequently used in phishing campaigns',
        '.hta': 'HTML Application — runs with admin-level access',
        '.js':  'JavaScript — can execute OS-level code via WScript',
        '.jse': 'Encoded JScript — obfuscated malicious script',
        '.jar': 'Java archive — can execute arbitrary code',
        '.apk': 'Android app — sideload malware, bypasses Play Store',
        '.ipa': 'iOS app — sideload attempt, bypasses App Store',
        '.lnk': 'Shortcut — can point to hidden malicious payload',
        '.reg': 'Registry file — can modify Windows system settings',
        '.scr': 'Screensaver — commonly disguised executable',
        '.msi': 'Windows installer — installs software silently',
        '.dmg': 'macOS disk image — can contain malicious apps',
        '.sh':  'Shell script — executes on Linux/macOS',
        '.py':  'Python script — executes code on your system',
        '.iso': 'Disk image — can contain autorun malware',
        '.vhd': 'Virtual disk — can contain bootable malware',
        '.chm': 'Help file — can execute embedded scripts',
        '.url': 'Internet shortcut — may redirect to phishing site'
      };
      const detail = extDetails[ext] || 'Executable file type — can run malicious code';
      r.score += 10; r.riskLevel = 'high';
      r.issues.push(ext.toUpperCase() + ': ' + detail);
      r.detectionMethod.push('Extension: ' + ext);
    }

    if (this.suspiciousExtensions.includes(ext)) {
      const archiveDetail = ['.docm','.dotm','.xlsm','.xltm','.xlam','.pptm','.potm','.ppam','.xlsb'].includes(ext)
        ? 'Macro-enabled Office document — macros can execute malicious code' : 'Archive file — may conceal dangerous executables';
      r.score += 3;
      if (r.riskLevel === 'safe') r.riskLevel = 'medium';
      r.issues.push(ext.toUpperCase() + ': ' + archiveDetail);
      r.detectionMethod.push('Suspicious extension: ' + ext);
    }

    // ── 3. Double extension trick ───────────────────────────────────
    if (/\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|gif|txt|mp3|mp4)\.(exe|bat|scr|vbs|js|jse|jar|apk|ps1|hta|cmd|lnk|msi)$/i.test(fn)) {
      r.score += 14; r.riskLevel = 'high';
      r.issues.push('DOUBLE EXTENSION TRICK: File looks like a document but is actually an executable — classic malware camouflage');
      r.detectionMethod.push('Double extension');
    }

    // ── 4. Suspicious filename patterns ────────────────────────────
    const suspiciousNames = [
      { pattern: /^[a-f0-9]{32,}\./i, label: 'MD5-hash filename (common in automated malware)' },
      { pattern: /^[a-z0-9]{16,}\.(exe|bat|scr|js|vbs|apk)$/i, label: 'Random filename with dangerous extension' },
      { pattern: /(invoice|payment|receipt|refund|order)[_\-\s]*\d*\.(exe|js|vbs|bat|scr|apk|ps1)/i, label: 'Financial lure filename' },
      { pattern: /(update|install|setup|patch|crack|keygen|loader|injector)\.(exe|bat|msi|dmg|apk)/i, label: 'Software lure filename' },
      { pattern: /\s{2,}/, label: 'Extra whitespace in filename (extension hiding trick)' },
      { pattern: /[\u200B-\u200D\uFEFF]/, label: 'Zero-width characters in filename (extension hiding trick)' },
      { pattern: /\.(doc|pdf|txt)\s*$/i, label: 'Trailing space before extension' }
    ];
    suspiciousNames.forEach(({ pattern, label }) => {
      if (pattern.test(fn) && (r.detectionMethod.length === 0 || r.score > 0)) {
        r.score += 3;
        if (r.riskLevel === 'safe') r.riskLevel = 'medium';
        r.issues.push('Suspicious filename: ' + label);
        r.detectionMethod.push(label);
      }
    });

    // ── 5. PDF specific ─────────────────────────────────────────────
    if (ext === '.pdf') {
      r.score += 2;
      if (r.riskLevel === 'safe') r.riskLevel = 'medium';
      r.issues.push('PDF: Can contain embedded JavaScript, links, or exploits — scan before opening');
      if (att.content) {
        const pdfSigs = ['/JavaScript','/JS ','/OpenAction','/Launch','/EmbeddedFile','/RichMedia','/GoToR'];
        if (pdfSigs.some(s => att.content.includes(s))) {
          r.score += 9; r.riskLevel = 'high';
          r.issues.push('PDF contains embedded JavaScript or launch actions — likely malicious');
          r.detectionMethod.push('PDF malicious signature');
        }
      }
    }

    // ── 6. Office macro docs ────────────────────────────────────────
    if (['.doc','.docx','.xls','.xlsx','.ppt','.pptx'].includes(ext)) {
      r.score += 2;
      if (r.riskLevel === 'safe') r.riskLevel = 'medium';
      r.issues.push(ext.toUpperCase() + ': Office document may contain macros — verify sender before opening');
      if (att.content) {
        const macroSigs = ['vba','macro','oleobject','autoopen','auto_open','workbook_open','wscript','shell','powershell'];
        if (macroSigs.some(s => att.content.toLowerCase().includes(s))) {
          r.score += 10; r.riskLevel = 'high';
          r.issues.push('Office document contains VBA macros or suspicious code — HIGH RISK');
          r.detectionMethod.push('Macro content detected');
        }
      }
    }

    // ── 7. File size anomalies ──────────────────────────────────────
    if (r.fileSize > 0) {
      if (r.fileSize < 1024 && this.executableExtensions.includes(ext)) {
        r.score += 4;
        r.issues.push('Suspiciously tiny executable (' + r.fileSize + ' bytes) — may be a dropper');
      }
      if (r.fileSize > 50 * 1024 * 1024 && ![ '.zip','.rar','.7z','.tar','.gz','.iso','.dmg','.vhd'].includes(ext)) {
        r.score += 2;
        r.issues.push('Unusually large file (' + (r.fileSize/1024/1024).toFixed(1) + ' MB) for this file type');
      }
    }

    return r;
  }

  // ── HELPERS ────────────────────────────────────────────────────────
  normalizeHomoglyphs(str) {
    return str.toLowerCase().split('').map(c => this.homoglyphs[c] || c).join('');
  }

  entropy(str) {
    if (!str.length) return 0;
    const freq = {};
    for (const c of str) freq[c] = (freq[c] || 0) + 1;
    return -Object.values(freq).reduce((acc, f) => {
      const p = f / str.length; return acc + p * Math.log2(p);
    }, 0);
  }

  checkLookalikeDomain(domain) {
    for (const legit of this.knownLegitimateDomains) {
      for (const v of this.generateVariations(legit)) {
        if (v !== legit && (domain === v || domain.endsWith('.' + v))) return { is: true, reason: 'Resembles ' + legit + ' (' + v + ')' };
      }
      if (this.editDistance(domain.split('.').slice(-2).join('.'), legit) <= 2 && domain !== legit) {
        return { is: true, reason: 'Similar spelling to ' + legit };
      }
    }
    return { is: false };
  }

  generateVariations(domain) {
    const vars = [domain];
    const chars = domain.split('');
    chars.forEach((c, i) => {
      (this.lookalikeChars[c] || []).forEach(sub => {
        const v = [...chars]; v[i] = sub; vars.push(v.join(''));
      });
    });
    return vars;
  }

  editDistance(a, b) {
    if (Math.abs(a.length - b.length) > 3) return 99;
    const dp = Array.from({ length: a.length + 1 }, (_, i) =>
      Array.from({ length: b.length + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0));
    for (let i = 1; i <= a.length; i++)
      for (let j = 1; j <= b.length; j++)
        dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    return dp[a.length][b.length];
  }

  checkTyposquatting(domain) {
    const tldStrip = d => d.replace(/\.(com|net|org|co|io|gov|edu|uk|au|us|ca|de|fr|in|ru)$/, '');
    const base = tldStrip(domain);
    return this.knownLegitimateDomains.some(l => {
      const lb = tldStrip(l);
      return base !== lb && this.editDistance(base, lb) <= 2 && lb.length >= 4;
    });
  }

  extractDomain(email) {
    const m = (email || '').match(/@([^\s<>]+)/);
    return m ? m[1].toLowerCase() : '';
  }

  extractDomainFromText(text) {
    try {
      if (/^https?:\/\//.test(text)) return new URL(text).hostname.toLowerCase();
      const m = text.match(/([a-z0-9-]+\.(com|net|org|co|io|gov|edu|uk|au))/i);
      return m ? m[1].toLowerCase() : null;
    } catch (_) { return null; }
  }

  getExt(fn) {
    const i = fn.lastIndexOf('.');
    return i === -1 ? '' : fn.substring(i).toLowerCase();
  }
}

if (typeof module !== 'undefined' && module.exports) module.exports = PhishingScanner;
