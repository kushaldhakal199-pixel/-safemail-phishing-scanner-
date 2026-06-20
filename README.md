# 🛡️ SafeMail Pro — Phishing & Threat Scanner

**Version 4.0.0** | Developed by Kushal Dhakal

A powerful browser extension that instantly scans every email you open in Gmail, Outlook, Yahoo Mail, ProtonMail, and more — detecting phishing, malware, BEC fraud, spoofing, and dangerous attachments. All scanning is 100% local. No data ever leaves your browser.

---

## 🚀 What's New in v4.0

### Bug Fixes
- **Fixed:** `.txt`, `.png`, `.jpg` and other common file attachments were incorrectly showing as "suspicious link" instead of being scanned as attachments
- **Fixed:** All file types are now properly detected regardless of extension — not just a hardcoded list
- **Fixed:** Files are no longer double-counted as both attachments and suspicious links
- **Fixed:** Renamed/disguised files (e.g. `malware.exe` renamed to `invoice.png`) are now detected

### New Features
- **Safe email banner** — every email now shows a result: 🟢 Safe, 🟠 Medium Risk, or 🔴 High Risk
- **Scanned attachments panel** — safe emails show all attachments that were scanned and cleared
- **9 email provider support** — Gmail, Outlook/365, Yahoo Mail, ProtonMail, Zoho Mail, Fastmail, Yandex Mail, AOL Mail, iCloud Mail
- **BEC (Business Email Compromise) detection** — wire transfer fraud, CEO impersonation, gift card scams
- **Shannon entropy scoring** — detects DGA (randomly generated) domains used by malware
- **Homoglyph / Unicode attack detection** — catches Cyrillic/Greek lookalike characters in domains
- **Reply-To header mismatch detection** — classic BEC signal
- **Renamed file detection** — MIME type vs extension mismatch, lure filenames (`invoice.png`, `receipt.txt`)
- **Magic byte detection** — detects executables disguised with fake extensions
- **IOC extraction** — Indicators of Compromise listed per email
- **Removed:** External threat intelligence APIs — fully local, instant, private

---

## 🎯 Features

### Real-time Email Scanning
- Scans every email the moment you open it
- Shows instant result banner: Safe / Medium Risk / High Risk
- Threat score displayed (0–20)
- Expandable detail panel with all findings

### File & Attachment Detection (30+ types)
- `.exe` `.bat` `.cmd` `.ps1` `.vbs` `.hta` `.js` `.jse` — Windows executables & scripts
- `.apk` `.ipa` — Android & iOS sideload apps
- `.jar` `.jnlp` — Java executables
- `.dmg` `.pkg` `.app` — macOS installers
- `.sh` `.bash` `.py` `.rb` `.pl` — Shell & scripting languages
- `.iso` `.vhd` `.vhdx` `.img` — Disk images (can contain autorun malware)
- `.lnk` `.url` `.reg` `.chm` — Windows system file attacks
- `.msi` `.msp` — Silent installers
- `.docm` `.xlsm` `.xlsb` `.pptm` `.xlam` — Macro-enabled Office documents
- `.zip` `.rar` `.7z` `.cab` — Archives that may conceal malware
- **Double extension trick** — `Invoice.pdf.exe`, `photo.jpg.bat`
- **Magic byte detection** — catches executables with fake extensions
- **Rename/spoof detection** — `malware.exe` disguised as `invoice.png`
- **Lure filename detection** — `receipt.png`, `document.txt`, `invoice.jpg`

### Link Analysis
- Domain spoofing & lookalike detection
- Homoglyph / Unicode character substitution
- URL shortener detection (30+ services)
- Raw IP address links
- Typosquatting (edit distance algorithm)
- DGA domain detection (Shannon entropy)
- Mismatch between link display text and actual URL
- Excessive subdomain nesting
- Heavy URL encoding (obfuscation)
- Non-HTTPS links
- Link click interception with warning modal

### Sender Analysis
- Display name spoofing
- Free email service impersonating a business
- Reply-To domain mismatch (BEC signal)
- Unicode/homoglyph characters in sender domain
- High-entropy sender domain (DGA detection)
- Typosquatting sender domain

### Content Analysis
- Phishing keyword detection (50+ terms)
- BEC fraud indicators (wire transfer, gift cards, CEO requests)
- Urgency language detection
- Credential harvesting phrases
- Financial fraud language
- Spelling error detection

### Threat Categories
- 🎣 Phishing
- 💼 BEC Fraud
- ☠️ Malware
- 🎭 Spoofing

---

## 🌐 Supported Email Providers

| Provider | Support |
|---|---|
| Gmail | ✅ Full |
| Outlook / Office 365 | ✅ Full |
| Yahoo Mail | ✅ Full |
| ProtonMail | ✅ Full |
| Zoho Mail | ✅ Full |
| Fastmail | ✅ Full |
| Yandex Mail | ✅ Full |
| AOL Mail | ✅ Full |
| iCloud Mail | ✅ Full |

---

## 📁 Project Structure

```
phishing-scanner-extension/
├── manifest.json       # Extension configuration (v3)
├── scanner.js          # Core detection engine
├── content.js          # DOM interaction, email extraction, banner injection
├── background.js       # Service worker: notifications, history, badge
├── ui.css              # Warning banner & modal styles
├── popup.html          # Extension popup UI
├── popup.js            # Popup logic
└── icons/
    ├── icon48.png
    └── icon128.png
```

---

## 🚀 Installation

1. Download or clone this repository
2. Open Chrome/Edge and go to `chrome://extensions/`
3. Enable **Developer mode** (toggle top right)
4. Click **Load unpacked**
5. Select the `phishing-scanner-extension` folder
6. Open Gmail, Outlook, or any supported email provider
7. Open any email — SafeMail Pro will instantly scan and show a result banner

---

## 🔒 Privacy

- **100% local scanning** — no email content is ever sent to external servers
- No APIs called — no internet connection required for scanning
- Scan history stored only in your browser's local storage
- You can clear all history from the popup at any time

---

## 🛡️ Risk Scoring

| Score | Risk Level | Meaning |
|---|---|---|
| 0–4 | 🟢 Safe | No significant threats detected |
| 5–9 | 🟠 Medium Risk | Suspicious indicators present |
| 10+ | 🔴 High Risk | Phishing, malware, or serious threat detected |

---

## 📊 Popup Panel

- **Dashboard** — live stats: emails scanned, safe, medium, high risk
- **History** — last 50 threats with sender, subject, score, category, time
- **Providers** — list of supported providers and all detection capabilities
- **Settings** — toggle notifications, high-risk only alerts, link intercept, safe banner, export history

---

## 🔧 Version History

| Version | Changes |
|---|---|
| v4.0.0 | Bug fixes: attachment detection, renamed file detection, safe banner, 9 providers |
| v3.0.0 | Multi-provider support, BEC detection, homoglyph detection, IOC extraction |
| v2.0.0 | Browser notifications, threat history, settings panel, badge updates |
| v1.0.0 | Initial release — Gmail/Outlook support, basic phishing detection |

---

*Developed by Kushal Dhakal — APU (Asia Pacific University of Technology & Innovation)*
