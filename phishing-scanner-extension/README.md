# SafeMail - Phishing & Link Scanner

**Developed by Kushal**

A powerful browser extension that scans emails in Gmail and Outlook web interfaces to detect phishing attempts, malware, payloads, and malicious content by analyzing links, sender information, attachments, and suspicious keywords.

## 🎯 Features

### 1. Real-time Email Scanning
- Automatically extracts email content and links from Gmail/Outlook DOM
- Scans emails when opened
- Monitors for dynamic content changes

### 2. Suspicious Link Detection
- **Mismatched domains**: Detects when link text shows one domain but URL points to another
- **Non-HTTPS URLs**: Flags insecure connections
- **IP addresses**: Identifies URLs using IP addresses instead of domain names
- **Lookalike domains**: Detects typosquatting (e.g., go0gle.com, paypa1.com)
- **URL shorteners**: Flags bit.ly, tinyurl.com, and other shortening services
- **Suspicious subdomains**: Detects excessive subdomain nesting

### 3. Suspicious Sender Detection
- **Display name spoofing**: Detects when display name claims different domain than email
- **Free email services**: Flags business impersonation using free email services
- **Random email patterns**: Identifies suspicious random-looking addresses

### 4. Risk Highlighting UI
- Color-coded warning banners:
  - 🔴 **High Risk** (Red) - Score ≥ 10
  - 🟠 **Medium Risk** (Orange) - Score 5-9
  - 🟢 **Safe** - Score < 5
- Detailed issue list
- Suspicious link details
- Easy-to-dismiss interface
- **Smart Warning Behavior**: Warnings reappear when you reopen emails (for your safety)

## 📁 Project Structure

```
phishing-scanner-extension/
│── manifest.json          # Extension configuration
│── content.js             # DOM interaction and email extraction
│── scanner.js             # Core phishing detection logic
│── ui.css                 # Warning banner styles
│── background.js          # Background service worker
│── popup.html             # Extension popup UI
│── popup.js               # Popup script
│── icons/
│     └── icon48.png       # Extension icon (48x48)
│     └── icon128.png      # Extension icon (128x128)
└── README.md              # This file
```

## 🚀 Installation

### For Development:

1. **Clone or download this repository**

2. **Create icon files** (or use placeholder images):
   - Create `icons/icon48.png` (48x48 pixels)
   - Create `icons/icon128.png` (128x128 pixels)

3. **Load extension in Chrome/Edge**:
   - Open `chrome://extensions/` (or `edge://extensions/`)
   - Enable "Developer mode" (toggle in top right)
   - Click "Load unpacked"
   - Select the `phishing-scanner-extension` folder

4. **Test the extension**:
   - Navigate to Gmail (mail.google.com) or Outlook (outlook.live.com)
   - Open an email
   - The extension will automatically scan and display warnings if threats are detected

## 🔧 How It Works

### Scanning Process:

1. **Email Detection**: Content script monitors the DOM for email views
2. **Data Extraction**: Extracts sender info, subject, content, and all links
3. **Analysis**: Scanner analyzes:
   - Sender authenticity
   - Link safety
   - Content suspiciousness
4. **Risk Assessment**: Calculates risk score (0-20) and determines risk level
5. **UI Display**: Shows warning banner if risk is detected

### Risk Scoring:

- **High Risk (10+)**: Multiple serious issues detected
- **Medium Risk (5-9)**: Some suspicious indicators
- **Safe (<5)**: No significant threats

### Warning Behavior:

The extension is designed with your safety in mind:

1. **First View**: When you open a suspicious email, a warning banner appears at the top
2. **Dismissal**: You can close the warning by clicking the × button
   - The warning is dismissed only for the current email view session
3. **Reopening**: When you close the email and reopen it later, the warning appears again
   - This ensures you're always reminded about potential phishing risks
4. **Why This Design?**: Prevents you from accidentally missing important security warnings

**Note**: Warnings are dismissed per email view session, not permanently. This safety feature ensures you're always aware of potential threats when viewing risky emails.

## 🛡️ Detection Capabilities

### Link Analysis:
- Domain mismatch detection
- HTTPS enforcement
- IP address detection
- URL shortener identification
- Lookalike domain detection
- Typosquatting patterns
- Subdomain analysis

### Sender Analysis:
- Display name vs email domain mismatch
- Free email service detection
- Business impersonation patterns
- Random email pattern detection

### Content Analysis:
- Suspicious keyword detection
- Urgency language analysis
- Spelling/grammar checks

## ⚙️ Configuration

The extension stores settings in `chrome.storage.local`:

- `enabled`: Boolean - Enable/disable scanner
- `riskThreshold`: String - Minimum risk level to show warnings
- `showNotifications`: Boolean - Show browser notifications
- `scanHistory`: Array - Recent scan results (last 100)

## 🔒 Privacy

- All scanning happens locally in your browser
- No data is sent to external servers
- Email content is never stored permanently
- Only scan results are logged locally (optional)

## 🐛 Known Limitations

- Works with Gmail and Outlook web interfaces only
- May have false positives/negatives
- Requires emails to be opened for scanning
- Some dynamic email content may not be detected immediately

## 🚧 Future Enhancements

- [ ] Support for more email providers
- [ ] Integration with threat intelligence APIs
- [ ] Machine learning-based detection
- [ ] Customizable detection rules
- [ ] Export scan reports
- [ ] Whitelist/blacklist domains

## 📝 License

This project is provided as-is for educational and security purposes.

## ⚠️ Disclaimer

This extension is a tool to assist in identifying potential phishing attempts. It is not a replacement for good security practices. Always verify suspicious emails through other means and never rely solely on automated tools.

## 🤝 Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

---

**Stay Safe! 🛡️**

