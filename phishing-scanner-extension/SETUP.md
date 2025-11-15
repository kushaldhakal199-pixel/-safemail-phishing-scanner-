# 🚀 Quick Setup Guide

## Step 1: Create Icon Files (Required)

You need to create two icon files. Here are quick options:

### Option A: Use Online Tool (Easiest)
1. Go to https://www.favicon-generator.org/ or any icon generator
2. Upload any image or use a shield/security icon
3. Download 48x48 and 128x128 versions
4. Save them as `icon48.png` and `icon128.png` in the `icons/` folder

### Option B: Use Simple Colored Squares (For Testing)
- Create two PNG files:
  - `icon48.png` - 48x48 pixels, any color
  - `icon128.png` - 128x128 pixels, any color
- You can use Paint, GIMP, or any image editor

### Option C: Use the Python Script (I'll create this for you)
- Run the provided `create_icons.py` script to generate simple placeholder icons

## Step 2: Load Extension in Chrome

1. **Open Chrome Extensions Page**
   - Type in address bar: `chrome://extensions/`
   - OR go to: Menu (⋮) → Extensions → Manage Extensions

2. **Enable Developer Mode**
   - Toggle the "Developer mode" switch in the top-right corner

3. **Load the Extension**
   - Click "Load unpacked" button
   - Navigate to: `E:\python\phishing-scanner-extension`
   - Select the folder and click "Select Folder"

4. **Verify Installation**
   - You should see "Phishing Email Scanner" in your extensions list
   - The extension icon should appear in your browser toolbar

## Step 3: Load Extension in Microsoft Edge

1. **Open Edge Extensions Page**
   - Type in address bar: `edge://extensions/`
   - OR go to: Menu (⋯) → Extensions

2. **Enable Developer Mode**
   - Toggle the "Developer mode" switch in the bottom-left

3. **Load the Extension**
   - Click "Load unpacked" button
   - Navigate to: `E:\python\phishing-scanner-extension`
   - Select the folder

## Step 4: Test the Extension

1. **Go to Gmail or Outlook**
   - Open: https://mail.google.com
   - OR: https://outlook.live.com

2. **Open an Email**
   - Click on any email to open it
   - The extension will automatically scan it

3. **Check for Warnings**
   - If phishing is detected, you'll see a colored warning banner
   - Red = High Risk
   - Orange = Medium Risk
   - You can close the warning by clicking the × button
   - **Important**: Warnings will reappear when you reopen the same email (for your safety)

4. **Test Extension Popup**
   - Click the extension icon in the toolbar
   - You should see the popup with scanner status

## Step 5: Verify It's Working

### Test with a Suspicious Email Pattern:
1. Create a test email (or use an existing one)
2. Look for emails with:
   - Links that don't match the text
   - Non-HTTPS URLs
   - Suspicious sender names
   - Urgent language

### Test Warning Reappearance:
1. Open a suspicious email → Warning appears
2. Close the warning by clicking ×
3. Navigate back to inbox
4. Reopen the same email → Warning appears again ✅
   - This ensures you're always warned about risky emails

### Check Console (Optional):
1. Press `F12` to open Developer Tools
2. Go to "Console" tab
3. You should see scan logs if emails are being processed

## Troubleshooting

### Extension Not Loading?
- ✅ Make sure all files are in the correct folder
- ✅ Check that `manifest.json` exists
- ✅ Verify icon files are present (even placeholder ones)

### No Warnings Showing?
- ✅ Make sure you're on Gmail or Outlook web interface
- ✅ Try refreshing the page (F5)
- ✅ Open an email (not just the inbox view)
- ✅ Check browser console for errors (F12)

### Icons Missing Error?
- ✅ Create the icon files (see Step 1)
- ✅ Files must be named exactly: `icon48.png` and `icon128.png`
- ✅ Files must be in the `icons/` folder

### Warning Not Reappearing?
- ✅ This is expected behavior - warnings are dismissed only for the current email view
- ✅ When you close an email and reopen it, the warning will show again
- ✅ This is a safety feature to ensure you're always warned about risky emails
- ✅ If you want to permanently dismiss a warning, you would need to mark the email as safe manually

## How Warning Dismissal Works

The extension is designed with your safety in mind:

1. **First View**: When you open a suspicious email, a warning appears
2. **Dismissal**: You can close the warning by clicking × (it's dismissed for this view only)
3. **Reopening**: When you close the email and reopen it, the warning appears again
4. **Why?**: This ensures you're always reminded about potential phishing risks

**Note**: Warnings are dismissed per email view session, not permanently. This prevents you from accidentally missing important security warnings.

## Quick Test Checklist

- [ ] Icon files created (`icon48.png`, `icon128.png`)
- [ ] Extension loaded in browser
- [ ] Developer mode enabled
- [ ] Extension appears in toolbar
- [ ] Opened Gmail or Outlook
- [ ] Opened an email
- [ ] Extension popup works
- [ ] Warning appears for suspicious emails
- [ ] Warning reappears when reopening the same email (after closing it)

## Need Help?

Check the main `README.md` file for more detailed information about features and how the scanner works.

