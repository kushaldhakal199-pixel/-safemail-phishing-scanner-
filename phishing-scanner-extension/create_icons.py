"""
Simple script to create placeholder icon files for the extension
Run this script to generate icon48.png and icon128.png
"""

from PIL import Image, ImageDraw, ImageFont
import os

def create_icon(size, filename):
    """Create a simple icon with shield symbol"""
    # Create image with transparent background
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Draw a shield shape
    # Calculate shield points
    width, height = size, size
    margin = size // 8
    
    # Shield outline (simplified)
    shield_points = [
        (width // 2, margin),  # Top point
        (width - margin, margin + size // 4),  # Top right
        (width - margin, height - margin - size // 4),  # Bottom right
        (width // 2, height - margin),  # Bottom point
        (margin, height - margin - size // 4),  # Bottom left
        (margin, margin + size // 4),  # Top left
    ]
    
    # Draw shield with blue color
    draw.polygon(shield_points, fill=(0, 123, 255, 255), outline=(0, 86, 179, 255), width=2)
    
    # Draw checkmark inside
    check_size = size // 3
    check_x = width // 2
    check_y = height // 2 + size // 12
    check_thickness = max(2, size // 16)
    
    # Draw checkmark
    draw.line([
        (check_x - check_size // 2, check_y),
        (check_x - check_size // 6, check_y + check_size // 3),
        (check_x + check_size // 2, check_y - check_size // 3)
    ], fill=(255, 255, 255, 255), width=check_thickness)
    
    # Save image
    icons_dir = os.path.join(os.path.dirname(__file__), 'icons')
    os.makedirs(icons_dir, exist_ok=True)
    
    filepath = os.path.join(icons_dir, filename)
    img.save(filepath, 'PNG')
    print(f"[OK] Created {filename} ({size}x{size})")

def main():
    print("Creating placeholder icons for Phishing Scanner Extension...")
    print()
    
    try:
        # Create icons
        create_icon(48, 'icon48.png')
        create_icon(128, 'icon128.png')
        
        print()
        print("[SUCCESS] Icons created successfully!")
        print()
        print("Next steps:")
        print("1. Load the extension in Chrome/Edge:")
        print("   - Go to chrome://extensions/ or edge://extensions/")
        print("   - Enable 'Developer mode'")
        print("   - Click 'Load unpacked'")
        print("   - Select the phishing-scanner-extension folder")
        print()
        print("2. Test it:")
        print("   - Go to Gmail or Outlook")
        print("   - Open an email")
        print("   - The extension will scan automatically")
        
    except ImportError:
        print("[ERROR] PIL (Pillow) library not found")
        print()
        print("Install it with:")
        print("  pip install Pillow")
        print()
        print("Or create icons manually:")
        print("  - Create icon48.png (48x48 pixels)")
        print("  - Create icon128.png (128x128 pixels)")
        print("  - Place them in the icons/ folder")
    except Exception as e:
        print(f"[ERROR] Error creating icons: {e}")
        print()
        print("You can create icons manually:")
        print("  - Use any image editor")
        print("  - Create 48x48 and 128x128 PNG files")
        print("  - Save as icon48.png and icon128.png in icons/ folder")

if __name__ == '__main__':
    main()

