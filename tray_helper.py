import os
import sys
import winreg
from PIL import Image, ImageDraw

APP_REG_NAME = "CyberGuardAI"


def create_shield_icon_image(size=(64, 64), is_active=True):
    """Generates a modern shield icon image in memory using PIL."""
    image = Image.new("RGBA", size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    
    w, h = size
    # Shield shape points
    shield_color = (2, 132, 199, 255) if is_active else (100, 116, 139, 255)
    border_color = (3, 105, 161, 255) if is_active else (71, 85, 105, 255)
    
    # Outer shield
    points = [
        (w * 0.5, h * 0.08),   # Top center point
        (w * 0.88, h * 0.22),  # Top right
        (w * 0.88, h * 0.55),  # Mid right
        (w * 0.5, h * 0.92),   # Bottom point
        (w * 0.12, h * 0.55),  # Mid left
        (w * 0.12, h * 0.22),  # Top left
    ]
    draw.polygon(points, fill=shield_color, outline=border_color, width=2)
    
    # Inner accent (checkmark / security symbol)
    check_points = [
        (w * 0.32, h * 0.48),
        (w * 0.46, h * 0.62),
        (w * 0.70, h * 0.36)
    ]
    draw.line(check_points, fill=(255, 255, 255, 255), width=int(w * 0.08))
    
    return image


def set_start_with_windows(enable: bool) -> bool:
    """Configures the application to run automatically on Windows startup via Registry."""
    reg_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    
    # Get current executable path
    if getattr(sys, 'frozen', False):
        exe_path = f'"{os.path.abspath(sys.executable)}" --minimized'
    else:
        python_exe = sys.executable
        script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app_gui.py"))
        exe_path = f'"{python_exe}" "{script_path}" --minimized'

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_key, 0, winreg.KEY_SET_VALUE | winreg.KEY_READ) as key:
            if enable:
                winreg.SetValueEx(key, APP_REG_NAME, 0, winreg.REG_SZ, exe_path)
            else:
                try:
                    winreg.DeleteValue(key, APP_REG_NAME)
                except FileNotFoundError:
                    pass
        return True
    except Exception:
        return False


def is_start_with_windows_enabled() -> bool:
    """Checks if the application is currently registered in Windows Startup."""
    reg_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_key, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, APP_REG_NAME)
            return True
    except Exception:
        return False
