# Importing required libraries
import win32gui, win32ui
from PIL import Image, ImageGrab
import ctypes

# Function to get the current cursor image
def get_cursor():
    try:
        # Getting the cursor information
        cursor_info=win32gui.GetCursorInfo()
        hcursor = cursor_info[1]

        # Creating a DC (device context) from handle and bitmap
        hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
        hbmp = win32ui.CreateBitmap()
        hbmp.CreateCompatibleBitmap(hdc, 36, 36)
        hdc = hdc.CreateCompatibleDC()
        hdc.SelectObject(hbmp)

    except Exception as e:
        try:
            # Cleaning up in case of exception
            hdc.DeleteDC()
            win32gui.DeleteObject(hbmp.GetHandle())
        finally:
            raise e

    # Drawing the icon into the bitmap and creating a PIL Image object
    hdc.DrawIcon((0,0), hcursor)
    bmpinfo = hbmp.GetInfo()
    bmpstr = hbmp.GetBitmapBits(True)
    cursor = Image.frombuffer('RGB', (bmpinfo['bmWidth'], bmpinfo['bmHeight']), bmpstr, 'raw', 'BGRX', 0, 1).convert("RGBA")

    # Destroying the icon and cleaning up
    win32gui.DestroyIcon(hcursor)    
    win32gui.DeleteObject(hbmp.GetHandle())
    hdc.DeleteDC()

    # Removing the black background from the cursor image and setting the transparency
    pixdata = cursor.load()
    width, height = cursor.size
    for y in range(height):
       for x in range(width):
            if pixdata[x, y] == (0, 0, 0, 255):
                pixdata[x, y] = (0, 0, 0, 0)
            else:
                pixdata[x, y] = (255, 255, 0, 255)

    # Getting the cursor hotspot position
    hotspot = win32gui.GetIconInfo(hcursor)[1:3]

    # Cleaning up
    del hdc,hbmp

    return (cursor, hotspot)

def take_screenshot(lock, quality):
    # Grab a screenshot of the entire screen, including layered windows
    img = ImageGrab.grab(bbox=None, include_layered_windows=True)

    # Save the screenshot to a file with the specified quality
    with lock:
        img.save("shot.jpg", 'JPEG', quality=quality)

# Function to take a screenshot with the cursor
def take_mouse_screenshot(lock):
    # Getting the cursor image and hotspot position
    cursor_info=get_cursor()
    if not cursor_info:
        # If there is no cursor, just take a screenshot without it
        img = ImageGrab.grab(bbox=None, include_layered_windows=True)
        with lock:
            img.save("shot.jpg", 'JPEG', quality=50)
        return
    cursor, (hotspotx, hotspoty) = cursor_info

    # Taking the screenshot and scaling it based on the display DPI scaling factor
    img = ImageGrab.grab(bbox=None, include_layered_windows=True)
    ratio = ctypes.windll.shcore.GetScaleFactorForDevice(0) / 100

    # Pasting the cursor image onto the screenshot at the cursor position
    pos_win = win32gui.GetCursorPos()
    pos = (round(pos_win[0]*ratio - hotspotx), round(pos_win[1]*ratio - hotspoty))
    img.paste(cursor, pos, cursor)

    # Saving the screenshot to a file
    with lock:
        img.save("shot.jpg", 'JPEG', quality=50)