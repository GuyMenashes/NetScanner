import  win32gui, win32ui
from PIL import Image, ImageGrab
import ctypes
import time
import threading


def get_cursor():
    cursor_info=win32gui.GetCursorInfo()
    hcursor = cursor_info[1]
    hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
    hbmp = win32ui.CreateBitmap()
    hbmp.CreateCompatibleBitmap(hdc, 36, 36)
    hdc = hdc.CreateCompatibleDC()
    hdc.SelectObject(hbmp)

    #if mouse not on screen, it will fail
    try:
        hdc.DrawIcon((0,0), hcursor)
    except:
        return None

    bmpinfo = hbmp.GetInfo()
    bmpstr = hbmp.GetBitmapBits(True)
    cursor = Image.frombuffer('RGB', (bmpinfo['bmWidth'], bmpinfo['bmHeight']), bmpstr, 'raw', 'BGRX', 0, 1).convert("RGBA")
    win32gui.DestroyIcon(hcursor)    
    win32gui.DeleteObject(hbmp.GetHandle())
    hdc.DeleteDC()


    pixdata = cursor.load()

    width, height = cursor.size

    for y in range(height):
       for x in range(width):
            if pixdata[x, y] == (0, 0, 0, 255):
                pixdata[x, y] = (0, 0, 0, 0)
            else:
                pixdata[x, y] = (255, 255, 0, 255)
    
    hotspot = win32gui.GetIconInfo(hcursor)[1:3]

    #cursor=cursor.resize((50,50))

    return (cursor, hotspot)

def take_screenshot(lock):
    cursor_info=get_cursor()
    if not cursor_info:
        img = ImageGrab.grab(bbox=None, include_layered_windows=True)
        with lock:
            img.save("shot.jpg", 'JPEG', quality=50)
        return
    cursor, (hotspotx, hotspoty) = cursor_info

    img = ImageGrab.grab(bbox=None, include_layered_windows=True)

    ratio = ctypes.windll.shcore.GetScaleFactorForDevice(0) / 100

    pos_win = win32gui.GetCursorPos()
    pos = (round(pos_win[0]*ratio - hotspotx), round(pos_win[1]*ratio - hotspoty))

    img.paste(cursor, pos, cursor)

    p=time.time()
    with lock:
        img.save("shot.jpg", 'JPEG', quality=50)
    print(time.time()-p)

take_screenshot(threading.Lock())