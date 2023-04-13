from Screenshot import take_screenshot
import threading
import keyboard

def a(event):
    keyboard.press(int(f'{event.scan_code}'))

keyboard.hook(a)

while True:
    pass