from Screenshot import take_screenshot
import threading

while True:
    try:
        take_screenshot(threading.Lock())
    except Exception as e:
        print(e)