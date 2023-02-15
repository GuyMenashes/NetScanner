import threading
from encrypted_server import encrypted_server
import zlib
from Screenshot import take_screenshot
import win32api, win32con    
import time
import keyboard

class RemoteControlled:
    def __init__(self):
        self.running=True
        mouse_thread=threading.Thread(target=self.mouse_control)
        mouse_thread.start()
        time.sleep(0.05)

        keyboard_thread=threading.Thread(target=self.keybord_control)

        keyboard_thread.start()

        self.share_screen()
    
    def screen_size(self)-> tuple[int,int]:
        '''
        Get the screen dimentions
        '''
        x,y=win32api.GetCursorPos()
        win32api.SetCursorPos((100000,100000))
        width,height=win32api.GetCursorPos()
        win32api.SetCursorPos((x,y))
        return width,height

    def mouse_control(self):
        self.mouse_server=encrypted_server(55551)
        self.mouse_server.start_server()
        width,height=self.screen_size()
        self.mouse_server.send(f'{width},{height}')
        is_left_pressed=False
        is_right_pressed=False
        while self.running:
            try:
                text= self.mouse_server.recieve()
            except:
                self.running=False
                break
            if not text:
                continue
            text=text.split(',')
            x,y=int(text[0]),int(text[1])
            win32api.SetCursorPos((x,y))
            if not is_left_pressed and int(text[2])==1:
                is_left_pressed=True
                win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN,x,y,0,0)
            elif is_left_pressed and int(text[2])==0:
                is_left_pressed=False
                win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP,x,y,0,0)

            if not is_right_pressed and int(text[3])==1:
                is_right_pressed=True
                win32api.mouse_event(win32con.MOUSEEVENTF_RIGHTDOWN,x,y,0,0)
            elif is_right_pressed and int(text[3])==0:
                is_right_pressed=False
                win32api.mouse_event(win32con.MOUSEEVENTF_RIGHTUP,x,y,0,0)

    def keybord_control(self):
        self.keybord_server=encrypted_server(33331)
        self.keybord_server.start_server(first_connection=False)
        while self.running:
            try:
                text= self.keybord_server.recieve()
            except:
                self.running=False
                break
            if not text:
                continue
            text=text.split(',')
            if text[1]=='down':
                keyboard.press(text[0])
            else:
                keyboard.release(text[0])

    def screenshot(self,lock):
        while self.running:
            take_screenshot(lock)
        
    def share_screen(self):
        lock=threading.Lock()
        screenshot_thr=threading.Thread(target=self.screenshot,args=(lock,))

        self.screen_server=encrypted_server(19999)
        self.screen_server.start_server(first_connection=False)
        screenshot_thr.start()
        with lock:
            with open("shot.jpg",'rb') as f:
                image=f.read()

        print('connected') 
        while self.running:
            try:
                self.screen_server.send(zlib.compress(image,level=9),isBytes=True)
            except:
                self.running=False
                break
            with lock:
                with open("shot.jpg",'rb') as f:
                    image=f.read()     

RemoteControlled()