import pynput
from tkinter import *
import zlib
import cv2
import numpy as np
from screeninfo import get_monitors
from encrypted_client import encrypted_client
import time
import win32api
import keyboard
import datetime

class RemoteController:
    def __init__(self,ip):
        self.ip=ip

        self.running=True
        
        self.mouse_control()

        self.keyboard_control()

        self.display_screen()

    def keyboard_control(self):
        self.keyboard_client=encrypted_client(self.ip,33331)
        self.keyboard_client.run_server(first_connection=False)

        keyboard.hook(self.send_keyboard_event)

    def send_keyboard_event(self,key_event):
        if not self.running:
            quit()
        try:
            self.keyboard_client.send(f'{key_event.scan_code},{key_event.event_type}')
        except:
            self.running=False 
            print('controlled computer disconnected')
            self.mouse_listener.stop()
            quit()

    def mouse_control(self):
        self.mouse_client=encrypted_client(self.ip,55551)
        self.mouse_client.run_server()

        self.left_pressed=False
        self.right_pressed=False
        
        other_width,other_height=map(int,self.mouse_client.recieve().split(','))

        m=get_monitors()
        width=m[0].width
        height=m[0].height

        self.xRatio=other_width/width
        self.yRatio=other_height/height

        x,y=win32api.GetCursorPos()

        self.mouse_client.send(f'{round(x*self.xRatio)},{round(y*self.yRatio)},{int(self.left_pressed)},{int(self.right_pressed)}')

        self.mouse_listener=pynput.mouse.Listener(on_click=self.is_clicked, on_move=self.moved)
        self.mouse_listener.start()
      
    def is_clicked(self,x,y,button,pressed):
        if not self.running:
            quit()

        if button==pynput.mouse.Button.left:
            self.left_pressed=pressed
            try:
                self.mouse_client.send(f'{round(x*self.xRatio)},{round(y*self.yRatio)},{int(self.left_pressed)},{int(self.right_pressed)}')
            except:
                keyboard.unhook_all()
                self.running=False 
                print('controlled computer disconnected')
                quit()
        
        elif button==pynput.mouse.Button.right:
            self.right_pressed=pressed
            try:
                self.mouse_client.send(f'{round(x*self.xRatio)},{round(y*self.yRatio)},{int(self.left_pressed)},{int(self.right_pressed)}')
            except:
                keyboard.unhook_all()
                self.running=False 
                print('controlled computer disconnected')
                quit()

    def moved(self,x,y):
        if not self.running:
            quit()

        try:
            self.mouse_client.send(f'{round(x*self.xRatio)},{round(y*self.yRatio)},{int(self.left_pressed)},{int(self.right_pressed)}')
        except:
            keyboard.unhook_all()
            self.running=False 
            print('controlled computer disconnected')
            quit()

    def display_screen(self):
        self.screen_client=encrypted_client(self.ip,19999)
        self.screen_client.run_server(first_connection=False)
        sum=0
        count=0
        lost_count=0
        image_bytes=0
        while self.running:
            a=time.time()
            try:
                recieved=self.screen_client.recieve(500_000,isBytes=True)
            except:
                keyboard.unhook_all()
                self.mouse_listener.stop()
                self.running=False
                print('controlled computer disconnected')
                break
            if not recieved or recieved==b'':
                lost_count+=1
                try:
                    cv2.imshow("img", img)
                finally:
                    continue
            
            image_bytes=zlib.decompress(recieved)
            img_arr = np.array(bytearray(image_bytes), dtype=np.uint8) 
            img = cv2.imdecode(img_arr, -1)

            cv2.namedWindow('img',cv2.WND_PROP_FULLSCREEN)
            cv2.setWindowProperty('img', cv2.WND_PROP_FULLSCREEN, cv2.WINDOW_FULLSCREEN)
            sum+=time.time()-a
            count+=1
            cv2.imshow("img", img)
            # Press Esc key to exit
            if cv2.waitKey(1) == 27:
                break
        
        cv2.destroyAllWindows()
        print(count,sum,f'{1/(sum/count)} fps',lost_count)