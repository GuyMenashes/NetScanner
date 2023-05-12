# Import necessary libraries
import threading
from encrypted_server import encrypted_server
import zlib
from Screenshot import take_screenshot
import win32api, win32con    
import time
import keyboard
from socket import timeout

class RemoteControlled:
    def __init__(self,quality):
        self.running=True   # Flag to keep the program running

        self.qaulity=quality   # Quality of the screenshot images

        self.exit_reason=''   # Reason for exiting the program

    def start_share(self,pipe):
        self.pipe=pipe   # Communication pipe between threads

        # Start mouse thread
        mouse_thread=threading.Thread(target=self.mouse_control)
        mouse_thread.start()
        time.sleep(0.05)

        # Start keyboard thread
        keyboard_thread=threading.Thread(target=self.keybord_control)
        keyboard_thread.start()

        # Register 'escape' key to exit sharing
        keyboard.hook_key('escape',self.exit_share)

        # Start sharing the screen
        self.share_screen()

        # Send the exit reason through the pipe
        self.pipe.send(self.exit_reason)
    
    def screen_size(self)-> tuple[int,int]:
        '''
        Get the screen dimensions
        '''
        x,y=win32api.GetCursorPos()
        win32api.SetCursorPos((100000,100000))
        width,height=win32api.GetCursorPos()
        win32api.SetCursorPos((x,y))
        return width,height

    def mouse_control(self):
        # Start the mouse server
        self.mouse_server=encrypted_server(32871)
        self.mouse_server.start_server()   
        self.mouse_server.client.settimeout(0.1)

        # Get the screen size and send it to the client
        width,height=self.screen_size()
        self.mouse_server.send(f'{width},{height}')

        # Initialize mouse control variables
        is_left_pressed=False
        is_right_pressed=False

        # Receive mouse input from the client and control the mouse accordingly
        while self.running:
            try:
                text= self.mouse_server.recieve()
            except timeout:
                continue
            except:
                self.exit_reason='controlled computer disconnected'
                self.running=False
                break
            if not text:
                continue
            text=text.split(',')
            x,y=int(text[0]),int(text[1])
            win32api.SetCursorPos((x,y))

            # Left mouse button control
            if not is_left_pressed and int(text[2])==1:
                is_left_pressed=True
                win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN,x,y,0,0)
            elif is_left_pressed and int(text[2])==0:
                is_left_pressed=False
                win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP,x,y,0,0)

            # Right mouse button control
            if not is_right_pressed and int(text[3])==1:
                is_right_pressed=True
                win32api.mouse_event(win32con.MOUSEEVENTF_RIGHTDOWN,x,y,0,0)
            elif is_right_pressed and int(text[3])==0:
                is_right_pressed=False
                win32api.mouse_event(win32con.MOUSEEVENTF_RIGHTUP,x,y,0,0)

    def keybord_control(self):
        # Create and start the encrypted server for keyboard control on port 33331
        self.keybord_server=encrypted_server(33331)
        self.keybord_server.start_server(first_connection=False)
        # Set timeout for the client connection to 0.1 seconds
        self.keybord_server.client.settimeout(0.1)

        # Continuously listen for keyboard control commands while running is True
        while self.running:
            try:
                # Receive keyboard control commands from the client
                text= self.keybord_server.recieve()
            except timeout:
                # Ignore timeouts and continue waiting for commands
                continue
            except:
                # Stop the keyboard control loop and set the exit reason if an exception occurs
                self.running=False
                self.exit_reason='controlled computer disconnected'
                break

            # If no command is received, continue waiting
            if not text:
                continue

            # Split the command into keycode and action
            text=text.split(',')
            if text[1]=='down':
                # If the action is "down", simulate a key press for the corresponding keycode
                keyboard.press(int(text[0]))
            else:
                # If the action is not "down", simulate a key release for the corresponding keycode
                keyboard.release(int(text[0]))

    def screenshot(self,lock):
        # Continuously take and send screenshots while running is True
        while self.running:
            try:
                # Take a screenshot and save it as "shot.jpg"
                take_screenshot(lock,self.qaulity)
            except Exception as e:
                # If an exception occurs, print the error message and wait 0.5 seconds before trying again
                print('screenshot error',e)
                time.sleep(0.5)

    def exit_share(self,*args):
        # Stop running and unhook all keyboard hooks
        self.running=False
        keyboard.unhook_all()

    def share_screen(self):
        # Set used to False and create a threading.Lock object
        self.used=False
        lock=threading.Lock()

        # Create a new thread for continuously taking and saving screenshots
        screenshot_thr=threading.Thread(target=self.screenshot,args=(lock,))

        # Create and start the encrypted server for screen sharing on port 19999
        self.screen_server=encrypted_server(19999)
        self.screen_server.start_server(first_connection=False)

        # Start the screenshot thread
        screenshot_thr.start()

        # Wait for the screenshot thread to acquire the lock and take a screenshot
        with lock:
            self.used=True
            try:
                with open("shot.jpg",'rb') as f:
                    image=f.read()
            except:
                time.sleep(0.05)
                with open("shot.jpg",'rb') as f:
                    image=f.read()

        # Send a message to the pipe indicating that the connection is established
        self.pipe.send('connected')

        # Continuously send screenshots while running is True
        while self.running:
            try:
                # Send the compressed screenshot image to the client
                self.screen_server.send(zlib.compress(image,level=9),isBytes=True)
            except:
                # If an exception occurs, set the exit reason and stop running
                self.exit_reason='controlled computer disconnected'
                self.running=False
                break

            # Wait for the screenshot thread to acquire the lock and take a new screenshot
            with lock:
                self.used=True
                try:
                    with open("shot.jpg",'rb') as f:
                        image=f.read()
                except:
                    # If an exception occurs,continue waiting
                    continue
