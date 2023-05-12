# Import necessary libraries
import pynput
from tkinter import *
import zlib
from numpy import array, uint8
import cv2
from screeninfo import get_monitors
from encrypted_client import encrypted_client
import time
import win32api
import keyboard
import sys

# Define a class for remote controlling
class RemoteController:
    # Initialize the class with the IP address
    def __init__(self,ip):
        self.ip=ip

        # Set a boolean flag to indicate if the program is running or not
        self.running=True

        # Initialize the exit reason to an empty string
        self.exit_reason=''

    # Start the connection with the server
    def start_connection(self,pipe):
        # Set the pipe to the instance variable
        self.pipe=pipe

        # Call the mouse control, keyboard control and display screen methods
        self.mouse_control()
        self.keyboard_control()
        self.display_screen()

    # Method to control the keyboard
    def keyboard_control(self):
        # Initialize an instance of encrypted_client with the IP address and port number
        self.keyboard_client=encrypted_client(self.ip,33331)

        # Run the server to listen to incoming connections
        self.keyboard_client.run_server(first_connection=False)

        # Hook the keyboard to listen to keyboard events and call the send_keyboard_event method for each event
        keyboard.hook(self.send_keyboard_event)

    # Method to send keyboard events to the server
    def send_keyboard_event(self,key_event):
        # If the program is not running, exit the program
        if not self.running:
            sys.exit()

        try:
            # Send the scan code and event type of the key event to the server
            self.keyboard_client.send(f'{key_event.scan_code},{key_event.event_type}')
        except:
            # If there is an exception, set the exit reason and stop the program
            self.exit_reason='controlled computer disconnected'
            self.running=False 
            print('controlled computer disconnected')
            self.mouse_listener.stop()
            sys.exit()

    # Method to control the mouse
    def mouse_control(self):
        # Initialize an instance of encrypted_client with the IP address and port number
        self.mouse_client=encrypted_client(self.ip,32871)

        # Run the server to listen to incoming connections
        self.mouse_client.run_server()

        # Set the left and right mouse buttons to false
        self.left_pressed=False
        self.right_pressed=False
        
        # Receive the screen resolution of the remote computer
        other_width,other_height=map(int,self.mouse_client.recieve().split(','))

        # Get the screen resolution of the local computer
        m=get_monitors()
        width=m[0].width
        height=m[0].height

        # Calculate the ratio of the remote computer resolution to the local computer resolution
        self.xRatio=other_width/width
        self.yRatio=other_height/height

        # Get the current cursor position
        x,y=win32api.GetCursorPos()

        # Send the cursor position and mouse button states to the server
        self.mouse_client.send(f'{round(x*self.xRatio)},{round(y*self.yRatio)},{int(self.left_pressed)},{int(self.right_pressed)}')

        # Start the mouse listener to listen for mouse events
        self.mouse_listener=pynput.mouse.Listener(on_click=self.is_clicked, on_move=self.moved)
        self.mouse_listener.start()
      
    def is_clicked(self, x, y, button, pressed):
        # check if the program is still running, if not exit
        if not self.running:
            sys.exit()

        # if left button clicked, set the left_pressed flag and send the mouse position and buttons states to the server
        if button == pynput.mouse.Button.left:
            self.left_pressed = pressed
            try:
                # send the x,y positions and the left and right buttons states to the server
                self.mouse_client.send(f'{round(x * self.xRatio)},{round(y * self.yRatio)},{int(self.left_pressed)},{int(self.right_pressed)}')
            except:
                # if the client couldn't send data to the server, exit the program
                keyboard.unhook_all()
                self.running = False 
                self.exit_reason = 'controlled computer disconnected'
                print('controlled computer disconnected')
                sys.exit()
        
        # if right button clicked, set the right_pressed flag and send the mouse position and buttons states to the server
        elif button == pynput.mouse.Button.right:
            self.right_pressed = pressed
            try:
                # send the x,y positions and the left and right buttons states to the server
                self.mouse_client.send(f'{round(x * self.xRatio)},{round(y * self.yRatio)},{int(self.left_pressed)},{int(self.right_pressed)}')
            except:
                # if the client couldn't send data to the server, exit the program
                keyboard.unhook_all()
                self.running = False 
                self.exit_reason = 'controlled computer disconnected'
                print('controlled computer disconnected')
                sys.exit()

    # This function is called when the mouse is moved
    def moved(self, x, y):
        # check if the program is still running, if not exit
        if not self.running:
            sys.exit()

        try:
            # send the x,y positions and the left and right buttons states to the server
            self.mouse_client.send(f'{round(x * self.xRatio)},{round(y * self.yRatio)},{int(self.left_pressed)},{int(self.right_pressed)}')
        except:
            # if the client couldn't send data to the server, exit the program
            keyboard.unhook_all()
            self.running = False 
            self.exit_reason = 'controlled computer disconnected'
            print('controlled computer disconnected')
            sys.exit()

    def display_screen(self):
        # Connect to the server and run it
        self.screen_client=encrypted_client(self.ip,19999)
        self.screen_client.run_server(first_connection=False)

        # Initialize variables
        sum=0
        count=0
        lost_count=0
        image_bytes=0

        # Loop while the program is running
        while self.running:
            # Get an image from the server
            a=time.time()
            try:
                recieved=self.screen_client.recieve(1_200_000,isBytes=True)
            except:
                # If an error occurs, stop the program and exit
                keyboard.unhook_all()
                self.mouse_listener.stop()
                self.running=False
                self.exit_reason='controlled computer disconnected'
                break

            # If the image is not received or is empty, skip this iteration
            if not recieved or recieved==b'':
                lost_count+=1
                try:
                    cv2.imshow("img", img)
                except:
                    pass
                finally:
                    continue

            try:
                # Decompress the image and create a numpy array
                image_bytes=zlib.decompress(recieved)
                img_arr = array(bytearray(image_bytes), dtype=uint8) 
                try:
                    img = cv2.imdecode(img_arr, -1)
                except:
                    continue

                # Display the image in fullscreen mode
                cv2.namedWindow('img',cv2.WND_PROP_FULLSCREEN)
                cv2.setWindowProperty('img', cv2.WND_PROP_FULLSCREEN, cv2.WINDOW_FULLSCREEN)

                # Calculate the FPS and display the image
                sum+=time.time()-a
                count+=1
                cv2.imshow("img", img)

            except:
                # If an error occurs, stop the program and exit
                keyboard.unhook_all()
                self.mouse_listener.stop()
                self.running=False
                self.exit_reason='controlled computer disconnected'
                break

            # Exit if the 'Esc' key is pressed
            if cv2.waitKey(1) == 27:
                self.exit_reason='quited'
                break

        # If the program is exiting due to a disconnection, set the exit reason
        if self.exit_reason=='':
            self.exit_reason='controlled computer disconnected'

        # Clean up variables and close windows
        self.running=False
        try:
            del self.screen_client.soc
        except:
            pass
        try:
            del self.mouse_client.soc
        except:
            pass
        try:
            del self.keyboard_client.soc
        except:
            pass
        cv2.destroyAllWindows()

        # Send the exit reason back to the main process
        try:
            print(count,sum,f'{1/(sum/count)} fps',lost_count)
        except:
            pass
        finally:
            self.pipe.send(self.exit_reason)