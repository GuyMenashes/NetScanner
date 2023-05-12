# Import necessary libraries
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import tkinter.font as tkFont
from get_net_info import get_ip_info
from PIL import Image, ImageTk
from encrypted_server import encrypted_server
import time
from Controlled import RemoteControlled
import threading
import multiprocessing
from sniffSen import SniffSen
from scapy.all import *

# Create a class for the GUI
class controlled_gui:
    def __init__(self):
        try:
            # Check if winpcap is installed
            sniff(1)
        except:
            # If not installed, prompt user to download and install it
            link='https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe'
            dialog = tk.Tk()
            dialog.title("Winpcap Error")
            label = tk.Label(dialog, text="In order to use this app, please download winpcap from this link:")
            label.pack(padx=10, pady=5)
            link_label = tk.Label(dialog, text=link, fg="blue", cursor="hand2")
            link_label.pack(padx=10, pady=5)
            link_label.bind("<Button-1>", lambda event: self.on_click_link(event, link))
            dialog.mainloop()
            quit()
        
        # Initialize the GUI variables
        self.running=True
        try:
            self.my_ip =get_ip_info()[0]
        except:
            # If not connected to wifi, display error message and quit
            messagebox.showerror("Error", "You must be connected to wifi in order to start this app!")
            quit()
        self.root = tk.Tk()
        self.root.geometry('600x675')
        self.root.title("Network Manager")
        self.root.resizable(False,False)

        # Create and start threads for listening for remote control and sniff connections
        rc_listen_thread=threading.Thread(target=self.listen_for_rc_connections)
        rc_listen_thread.start()
        sns_listen_thread=threading.Thread(target=self.listen_for_sniff_connections)
        sns_listen_thread.start()

        # Initialize a SniffSen object for sending sniff requests
        self.sniff_sender=SniffSen()

        # Load images for the GUI
        self.approve_img= Image.open("images/passed.png")
        self.approve_img = self.approve_img.resize((20, 20))  # Resize image
        self.approve_img = ImageTk.PhotoImage(self.approve_img)

        self.deny_img= Image.open("images/x.png")
        self.deny_img = self.deny_img.resize((20, 20))  # Resize image
        self.deny_img = ImageTk.PhotoImage(self.deny_img)

        escape_img=Image.open("images/escape.png")
        escape_img=escape_img.resize((35,35))
        escape_img = ImageTk.PhotoImage(escape_img)

        # Create tabs for the GUI
        action_bar = ttk.Notebook(self.root,style="Custom.TNotebook",takefocus=False)
        action_bar.pack(fill='x')

        # Create a tab for remote control
        self.remote_control_frame=ttk.Frame(action_bar)
        action_bar.add(self.remote_control_frame,text="Remote Control")

        # Create a tab for sniff sharing
        self.sniff_share_frame=ttk.Frame(action_bar)
        action_bar.add(self.sniff_share_frame,text="Sniff Share")

        # Create frames for the remote control tab
        self.escape_frame=ttk.Frame(self.remote_control_frame,padding=(5,5))
        self.escape_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.rc_ip_frame=ttk.Frame(self.remote_control_frame,borderwidth=4,relief='solid',padding=(10,13))
        self.rc_ip_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.rc_request_frame=ttk.Frame(self.remote_control_frame,borderwidth=4,relief='solid',padding=(10,13))
        self.rc_request_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.rc_buttons_frame=ttk.Frame(self.remote_control_frame,padding=(10,7))
        self.rc_buttons_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.rc_status_frame=ttk.Frame(self.remote_control_frame,padding=(10,0))
        self.rc_status_frame.pack(side=tk.TOP,padx=5,fill=tk.BOTH)

        #create widgets for escape frame
        escape_label = ttk.Label(self.escape_frame,text="Press escape at any time to exit share! ",font=(23,23) ,image=escape_img,compound='right',background='tomato2') # create a ttk label with text and image and add it to the escape frame
        escape_label.pack() # pack the label inside the escape frame

        #create widgets for ip frame
        your_ip_label = tk.Label(self.rc_ip_frame,text="Your Ip:",font=(30,30),border=0,borderwidth=0) # create a tk label with text and font and add it to the ip frame
        hedline_font = tkFont.Font(your_ip_label, your_ip_label.cget("font")) # create a font for the label
        hedline_font.configure(underline = True) # configure the font to be underlined
        your_ip_label.configure(font=hedline_font) # set the label font to the newly created font
        your_ip_label.pack(pady=10) # pack the label inside the ip frame with padding

        self.rc_ip_label= tk.Label(self.rc_ip_frame,text=self.my_ip,font=(20,20),border=0,borderwidth=0,background='light blue') # create a tk label with text, font, background and add it to the ip frame
        self.rc_ip_label.pack(pady=10) # pack the label inside the ip frame with padding

        #create widgets for request frame
        request_headline_label = tk.Label(self.rc_request_frame,text="Request:",font=(20,20),border=0,borderwidth=0,width=35) # create a tk label with text, font, borderwidth, width and add it to the request frame
        hedline_font = tkFont.Font(request_headline_label, request_headline_label.cget("font")) # create a font for the label
        hedline_font.configure(underline = True) # configure the font to be underlined
        request_headline_label.configure(font=hedline_font) # set the label font to the newly created font
        request_headline_label.grid(row=0,column=0,pady=10,columnspan=2,sticky='ew')

        name_label= tk.Label(self.rc_request_frame,text="Name:",font=(16,16),border=0,borderwidth=0)
        underline_font = tkFont.Font(name_label, name_label.cget("font"))
        underline_font.configure(underline = True)
        name_label.grid(row=1,column=0,pady=10,sticky='w')
        name_label.configure(font=underline_font)
        self.rc_name_value_label= tk.Label(self.rc_request_frame,text="",font=(16,16),border=0,borderwidth=0)
        self.rc_name_value_label.grid(row=1,column=1,pady=10,sticky='w')

        request_ip_label= tk.Label(self.rc_request_frame,text="IP:",font=(16,16),border=0,borderwidth=0)
        request_ip_label.grid(row=2,column=0,pady=10,sticky='w')
        request_ip_label.configure(font=underline_font)
        self.rc_request_ip_value_label= tk.Label(self.rc_request_frame,text="",font=(16,16),border=0,borderwidth=0)
        self.rc_request_ip_value_label.grid(row=2,column=1,pady=10,sticky='w')

        reason_label= tk.Label(self.rc_request_frame,text="Reason:",font=(16,16),border=0,borderwidth=0)
        reason_label.grid(row=3,column=0,pady=10,sticky='w')
        reason_label.configure(font=underline_font)
        self.rc_reason_value_label= tk.Label(self.rc_request_frame,text="",font=(16,16),border=0,borderwidth=0)
        self.rc_reason_value_label.grid(row=3,column=1,pady=10,sticky='w')

        #create widgets for buttons frame
        self.rc_approve_button = ttk.Button(self.rc_buttons_frame, text="Approve",image=self.approve_img,compound='right',width=30,padding=(10,20),state=tk.DISABLED,command=lambda:self.start_rc_connection_thread('a'))
        self.rc_approve_button.grid(row=0,column=0,padx=(42,5))

        self.rc_deny_button = ttk.Button(self.rc_buttons_frame, text="Deny",width=30,padding=(10,20),image=self.deny_img,compound='right',state=tk.DISABLED,command=lambda:self.start_rc_connection_thread('d'))
        self.rc_deny_button.grid(row=0,column=1,padx=(30,5))

        #create widgets for status frame
        self.rc_status_label= tk.Label(self.rc_status_frame,text="",font=(16,16),border=0,borderwidth=0)
        self.rc_status_label.pack()

        #-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

        #create frames for sniff share frame
        self.sns_ip_frame=ttk.Frame(self.sniff_share_frame,borderwidth=4,relief='solid',padding=(10,13))
        self.sns_ip_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.sns_request_frame=ttk.Frame(self.sniff_share_frame,borderwidth=4,relief='solid',padding=(10,13))
        self.sns_request_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.sns_buttons_frame=ttk.Frame(self.sniff_share_frame,padding=(10,7))
        self.sns_buttons_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.sns_status_frame=ttk.Frame(self.sniff_share_frame,padding=(10,0))
        self.sns_status_frame.pack(side=tk.TOP,padx=5,fill=tk.BOTH)

        #create widgets for ip frame
        your_ip_label = tk.Label(self.sns_ip_frame,text="Your Ip:",font=(30,30),border=0,borderwidth=0)
        hedline_font = tkFont.Font(your_ip_label, your_ip_label.cget("font"))
        hedline_font.configure(underline = True)
        your_ip_label.configure(font=hedline_font)
        your_ip_label.pack(pady=10)

        self.sns_ip_label= tk.Label(self.sns_ip_frame,text=self.my_ip,font=(20,20),border=0,borderwidth=0,background='light blue')
        self.sns_ip_label.pack(pady=10)

        #create widgets for request frame
        request_headline_label = tk.Label(self.sns_request_frame,text="Request:",font=(20,20),border=0,borderwidth=0,width=35)
        hedline_font = tkFont.Font(request_headline_label, request_headline_label.cget("font"))
        hedline_font.configure(underline = True)
        request_headline_label.configure(font=hedline_font)
        request_headline_label.grid(row=0,column=0,pady=10,columnspan=2,sticky='ew')

        name_label = tk.Label(self.sns_request_frame,text="Name:",font=(16, 16),border=0,borderwidth=0)
        # create an underline font for the label
        underline_font = tkFont.Font(name_label, name_label.cget("font"))
        underline_font.configure(underline=True)
        # configure the label with the underline font and grid it
        name_label.grid(row=1, column=0, pady=10, sticky='w')
        name_label.configure(font=underline_font)
        # create a label to display the name value
        self.sns_name_value_label = tk.Label(self.sns_request_frame,text="",font=(16, 16),border=0,borderwidth=0)
        # grid the name value label
        self.sns_name_value_label.grid(row=1, column=1, pady=10, sticky='w')

        # create a label for "IP:"
        request_ip_label = tk.Label(self.sns_request_frame,text="IP:",font=(16, 16),border=0,borderwidth=0)
        # configure the label with the underline font and grid it
        request_ip_label.grid(row=2, column=0, pady=10, sticky='w')
        request_ip_label.configure(font=underline_font)
        # create a label to display the request IP value
        self.sns_request_ip_value_label = tk.Label(self.sns_request_frame,text="",font=(16, 16),border=0,borderwidth=0)
        # grid the request IP value label
        self.sns_request_ip_value_label.grid(row=2, column=1, pady=10, sticky='w')

        # create a label for "Reason:"
        reason_label = tk.Label(self.sns_request_frame,text="Reason:",font=(16, 16),border=0,borderwidth=0)
        # configure the label with the underline font and grid it
        reason_label.grid(row=3, column=0, pady=10, sticky='w')
        reason_label.configure(font=underline_font)
        # create a label to display the reason value
        self.sns_reason_value_label = tk.Label(self.sns_request_frame,text="",font=(16, 16),border=0,borderwidth=0)
        # grid the reason value label
        self.sns_reason_value_label.grid(row=3, column=1, pady=10, sticky='w')

        #create widgets for buttons frame
        self.sns_approve_button = ttk.Button(self.sns_buttons_frame, text="Approve",image=self.approve_img,compound='right',width=30,padding=(10,20),state=tk.DISABLED,command=lambda:self.start_sniff_connection_thread('a'))
        self.sns_approve_button.grid(row=0,column=0,padx=(42,5))

        self.sns_deny_button = ttk.Button(self.sns_buttons_frame, text="Deny",width=30,padding=(10,20),image=self.deny_img,compound='right',state=tk.DISABLED,command=lambda:self.start_sniff_connection_thread('d'))
        self.sns_deny_button.grid(row=0,column=1,padx=(30,5))

        #create widgets for status frame
        self.sns_status_label= tk.Label(self.sns_status_frame,text="",font=(16,16),border=0,borderwidth=0)
        self.sns_status_label.pack()

        self.root.mainloop()

    def listen_for_rc_connections(self):
        while self.running:
            try:
                # create and start encrypted server
                self.rc_server = encrypted_server(11123)
                self.rc_server.start_server(first_connection=True)
                break
            except:
                try:
                    # close server socket and client socket if they exist
                    self.rc_server.server_socket.close()
                    self.rc_server.client.close()
                except:
                    pass
                finally:
                    # delete server object
                    del self.rc_server
                    # exit thread
                    return

        # receive data from client
        info = self.rc_server.recieve().split(',')
        # extract quality parameter from data
        self.quality = int(info[2])
        # extract client IP address from server object
        request_ip = self.rc_server.addr[0]
        # set GUI label texts with received data
        self.rc_request_ip_value_label.config(text=request_ip)
        name = info[0]
        self.rc_name_value_label.config(text=name)
        reason = info[1]
        self.rc_reason_value_label.config(text=reason)
        # enable approve and deny buttons
        self.rc_approve_button.config(state=tk.ACTIVE)
        self.rc_deny_button.config(state=tk.ACTIVE)

    def on_click_link(self, event, link):
        import webbrowser
        # open link in the default web browser
        webbrowser.open_new(link)
                
    def start_rc_connection_thread(self, code):
        if code == 'a':
            # start a new thread to handle approved connection
            threading.Thread(target=self.start_connection).start()
        else:
            # start a new thread to handle denied connection
            threading.Thread(target=self.deny_rc_connection).start()

    def start_connection(self):
        # send 'approved' message to client
        self.rc_server.send('approved')
        # update GUI status label
        self.rc_status_label.config(text='connecting...')
        # create and start RemoteControlled object
        rc = RemoteControlled(self.quality)
        # create multiprocessing pipes for IPC
        this_pipe, other_pipe = multiprocessing.Pipe()
        # start RemoteControlled process
        p = multiprocessing.Process(target=rc.start_share, args=(other_pipe,))
        p.start()
        # receive connection status from RemoteControlled process
        is_connected = this_pipe.recv()
        # minimize main GUI window
        self.root.iconify()
        self.root.withdraw()
        # create top bar GUI element in a new thread
        bar_thr = threading.Thread(target=self.create_top_bar)
        bar_thr.start()
        # receive exit reason from RemoteControlled process
        exit_reason = this_pipe.recv()
        print('share ended')
        # restore main GUI window
        self.root.deiconify()
        self.root.wm_state("normal")
        # update GUI status label with exit reason
        if exit_reason == 'controlled computer disconnected':
            self.rc_status_label.config(text="Other computer stopped control or had a problem!")
        else:
            self.rc_status_label.config(text="")
        # clean up server object and GUI elements
        self.clean_rc_request()
        try:
            self.rc_server.server_socket.close()
            self.rc_server.client.close()
        finally:
            del self.rc_server
        # start listening for new RemoteControlled connections in a new thread
        listen_thread = threading.Thread(target=self.listen_for_rc_connections)
        listen_thread.start()
        # destroy top bar GUI element
        self.top_bar_root.destroy()

    # Method to deny remote control connection
    def deny_rc_connection(self):
        # send message to client
        self.rc_server.send('denied')
        # clean up the GUI
        self.clean_rc_request()
        # wait for 1 second
        time.sleep(1)
        try:
            # close the socket connection
            self.rc_server.server_socket.close()
            self.rc_server.client.close()
        finally:
            # delete the RC server instance
            del self.rc_server

        # start listening for new RC connections
        listen_thread = threading.Thread(target=self.listen_for_rc_connections)
        listen_thread.start()

    # Method to create the top bar GUI
    def create_top_bar(self):
        # create the main window
        self.top_bar_root = tk.Toplevel(self.root)
        bcolor = 'green'
        # set the background color
        self.top_bar_root.configure(bg=bcolor)
        # remove window decorations
        self.top_bar_root.overrideredirect(True)
        # bring window to the front
        self.top_bar_root.lift()
        # set the window to always stay on top
        self.top_bar_root.wm_attributes("-topmost", True)

        # get the screen dimensions
        screen_width = self.top_bar_root.winfo_screenwidth()

        # set the size and position of the window
        window_width = 400
        window_height = 20
        pos_x = (screen_width // 2) - (window_width // 2)
        pos_y = 0
        self.top_bar_root.geometry(f"{window_width}x{window_height}+{pos_x}+{pos_y}")

        # create a label widget with the text you want to display
        label = tk.Label(self.top_bar_root, text="Remote controll active. Press esc to exit!", font=("Arial", 14), background=bcolor)
        label.pack()

        # remove the ability to resize or move the window
        self.top_bar_root.resizable(False, False)
        self.top_bar_root.overrideredirect(True)

    # Method to clean up the RC request GUI
    def clean_rc_request(self):
        # disable the approve and deny buttons
        self.rc_approve_button.config(state=tk.DISABLED)
        self.rc_deny_button.config(state=tk.DISABLED)
        # clear the name, IP, and reason values
        self.rc_name_value_label.config(text='')
        self.rc_request_ip_value_label.config(text='')
        self.rc_reason_value_label.config(text='')

    # Define a method to listen for sniffing connections
    def listen_for_sniff_connections(self):
        # Keep running the while loop until the program is closed
        while self.running:
            try:
                # Create an encrypted server object on port 28245 and start it
                self.sniff_server = encrypted_server(28245)
                self.sniff_server.start_server(first_connection=True)
                # If the server starts successfully, exit the loop
                break
            except:
                try:
                    # Attempt to close the server socket and client connection
                    self.sniff_server.server_socket.close()
                    self.sniff_server.client.close()
                except:
                    # If an error occurs while closing the connections, do nothing
                    pass
                finally:
                    # Delete the sniff server object and return to the beginning of the loop
                    del self.sniff_server
                    return

        # If a connection is received, receive the data and update the GUI labels and buttons accordingly
        info = self.sniff_server.recieve().split(',')
        request_ip = self.sniff_server.addr[0]
        self.sns_request_ip_value_label.config(text=request_ip)
        name = info[0]
        self.sns_name_value_label.config(text=name)
        reason = info[1]
        self.sns_reason_value_label.config(text=reason)
        self.sns_approve_button.config(state=tk.ACTIVE)
        self.sns_deny_button.config(state=tk.ACTIVE)

    # Define a method to start the sniffing connection thread
    def start_sniff_connection_thread(self, code):
        # If the code is 'a', start a new thread to share the sniff data
        if code == 'a':
            threading.Thread(target=self.share_sniff).start()
        # Otherwise, start a new thread to deny the sniff request
        else:
            threading.Thread(target=self.deny_sniff_connection).start()

    # Define a method to share the sniff data
    def share_sniff(self):
        # Send a message to the client indicating that the sniff request was approved
        self.sniff_server.send('approved')
        # Clean up the GUI labels and buttons related to the sniff request
        self.clean_sniff_request()

        try:
            # Send the captured packet data to the client
            self.sniff_sender.send_pcap()
            # Update the GUI status label to indicate that the data has been shared
            self.sns_status_label.config(text='sniff share completed!')
            # Close the server socket and client connection
            self.sniff_server.server_socket.close()
            self.sniff_server.client.close()
        except:
            # If an error occurs while sending the data or closing the connections, do nothing
            pass
        finally:
            # Delete the sniff server object and start listening for new connections
            del self.sniff_server
            listen_thread = threading.Thread(target=self.listen_for_sniff_connections)
            listen_thread.start()

    def deny_sniff_connection(self):
        # Send 'denied' message to the client who requested sniffing
        self.sniff_server.send('denied')
        
        # Clean up the GUI after denying the request
        self.clean_sniff_request()
        
        # Wait for 1 second before closing the server socket and client connection
        time.sleep(1)
        
        try:
            # Close the server socket and client connection
            self.sniff_server.server_socket.close()
            self.sniff_server.client.close()
        finally:
            # Delete the server object from memory
            del self.sniff_server
        
        # Start listening for new sniff requests
        listen_thread = threading.Thread(target=self.listen_for_sniff_connections)
        listen_thread.start()

    def clean_sniff_request(self):
        # Disable the approve and deny buttons in the GUI
        self.sns_approve_button.config(state=tk.DISABLED)
        self.sns_deny_button.config(state=tk.DISABLED)
        
        # Clear the text labels in the GUI
        self.sns_name_value_label.config(text='')
        self.sns_request_ip_value_label.config(text='')
        self.sns_reason_value_label.config(text='')

if __name__=='__main__':
    # Freeze the code to create a standalone executable
    multiprocessing.freeze_support()
    
    # Create an instance of the GUI
    cg = controlled_gui()
    
    try:
        # Close the server socket and client connection for the reverse connection
        cg.rc_server.server_socket.close()
        if hasattr(cg.rc_server, 'client'):
            cg.rc_server.client.close()
        del cg.rc_server.server_socket
        
        # Close the server socket and client connection for the sniff request
        cg.sniff_server.server_socket.close()
        if hasattr(cg.sniff_server, 'client'):
            cg.sniff_server.client.close()
        del cg.sniff_server.server_socket
    except:
        pass
    finally:
        # Set the scanning flag in the sniff_sender object to False
        cg.sniff_sender.scanning = False
        
        # Set the running flag to False to stop all threads
        cg.running = False
