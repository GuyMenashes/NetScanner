import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import tkinter.font as tkFont
from get_net_info import get_ip_info
from PIL import Image,ImageTk
from encrypted_server import encrypted_server
import time
from Controlled import RemoteControlled
import threading
import multiprocessing
from sniffSen import SniffSen
from scapy.all import *

class controlled_gui:
    def __init__(self):
        try:
            sniff(1)
        except:
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
        self.running=True
        try:
            self.my_ip =get_ip_info()[0]
        except:
            messagebox.showerror("Error", "You must be connected to wifi in order to start this app!")
            quit()
        self.root = tk.Tk()
        self.root.geometry('600x675')
        self.root.title("Network Manager")
        self.root.resizable(False,False)

        rc_listen_thread=threading.Thread(target=self.listen_for_rc_connections)
        rc_listen_thread.start()
        
        sns_listen_thread=threading.Thread(target=self.listen_for_sniff_connections)
        sns_listen_thread.start()

        self.sniff_sender=SniffSen()

        # create menu bar
        self.menu_bar = tk.Menu(self.root)
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="Exit", command=self.root.quit)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)

        settings_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Settings", menu=settings_menu)

        help_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=self.menu_bar)

        #load images
        self.approve_img= Image.open("images/passed.png")
        self.approve_img = self.approve_img.resize((20, 20))  # Resize image
        self.approve_img = ImageTk.PhotoImage(self.approve_img)

        self.deny_img= Image.open("images/x.png")
        self.deny_img = self.deny_img.resize((20, 20))  # Resize image
        self.deny_img = ImageTk.PhotoImage(self.deny_img)

        escape_img=Image.open("images/escape.png")
        escape_img=escape_img.resize((35,35))
        escape_img = ImageTk.PhotoImage(escape_img)

        #create screens
        action_bar = ttk.Notebook(self.root,style="Custom.TNotebook",takefocus=False)
        action_bar.pack(fill='x')

        self.remote_control_frame=ttk.Frame(action_bar)
        action_bar.add(self.remote_control_frame,text="Remote Control")

        self.sniff_share_frame=ttk.Frame(action_bar)
        action_bar.add(self.sniff_share_frame,text="Sniff Share")

        #create frames for remote_control_frame
        self.escape_frame=ttk.Frame(self.remote_control_frame,padding=(5,5))
        self.escape_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.rc_ip_frame=ttk.Frame(self.remote_control_frame,borderwidth=4,relief='solid',padding=(10,20))
        self.rc_ip_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.rc_request_frame=ttk.Frame(self.remote_control_frame,borderwidth=4,relief='solid',padding=(10,20))
        self.rc_request_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.rc_buttons_frame=ttk.Frame(self.remote_control_frame,padding=(10,20))
        self.rc_buttons_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.rc_status_frame=ttk.Frame(self.remote_control_frame,padding=(10,0))
        self.rc_status_frame.pack(side=tk.TOP,padx=5,fill=tk.BOTH)

        #create widgets for escape frame
        escape_label = ttk.Label(self.escape_frame,text="Press escape at any time to exit share! ",font=(23,23) ,image=escape_img,compound='right',background='tomato2')
        escape_label.pack()

        #create widgets for ip frame
        your_ip_label = tk.Label(self.rc_ip_frame,text="Your Ip:",font=(30,30),border=0,borderwidth=0)
        hedline_font = tkFont.Font(your_ip_label, your_ip_label.cget("font"))
        hedline_font.configure(underline = True)
        your_ip_label.configure(font=hedline_font)
        your_ip_label.pack(pady=10)

        self.rc_ip_label= tk.Label(self.rc_ip_frame,text=self.my_ip,font=(20,20),border=0,borderwidth=0,background='light blue')
        self.rc_ip_label.pack(pady=10)

        #create widgets for request frame
        request_headline_label = tk.Label(self.rc_request_frame,text="Request:",font=(20,20),border=0,borderwidth=0,width=35)
        hedline_font = tkFont.Font(request_headline_label, request_headline_label.cget("font"))
        hedline_font.configure(underline = True)
        request_headline_label.configure(font=hedline_font)
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
        self.sns_ip_frame=ttk.Frame(self.sniff_share_frame,borderwidth=4,relief='solid',padding=(10,20))
        self.sns_ip_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.sns_request_frame=ttk.Frame(self.sniff_share_frame,borderwidth=4,relief='solid',padding=(10,20))
        self.sns_request_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.sns_buttons_frame=ttk.Frame(self.sniff_share_frame,padding=(10,20))
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

        name_label= tk.Label(self.sns_request_frame,text="Name:",font=(16,16),border=0,borderwidth=0)
        underline_font = tkFont.Font(name_label, name_label.cget("font"))
        underline_font.configure(underline = True)
        name_label.grid(row=1,column=0,pady=10,sticky='w')
        name_label.configure(font=underline_font)
        self.sns_name_value_label= tk.Label(self.sns_request_frame,text="",font=(16,16),border=0,borderwidth=0)
        self.sns_name_value_label.grid(row=1,column=1,pady=10,sticky='w')

        request_ip_label= tk.Label(self.sns_request_frame,text="IP:",font=(16,16),border=0,borderwidth=0)
        request_ip_label.grid(row=2,column=0,pady=10,sticky='w')
        request_ip_label.configure(font=underline_font)
        self.sns_request_ip_value_label= tk.Label(self.sns_request_frame,text="",font=(16,16),border=0,borderwidth=0)
        self.sns_request_ip_value_label.grid(row=2,column=1,pady=10,sticky='w')

        reason_label= tk.Label(self.sns_request_frame,text="Reason:",font=(16,16),border=0,borderwidth=0)
        reason_label.grid(row=3,column=0,pady=10,sticky='w')
        reason_label.configure(font=underline_font)
        self.sns_reason_value_label= tk.Label(self.sns_request_frame,text="",font=(16,16),border=0,borderwidth=0)
        self.sns_reason_value_label.grid(row=3,column=1,pady=10,sticky='w')

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
                self.rc_server=encrypted_server(11123)
                self.rc_server.start_server(first_connection=True)
                break
            except:
                try:
                    self.rc_server.server_socket.close()
                    self.rc_server.client.close()
                except:
                    pass
                finally:
                    del self.rc_server
                    return
                
        info=self.rc_server.recieve().split(',')
        self.quality=int(info[2])
        request_ip=self.rc_server.addr[0]
        self.rc_request_ip_value_label.config(text=request_ip)
        name=info[0]
        self.rc_name_value_label.config(text=name)
        reason=info[1]
        self.rc_reason_value_label.config(text=reason)
        self.rc_approve_button.config(state=tk.ACTIVE)
        self.rc_deny_button.config(state=tk.ACTIVE)

    def on_click_link(self,event, link):
        import webbrowser
        webbrowser.open_new(link)
                
    def start_rc_connection_thread(self,code):
        if code=='a':
            threading.Thread(target=self.start_connection).start()
        else:
            threading.Thread(target=self.deny_rc_connection).start()

    def start_connection(self):
        self.rc_server.send('approved')
        self.rc_status_label.config(text='connecting...')

        rc=RemoteControlled(self.quality)
        this_pipe,other_pipe=multiprocessing.Pipe()
        p=multiprocessing.Process(target=rc.start_share,args=(other_pipe,))
        p.start()

        is_connected=this_pipe.recv()
        self.root.iconify()
        self.root.withdraw()
        bar_thr=threading.Thread(target=self.create_top_bar)
        bar_thr.start()
        exit_reason=this_pipe.recv()
        self.root.deiconify()
        self.root.wm_state("normal")

        if exit_reason=='controlled computer disconnected':
            self.rc_status_label.config(text="Other computer stopped control or had a problem!")
        else:
            self.rc_status_label.config(text="")

        self.clean_rc_request()
        try:
            self.rc_server.server_socket.close()
            self.rc_server.client.close()
        finally:
            del self.rc_server

        listen_thread=threading.Thread(target=self.listen_for_rc_connections)
        listen_thread.start()

        self.top_bar_root.destroy()

    def deny_rc_connection(self):
        self.rc_server.send('denied')
        self.clean_rc_request()
        time.sleep(1)
        try:
            self.rc_server.server_socket.close()
            self.rc_server.client.close()
        finally:
            del self.rc_server

        listen_thread=threading.Thread(target=self.listen_for_rc_connections)
        listen_thread.start()

    def create_top_bar(self):
        # create the main window
        self.top_bar_root = tk.Toplevel(self.root)
        bcolor='green'
        self.top_bar_root.configure(bg=bcolor)
        self.top_bar_root.overrideredirect(True)  # removes the window decorations
        self.top_bar_root.lift()  # brings the window to the front
        self.top_bar_root.wm_attributes("-topmost", True)  # set the window to always stay on top

        # get the screen dimensions
        screen_width = self.top_bar_root.winfo_screenwidth()

        # set the size and position of the window
        window_width = 400
        window_height = 20
        pos_x = (screen_width // 2) - (window_width // 2)
        pos_y = 0
        self.top_bar_root.geometry(f"{window_width}x{window_height}+{pos_x}+{pos_y}")

        # create a label widget with the text you want to display
        label = tk.Label(self.top_bar_root, text="Remote controll active. Press esc to exit!", font=("Arial", 14),background=bcolor)
        label.pack()

        # remove the ability to resize or move the window
        self.top_bar_root.resizable(False, False)
        self.top_bar_root.overrideredirect(True)

    def clean_rc_request(self):
        self.rc_approve_button.config(state=tk.DISABLED)
        self.rc_deny_button.config(state=tk.DISABLED)
        self.rc_name_value_label.config(text='')
        self.rc_request_ip_value_label.config(text='')
        self.rc_reason_value_label.config(text='')

    def listen_for_sniff_connections(self):
        while self.running:
            try:
                self.sniff_server=encrypted_server(28245)
                self.sniff_server.start_server(first_connection=True)
                break
            except:
                try:
                    self.sniff_server.server_socket.close()
                    self.sniff_server.client.close()
                except:
                    pass
                finally:
                    del self.sniff_server
                    return

        info=self.sniff_server.recieve().split(',')
        request_ip=self.sniff_server.addr[0]
        self.sns_request_ip_value_label.config(text=request_ip)
        name=info[0]
        self.sns_name_value_label.config(text=name)
        reason=info[1]
        self.sns_reason_value_label.config(text=reason)
        self.sns_approve_button.config(state=tk.ACTIVE)
        self.sns_deny_button.config(state=tk.ACTIVE)

    def start_sniff_connection_thread(self,code):
        if code=='a':
            threading.Thread(target=self.share_sniff).start()
        else:
            threading.Thread(target=self.deny_sniff_connection).start()

    def share_sniff(self):
        self.sniff_server.send('approved')
        self.clean_sniff_request()

        try:
            self.sniff_sender.send_pcap()
            self.sns_status_label.config(text='sniff share completed!')
            self.sniff_server.server_socket.close()
            self.sniff_server.client.close()
        except:
            pass
        finally:
            del self.sniff_server

        listen_thread=threading.Thread(target=self.listen_for_sniff_connections)
        listen_thread.start()

    def deny_sniff_connection(self):
        self.sniff_server.send('denied')
        self.clean_sniff_request()
        time.sleep(1)
        try:
            self.sniff_server.server_socket.close()
            self.sniff_server.client.close()
        finally:
            del self.sniff_server

        listen_thread=threading.Thread(target=self.listen_for_sniff_connections)
        listen_thread.start()

    def clean_sniff_request(self):
        self.sns_approve_button.config(state=tk.DISABLED)
        self.sns_deny_button.config(state=tk.DISABLED)
        self.sns_name_value_label.config(text='')
        self.sns_request_ip_value_label.config(text='')
        self.sns_reason_value_label.config(text='')

if __name__=='__main__':
    multiprocessing.freeze_support()
    cg=controlled_gui()
    try:
        cg.rc_server.server_socket.close()
        cg.rc_server.client.close()
        cg.sniff_server.server_socket.close()
        cg.sniff_server.client.close()
    except:
        pass
    finally:
        cg.sniff_sender.scanning=False
        cg.running=False
    