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

class controlled_gui:
    def __init__(self):
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

        listen_thread=threading.Thread(target=self.listen_for_connections)
        listen_thread.start()

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

        #create frames
        self.escape_frame=ttk.Frame(self.root,padding=(5,5))
        self.escape_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.ip_frame=ttk.Frame(self.root,borderwidth=4,relief='solid',padding=(10,20))
        self.ip_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.request_frame=ttk.Frame(self.root,borderwidth=4,relief='solid',padding=(10,20))
        self.request_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.buttons_frame=ttk.Frame(self.root,padding=(10,20))
        self.buttons_frame.pack(side=tk.TOP,padx=5, pady=5,fill=tk.BOTH)

        self.status_frame=ttk.Frame(self.root,padding=(10,0))
        self.status_frame.pack(side=tk.TOP,padx=5,fill=tk.BOTH)

        #create widgets for escape frame
        escape_label = ttk.Label(self.escape_frame,text="Press escape at any time to exit share! ",font=(23,23) ,image=escape_img,compound='right',background='tomato2')
        escape_label.pack()

        #create widgets for ip frame
        your_ip_label = tk.Label(self.ip_frame,text="Your Ip:",font=(30,30),border=0,borderwidth=0)
        hedline_font = tkFont.Font(your_ip_label, your_ip_label.cget("font"))
        hedline_font.configure(underline = True)
        your_ip_label.configure(font=hedline_font)
        your_ip_label.pack(pady=10)

        self.ip_label= tk.Label(self.ip_frame,text=self.my_ip,font=(20,20),border=0,borderwidth=0,background='light blue')
        self.ip_label.pack(pady=10)

        #create widgets for request frame
        request_headline_label = tk.Label(self.request_frame,text="Request:",font=(20,20),border=0,borderwidth=0,width=35)
        hedline_font = tkFont.Font(request_headline_label, request_headline_label.cget("font"))
        hedline_font.configure(underline = True)
        request_headline_label.configure(font=hedline_font)
        request_headline_label.grid(row=0,column=0,pady=10,columnspan=2,sticky='ew')

        name_label= tk.Label(self.request_frame,text="Name:",font=(16,16),border=0,borderwidth=0)
        underline_font = tkFont.Font(name_label, name_label.cget("font"))
        underline_font.configure(underline = True)
        name_label.grid(row=1,column=0,pady=10,sticky='w')
        name_label.configure(font=underline_font)
        self.name_value_label= tk.Label(self.request_frame,text="",font=(16,16),border=0,borderwidth=0)
        self.name_value_label.grid(row=1,column=1,pady=10,sticky='w')

        request_ip_label= tk.Label(self.request_frame,text="IP:",font=(16,16),border=0,borderwidth=0)
        request_ip_label.grid(row=2,column=0,pady=10,sticky='w')
        request_ip_label.configure(font=underline_font)
        self.request_ip_value_label= tk.Label(self.request_frame,text="",font=(16,16),border=0,borderwidth=0)
        self.request_ip_value_label.grid(row=2,column=1,pady=10,sticky='w')

        reason_label= tk.Label(self.request_frame,text="Reason:",font=(16,16),border=0,borderwidth=0)
        reason_label.grid(row=3,column=0,pady=10,sticky='w')
        reason_label.configure(font=underline_font)
        self.reason_value_label= tk.Label(self.request_frame,text="",font=(16,16),border=0,borderwidth=0)
        self.reason_value_label.grid(row=3,column=1,pady=10,sticky='w')

        #create widgets for buttons frame
        self.approve_button = ttk.Button(self.buttons_frame, text="Approve",image=self.approve_img,compound='right',width=30,padding=(10,20),state=tk.DISABLED,command=lambda:self.start_thread('a'))
        self.approve_button.grid(row=0,column=0,padx=(42,5))

        self.deny_button = ttk.Button(self.buttons_frame, text="Deny",width=30,padding=(10,20),image=self.deny_img,compound='right',state=tk.DISABLED,command=lambda:self.start_thread('d'))
        self.deny_button.grid(row=0,column=1,padx=(30,5))

        #create widgets for status frame
        self.status_label= tk.Label(self.status_frame,text="",font=(16,16),border=0,borderwidth=0)
        self.status_label.pack()

        self.root.mainloop()

    def listen_for_connections(self):
        while self.running:
            try:
                self.server=encrypted_server(11123)
                self.server.start_server(first_connection=True)
                break
            except:
                try:
                    self.server.server_socket.close()
                    self.server.client.close()
                except:
                    pass
                finally:
                    del self.server
                    return

        info=self.server.recieve().split(',')
        self.quality=int(info[2])
        controller_ip=self.server.addr[0]
        self.request_ip_value_label.config(text=controller_ip)
        name=info[0]
        self.name_value_label.config(text=name)
        reason=info[1]
        self.reason_value_label.config(text=reason)
        self.approve_button.config(state=tk.ACTIVE)
        self.deny_button.config(state=tk.ACTIVE)

    def start_thread(self,code):
        if code=='a':
            threading.Thread(target=self.start_connection).start()
        else:
            threading.Thread(target=self.deny_connection).start()

    def start_connection(self):
        self.server.send('approved')
        self.status_label.config(text='connecting...')

        rc=RemoteControlled(self.quality)
        this_pipe,other_pipe=multiprocessing.Pipe()
        p=multiprocessing.Process(target=rc.start_share,args=(other_pipe,))
        p.start()
        self.root.iconify()
        self.root.withdraw()
        exit_reason=this_pipe.recv()
        self.root.deiconify()
        if exit_reason=='controlled computer disconnected':
            print(1)
            self.status_label.config(text="other computer stopped control or expirienced a problem/shut down!")
        else:
            self.status_label.config(text="")

        self.clean_request()
        try:
            self.server.server_socket.close()
            self.server.client.close()
        finally:
            del self.server

        listen_thread=threading.Thread(target=self.listen_for_connections)
        listen_thread.start()

    def deny_connection(self):
        self.server.send('denied')
        self.clean_request()
        time.sleep(1)
        try:
            self.server.server_socket.close()
            self.server.client.close()
        finally:
            del self.server

        listen_thread=threading.Thread(target=self.listen_for_connections)
        listen_thread.start()
    
    def clean_request(self):
        self.approve_button.config(state=tk.DISABLED)
        self.deny_button.config(state=tk.DISABLED)
        self.name_value_label.config(text='')
        self.request_ip_value_label.config(text='')
        self.reason_value_label.config(text='')

if __name__=='__main__':
    multiprocessing.freeze_support()
    cg=controlled_gui()
    try:
        cg.server.server_socket.close()
        cg.server.client.close()
    except:
        pass
    finally:
        cg.running=False
    