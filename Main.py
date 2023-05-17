# Importing necessary modules
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import tkinter.font as tkFont
from network_scanner import network_scanner
import threading,multiprocessing
import get_net_info
import Device
from PIL import Image,ImageTk
import shutdown_restart
import textwrap
import re
from wifi_pass_tester import password_tester
import traffic_testing
import attacks_detection
import socket
from encrypted_client import encrypted_client
from Controller import RemoteController
import time
import os
from scapy.all import *
import datetime
from tkinter import filedialog
import shutil

class gui:
    # Initialize the GUI class
    def __init__(self):
        # Get the IP address of the current device and the router's IP address
        try:
            self.my_ip = get_net_info.get_ip_info()[0]
            self.router_ip = get_net_info.get_ip_info()[1]
        except:
            # If there is an error, show an error message and exit the program
            messagebox.showerror("Error", "You must be connected to wifi in order to start this app!")
            sys.exit()

        # Check if winpcap is installed on the system
        try:
            sniff(1)
        except:
            # If winpcap is not installed, show a dialog box with a link to download it
            link='https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe'
            dialog = tk.Tk()
            dialog.title("Winpcap Error")
            label = tk.Label(dialog, text="In order to use this app, please download winpcap from this link:")
            label.pack(padx=10, pady=5)
            # Create a clickable link to open the download link in a web browser
            link_label = tk.Label(dialog, text=link, fg="blue", cursor="hand2")
            link_label.pack(padx=10, pady=5)
            link_label.bind("<Button-1>", lambda event: self.on_click_link(event, link))
            dialog.mainloop()
            quit()

        # Initialize the network scanner object
        self.net_scanner = network_scanner()
        # Initialize variables for scanning and detecting network attacks
        self.scanning = False
        self.scanning_thr=threading.Thread()
        self.attack_detecter=attacks_detection.network_attack_detector()
        self.attack_detecter.start_sniffers()

        # Create the main window for the GUI
        self.root = tk.Tk()
        # Maximize the window to fill the screen
        self.root.state('zoomed')
        # Set the title of the window
        self.root.title("Network Manager")

        #Sets the icon of the root window to 'icon.ico' in a separate thread, allowing the GUI to remain responsive to user input while the operation completes.
        threading.Thread(target=lambda:self.root.iconbitmap('icon.ico')).start()

        # Initialize a thread to check the connection status
        self.connection_check_thr=threading.Thread(target=self.check_connection)
        self.connection_check_thr.start()

        # Set default font family and size
        self.font_family = "Courier New"
        self.font_size = 14

        # Configure styles for GUI elements using the default font and size
        ttk.Style().configure("Treeview", font=(self.font_family, self.font_size), rowheight=36)
        ttk.Style().configure("TButton", font=(self.font_family, self.font_size), padding=5)
        ttk.Style().configure("TEntry", font=(self.font_family, self.font_size), padding=5, height=3)
        ttk.Style().configure("TRadiobutton", font=(self.font_family, self.font_size))
        ttk.Style().configure("TCheckbutton", font=(self.font_family, self.font_size))
        ttk.Style().configure("TCombobox", font=(self.font_family, self.font_size), height=100)

        # Configure custom label styles with different foreground colors
        ttk.Style().configure("Red.TLabel", foreground="red")
        ttk.Style().configure("Grey.TLabel", foreground="grey25")
        ttk.Style().configure("Orange.TLabel", foreground="DarkOrange3")
        ttk.Style().configure("Yellow.TLabel", foreground="goldenrod1")

        # Load all images used in the GUI
        self.device_img = Image.open("images/device.png")
        self.device_img = self.device_img.resize((20, 20))  # Resize image
        self.device_img = ImageTk.PhotoImage(self.device_img)

        self.dead_device_img = Image.open("images/dead_device.png")
        self.dead_device_img = self.dead_device_img.resize((20, 20))  # Resize image
        self.dead_device_img = ImageTk.PhotoImage(self.dead_device_img)

        self.router_img = Image.open("images/router.png")
        self.router_img = self.router_img.resize((20, 20))  # Resize image
        self.router_img = ImageTk.PhotoImage(self.router_img)

        self.me_img = Image.open("images/me.png")
        self.me_img = self.me_img.resize((20, 20))  # Resize image
        self.me_img = ImageTk.PhotoImage(self.me_img)

        self.run_img = Image.open("images/run.png")
        self.run_img = self.run_img.resize((20, 20))  # Resize image
        self.run_img = ImageTk.PhotoImage(self.run_img)

        self.stop_img = Image.open("images/stop.png")
        self.stop_img = self.stop_img.resize((20, 20))  # Resize image
        self.stop_img = ImageTk.PhotoImage(self.stop_img)

        self.ps_load_img= Image.open("images/port_scan_load.png")
        self.ps_load_img = self.ps_load_img.resize((20, 20))  # Resize image
        self.ps_load_img = ImageTk.PhotoImage(self.ps_load_img)

        self.passed_img= Image.open("images/passed.png")
        self.passed_img = self.passed_img.resize((20, 20))  # Resize image
        self.passed_img = ImageTk.PhotoImage(self.passed_img)

        self.failed_img= Image.open("images/x.png")
        self.failed_img = self.failed_img.resize((20, 20))  # Resize image
        self.failed_img = ImageTk.PhotoImage(self.failed_img)

        self.question_img= Image.open("images/question_mark.png")
        self.question_img = self.question_img.resize((20, 20))  # Resize image
        self.question_img = ImageTk.PhotoImage(self.question_img)

        self.upload_img=Image.open("images/upload.png")
        self.upload_img=self.upload_img.resize((300,350))# Resize image
        self.upload_img = ImageTk.PhotoImage(self.upload_img)

        self.ping_img=Image.open("images/ping.png")
        self.ping_img=self.ping_img.resize((300,350))
        self.ping_img = ImageTk.PhotoImage(self.ping_img)

        self.bandwidth_img=Image.open("images/bandwidth.png")
        self.bandwidth_img=self.bandwidth_img.resize((300,350))# Resize image
        self.bandwidth_img = ImageTk.PhotoImage(self.bandwidth_img)

        self.latency_img=Image.open("images/latency.png")
        self.latency_img=self.latency_img.resize((300,350))# Resize image
        self.latency_img = ImageTk.PhotoImage(self.latency_img)

        self.download_img=Image.open("images/download.png")
        self.download_img = ImageTk.PhotoImage(self.download_img)

        self.escape_img=Image.open("images/escape.png")
        self.escape_img=self.escape_img.resize((35,35))# Resize image
        self.escape_img = ImageTk.PhotoImage(self.escape_img)

        #create action bar and add all window frames
        ttk.Style().configure('Custom.TNotebook', tabmargins=[2, 5, 2, 0])
        ttk.Style().configure('Custom.TNotebook.Tab', foreground='black', padding=[10, 5])

        self.action_bar = ttk.Notebook(self.root,style="Custom.TNotebook",takefocus=False)
        self.action_bar.pack(fill='x')

        self.network_scanner_frame=ttk.Frame(self.action_bar)
        self.action_bar.add(self.network_scanner_frame,text="Network Scanner")

        self.remote_control_frame=ttk.Frame(self.action_bar)
        self.action_bar.add(self.remote_control_frame,text="Remote Control")

        ttk.Style().configure('Custom.TFrame', background='gray35')
        self.network_testing_frame=ttk.Frame(self.action_bar,style='Custom.TFrame')
        self.action_bar.add(self.network_testing_frame,text="Netwotk Tester")

        self.sniff_share_frame=ttk.Frame(self.action_bar)
        self.action_bar.add(self.sniff_share_frame,text="Sniff Share")

        self.attack_detection_frame=ttk.Frame(self.action_bar)
        self.action_bar.add(self.attack_detection_frame,text="Attack Detector")

        self.password_testing_frame=ttk.Frame(self.action_bar)
        self.action_bar.add(self.password_testing_frame,text="Password Tester")

        #create frames for sniff share
        self.sender_info_frame=ttk.Frame(self.sniff_share_frame,relief='solid',padding=17)
        self.sender_info_frame.pack(padx=5, pady=0,fill=tk.X,anchor=tk.CENTER)

        self.reciever_info_frame=ttk.Frame(self.sniff_share_frame,relief='solid',padding=17)
        self.reciever_info_frame.pack(padx=5, pady=0,fill=tk.X)

        self.sniff_request_frame=ttk.Frame(self.sniff_share_frame)
        self.sniff_request_frame.pack(padx=5, pady=(25,15))

        self.file_handle_frame=ttk.Frame(self.sniff_share_frame,relief='solid',padding=17)
        self.file_handle_frame.pack(padx=0, pady=0,anchor='center')

        #create widgets for sender info frame
        self.sender_info_heading_label=ttk.Label(self.sender_info_frame,text="Sending Computer Information",font=(15,15),style='Grey.TLabel',justify='center')
        self.sender_info_heading_label.grid(row=0, column=0, padx=5, pady=15,columnspan=2, sticky='n')
        self.sender_ip_label=ttk.Label(self.sender_info_frame,text="Ip:",font=(20,20))
        self.sender_ip_label.grid(row=1, column=0, padx=5, pady=15, sticky='e')
        self.sender_ip_input=ttk.Entry(self.sender_info_frame,width=35)
        self.sender_ip_input.grid(row=1, column=1, padx=5, pady=15, sticky='w')
        self.sender_info_frame.grid_columnconfigure(0, weight=1)
        self.sender_info_frame.grid_columnconfigure(1, weight=1)

        #create widgets for reciever info frame
        # add columnconfigure to make all columns the same weight
        self.reciever_info_frame.columnconfigure(0, weight=26)
        self.reciever_info_frame.columnconfigure(1, weight=1)
        self.reciever_info_frame.columnconfigure(2, weight=1)
        self.reciever_info_frame.columnconfigure(3, weight=20)

        # create widgets for reciever info frame
        self.reciever_info_heading_label=ttk.Label(self.reciever_info_frame,text="My Information",font=(15,15),style='Grey.TLabel',justify='center')
        self.reciever_info_heading_label.grid(row=0, column=0, padx=5, pady=15, columnspan=4, sticky='n')

        self.reciever_name_label=ttk.Label(self.reciever_info_frame,text="Name:",font=(20,20))
        self.reciever_name_label.grid(row=1, column=0, padx=5, pady=15, sticky='e')
        self.reciever_name_input=ttk.Entry(self.reciever_info_frame,width=35)
        self.reciever_name_input.grid(row=1, column=1, padx=5, pady=15, sticky='w')

        self.reciever_reason_label=ttk.Label(self.reciever_info_frame,text="Reason:",font=(20,20))
        self.reciever_reason_label.grid(row=1, column=2, padx=(10,5), pady=15, sticky='e')
        self.reciever_reason_input=ttk.Entry(self.reciever_info_frame,width=60)
        self.reciever_reason_input.grid(row=1, column=3, padx=5, pady=15, sticky='w')

        self.my_info_explain_label=ttk.Label(self.reciever_info_frame,text="(This information will be displayed at the other computer)",font=(12,12),style='Grey.TLabel',anchor='center')
        self.my_info_explain_label.grid(row=2, column=0, padx=5, pady=(2,15), columnspan=4, sticky='n')

        #create widgets for button frame
        self.sniff_button = ttk.Button(self.sniff_request_frame, text="Send sniff share Request",width=30,image=self.run_img,compound="right",takefocus=False)
        self.sniff_button.grid(row=0, column=0, padx=5, pady=5)
        self.sniff_button.config(command=self.sniff_request)

        self.sniff_request_result_label=ttk.Label(self.sniff_request_frame,text="",font=(15,15),justify='center')
        self.sniff_request_result_label.grid(row=1, column=0, padx=5, pady=(15,0))

        #create widgets for file handle frame
        self.pcap_size_label=ttk.Label(self.file_handle_frame,text="Size:",font=(15,15))
        self.underline_font = tkFont.Font(self.pcap_size_label, self.pcap_size_label.cget("font"))
        self.underline_font.configure(underline = True)
        self.pcap_size_label.configure(font=self.underline_font)
        self.pcap_size_label.grid(row=0, column=0, padx=5, pady=15)

        self.pcap_size_value_label=ttk.Label(self.file_handle_frame,text="",font=(15,15))
        self.pcap_size_value_label.grid(row=0, column=1, padx=5, pady=15)

        self.pcap_pnum_label=ttk.Label(self.file_handle_frame,text="Number of Packets:",font=(15,15))
        self.pcap_pnum_label.grid(row=0, column=2, padx=5, pady=15)
        self.pcap_pnum_label.configure(font=self.underline_font)

        self.pcap_pnum_value_label=ttk.Label(self.file_handle_frame,text="",font=(15,15))
        self.pcap_pnum_value_label.grid(row=0, column=3, padx=5, pady=15)

        self.pcap_oldest_label=ttk.Label(self.file_handle_frame,text="Oldest Packet Time:",font=(15,15))
        self.pcap_oldest_label.grid(row=0, column=4, padx=5, pady=15)
        self.pcap_oldest_label.configure(font=self.underline_font)

        self.pcap_oldest_value_label=ttk.Label(self.file_handle_frame,text="",font=(15,15))
        self.pcap_oldest_value_label.grid(row=0, column=5, padx=5, pady=15)

        self.save_file_button=ttk.Button(self.file_handle_frame, text="Save as Pcap File",width=25,takefocus=False,state=tk.DISABLED)
        self.save_file_button.grid(row=1, column=0, padx=5, pady=5,columnspan=6)
        self.save_file_button.config(command=self.save_file)

        self.open_file_button=ttk.Button(self.file_handle_frame, text="Open File",width=25,takefocus=False,state=tk.DISABLED)
        self.open_file_button.grid(row=2, column=0, padx=5, pady=5,columnspan=6)
        self.open_file_button.config(command=self.open_file)

        self.wireshark_explain_label=ttk.Label(self.file_handle_frame,text="(Opens with outer installed programm if exists (usually it's wireshark))",font=(13,13))
        self.wireshark_explain_label.grid(row=3, column=0, padx=5, pady=5,columnspan=6)

        #create frames for remote control
        self.escape_frame=ttk.Frame(self.remote_control_frame)
        self.escape_frame.pack(padx=5,pady=10)

        self.controlled_info_frame=ttk.Frame(self.remote_control_frame,relief='solid',padding=12)
        self.controlled_info_frame.pack(padx=5, pady=0,fill=tk.X,anchor=tk.CENTER)

        self.controller_info_frame=ttk.Frame(self.remote_control_frame,relief='solid',padding=12)
        self.controller_info_frame.pack(padx=5, pady=0,fill=tk.X)

        self.quality_frame=ttk.Frame(self.remote_control_frame,relief='solid',padding=12)
        self.quality_frame.pack(padx=5, pady=0,fill=tk.X)

        self.rc_request_frame=ttk.Frame(self.remote_control_frame)
        self.rc_request_frame.pack(padx=5, pady=10)

        #create widgets for escape frame
        self.escape_label = ttk.Label(self.escape_frame,text="Press escape at any time to exit control! ",font=(25,25) ,image=self.escape_img,compound='right',style='Red.TLabel')
        self.escape_label.pack()

        #create widgets for controlled info frame
        self.controlled_info_heading_label=ttk.Label(self.controlled_info_frame,text="Controlled Computer Information",font=(15,15),style='Grey.TLabel',justify='center')
        self.controlled_info_heading_label.grid(row=0, column=0, padx=5, pady=10,columnspan=2, sticky='n')
        self.controlled_ip_label=ttk.Label(self.controlled_info_frame,text="Ip:",font=(20,20))
        self.controlled_ip_label.grid(row=1, column=0, padx=5, pady=10, sticky='e')
        self.controlled_ip_input=ttk.Entry(self.controlled_info_frame,width=35)
        self.controlled_ip_input.grid(row=1, column=1, padx=5, pady=10, sticky='w')
        self.controlled_info_frame.grid_columnconfigure(0, weight=1)
        self.controlled_info_frame.grid_columnconfigure(1, weight=1)

        #create widgets for controller info frame
        # add columnconfigure to make all columns the same weight
        self.controller_info_frame.columnconfigure(0, weight=26)
        self.controller_info_frame.columnconfigure(1, weight=1)
        self.controller_info_frame.columnconfigure(2, weight=1)
        self.controller_info_frame.columnconfigure(3, weight=20)

        # create widgets for controller info frame
        self.controller_info_heading_label=ttk.Label(self.controller_info_frame,text="My Information",font=(15,15),style='Grey.TLabel',justify='center')
        self.controller_info_heading_label.grid(row=0, column=0, padx=5, pady=10, columnspan=4, sticky='n')

        self.controller_name_label=ttk.Label(self.controller_info_frame,text="Name:",font=(20,20))
        self.controller_name_label.grid(row=1, column=0, padx=5, pady=10, sticky='e')
        self.controller_name_input=ttk.Entry(self.controller_info_frame,width=35)
        self.controller_name_input.grid(row=1, column=1, padx=5, pady=10, sticky='w')

        self.controller_reason_label=ttk.Label(self.controller_info_frame,text="Reason:",font=(20,20))
        self.controller_reason_label.grid(row=1, column=2, padx=(10,5), pady=10, sticky='e')
        self.controller_reason_input=ttk.Entry(self.controller_info_frame,width=60)
        self.controller_reason_input.grid(row=1, column=3, padx=5, pady=10, sticky='w')

        self.my_info_explain_label=ttk.Label(self.controller_info_frame,text="(This information will be displayed at the other computer)",font=(12,12),style='Grey.TLabel',anchor='center')
        self.my_info_explain_label.grid(row=2, column=0, padx=5, pady=(2,10), columnspan=4, sticky='n')

        #create widgets for quality frame
        self.quality_frame.columnconfigure(0, weight=5)
        self.quality_frame.columnconfigure(1, weight=1)
        self.quality_frame.columnconfigure(2, weight=5)

        self.quality_heading_label=ttk.Label(self.quality_frame,text="Quality",font=(15,15),style='Grey.TLabel',justify='center')
        self.quality_heading_label.grid(row=0, column=0, padx=5, pady=10,columnspan=3,sticky='n')

        self.twenty_label=ttk.Label(self.quality_frame,text="  20",font=(20,20))
        self.twenty_label.grid(row=1, column=0, padx=0, pady=10,sticky='e')

        self.scale_value=tk.StringVar()
        self.scale = ttk.Scale(self.quality_frame, from_=20, to=100, orient=tk.HORIZONTAL, length=200,command=self.update_scale_value)
        self.scale.set(60) # Set the default value
        self.scale.grid(row=1, column=1, padx=0, pady=10)

        self.one_hundred_label=ttk.Label(self.quality_frame,text="100",font=(20,20))
        self.one_hundred_label.grid(row=1, column=2, padx=0, pady=10,sticky='w')

        self.scale_value_label=ttk.Label(self.quality_frame,textvariable=self.scale_value,font=(20,20),relief="solid",padding=5)
        self.scale_value_label.grid(row=2, column=0, padx=10, pady=10,columnspan=3,sticky='s')

        self.quality_explain_label=ttk.Label(self.quality_frame,text="  (Higher quality means lower fps (frames per second))",font=(12,12),style='Grey.TLabel',justify='center')
        self.quality_explain_label.grid(row=3, column=0, padx=5, pady=(2,10),columnspan=3,sticky='s')

        #create widgets for button frame
        self.control_button = ttk.Button(self.rc_request_frame, text="Send Controll Request",width=25,image=self.run_img,compound="right",takefocus=False)
        self.control_button.grid(row=0, column=0, padx=5, pady=5)
        self.control_button.config(command=self.control_request)

        self.rc_request_result_label=ttk.Label(self.rc_request_frame,text="",font=(15,15),justify='center')
        self.rc_request_result_label.grid(row=1, column=0, padx=5, pady=15)

        #create widgets for attack detection window
        self.arp_headline=ttk.Label(self.attack_detection_frame,text="Arp Spoffing:",font=('Arial',20))
        self.arp_headline.grid(row=0, column=0, padx=5, pady=5)
        self.arp_log=tk.Text(self.attack_detection_frame,width=34,height=38)
        self.arp_log.grid(row=1, column=0, padx=5, pady=5)
        self.arp_scrollbar=tk.Scrollbar(self.attack_detection_frame,background='red',troughcolor='red', orient='vertical')
        self.arp_scrollbar.grid(row=1, column=1, padx=0, pady=5,sticky='ns')
        self.arp_log.config(yscrollcommand=self.arp_scrollbar.set)
        self.arp_scrollbar.config(command=self.arp_log.yview)
        self.exp_text="ARP spoofing consists of sending falsified arp messages in order to link the attacker's MAC address with the IP address of another device (usually the router). This allows the attacker to intercept and manipulate network traffic."
        self.line_width = 59
        self.lined_text ="\n".join(textwrap.wrap(self.exp_text, width=self.line_width))
        self.arp_explanation_label=ttk.Label(self.attack_detection_frame,text=self.lined_text,width=49,font=('Arial',8),borderwidth=5,relief='solid')
        self.arp_explanation_label.grid(row=2, column=0,columnspan=2, padx=5, pady=5)

        self.dos_headline=ttk.Label(self.attack_detection_frame,text="Dos Attack:",font=('Arial',20))
        self.dos_headline.grid(row=0, column=2, padx=5, pady=5)
        self.dos_log=tk.Text(self.attack_detection_frame,width=34,height=38)
        self.dos_log.grid(row=1, column=2, padx=5, pady=5)
        self.dos_scrollbar=tk.Scrollbar(self.attack_detection_frame,background='red',troughcolor='red', orient='vertical')
        self.dos_scrollbar.grid(row=1, column=3, padx=0, pady=5,sticky='ns')
        self.dos_log.config(yscrollcommand=self.dos_scrollbar.set)
        self.dos_scrollbar.config(command=self.dos_log.yview)
        self.line_width = 59
        self.exp_text="A Denial-of-Service attack (DOS) aims to disrupt the availability of a network, website, or other online service by overwhelming it with traffic or other requests, usually using TCP, UPD or ICMP packets"
        self.lined_text ="\n".join(textwrap.wrap(self.exp_text, width=self.line_width))
        self.dos_explanation_label=ttk.Label(self.attack_detection_frame,text=self.lined_text,width=49,font=('Arial',8),borderwidth=5,relief='solid')
        self.dos_explanation_label.grid(row=2, column=2,columnspan=2, padx=5, pady=5)

        self.brodcast_headline=ttk.Label(self.attack_detection_frame,text="Brodcast Storm:",font=('Arial',20))
        self.brodcast_headline.grid(row=0, column=4, padx=5, pady=5)
        self.brodcast_log=tk.Text(self.attack_detection_frame,width=34,height=38)
        self.brodcast_log.grid(row=1, column=4, padx=5, pady=5)
        self.brodcast_scrollbar=tk.Scrollbar(self.attack_detection_frame,background='red',troughcolor='red', orient='vertical')
        self.brodcast_scrollbar.grid(row=1, column=5, padx=0, pady=5,sticky='ns')
        self.brodcast_log.config(yscrollcommand=self.brodcast_scrollbar.set)
        self.brodcast_scrollbar.config(command=self.brodcast_log.yview)
        self.exp_text="A broadcast storm is when a broadcast or multicast packet is continuously transmitted and retransmitted by every device on a network, creating a loop of excessive traffic that can significantly slow down or even crash the network."
        self.line_width = 59
        self.lined_text ="\n".join(textwrap.wrap(self.exp_text, width=self.line_width))
        self.brodcast_explanation_label=ttk.Label(self.attack_detection_frame,text=self.lined_text,width=49,font=('Arial',8),borderwidth=5,relief='solid')
        self.brodcast_explanation_label.grid(row=2, column=4,columnspan=2, padx=5, pady=5)

        self.ps_headline=ttk.Label(self.attack_detection_frame,text="Port Scanning:",font=('Arial',20))
        self.ps_headline.grid(row=0, column=6, padx=5, pady=5)
        self.ps_log=tk.Text(self.attack_detection_frame,width=34,height=38)
        self.ps_log.grid(row=1, column=6, padx=5, pady=5)
        self.ps_scrollbar=tk.Scrollbar(self.attack_detection_frame,background='red',troughcolor='red', orient='vertical')
        self.ps_scrollbar.grid(row=1, column=7, padx=0, pady=5,sticky='ns')
        self.ps_log.config(yscrollcommand=self.ps_scrollbar.set)
        self.ps_scrollbar.config(command=self.ps_log.yview)
        self.exp_text="Port scanning is used to discover which network ports are open on a target computer or device. Hackers may use port scanning to identify open ports that could be used as entry points for a cyber attack."
        self.line_width = 59
        self.lined_text ="\n".join(textwrap.wrap(self.exp_text, width=self.line_width))
        self.ps_explanation_label=ttk.Label(self.attack_detection_frame,text=self.lined_text,width=49,font=('Arial',8),borderwidth=5,relief='solid')
        self.ps_explanation_label.grid(row=2, column=6,columnspan=2, padx=5, pady=5)

        self.malware_headline=ttk.Label(self.attack_detection_frame,text="Malware Signatures:",font=('Arial',20))
        self.malware_headline.grid(row=0, column=8, padx=5, pady=5)
        self.malware_log=tk.Text(self.attack_detection_frame,width=34,height=38)
        self.malware_log.grid(row=1, column=8, padx=5, pady=5)
        self.malware_scrollbar=tk.Scrollbar(self.attack_detection_frame,background='red',troughcolor='red', orient='vertical')
        self.malware_scrollbar.grid(row=1, column=9, padx=0, pady=5,sticky='ns')
        self.malware_log.config(yscrollcommand=self.malware_scrollbar.set)
        self.malware_scrollbar.config(command=self.malware_log.yview)
        self.exp_text="Malware signatures are unique identifiers that can be used to identify a particular piece of malware, based on its code or behavior. This searches for malware on network packets."
        self.line_width = 58
        self.lined_text ="\n".join(textwrap.wrap(self.exp_text, width=self.line_width))
        self.malware_explanation_label=ttk.Label(self.attack_detection_frame,text=self.lined_text,width=48,font=('Arial',8),borderwidth=5,relief='solid')
        self.malware_explanation_label.grid(row=2, column=8,columnspan=2, padx=5, pady=5)

        self.update_attack_logs()

        #create frames for network tester
        self.network_tester=traffic_testing.traffic_tester()

        self.left_tests_frame=ttk.Frame(self.network_testing_frame,style='Custom.TFrame')
        self.left_tests_frame.pack(side=tk.LEFT,padx=5, pady=5)

        self.middle_tests_frame=ttk.Frame(self.network_testing_frame,style='Custom.TFrame')
        self.middle_tests_frame.pack(side=tk.LEFT,padx=5, pady=5)

        self.right_tests_frame=ttk.Frame(self.network_testing_frame,style='Custom.TFrame')
        self.right_tests_frame.pack(side=tk.RIGHT,padx=5, pady=5)

        #create widgets for left frame
        self.upload_label = tk.Label(self.left_tests_frame,text="-",font=(40,40) ,image=self.upload_img,compound='center',border=0,borderwidth=0)
        self.upload_label.grid(row=0, column=0, padx=30, pady=6)

        self.ping_label = tk.Label(self.left_tests_frame,text="-",font=(40,40), image=self.ping_img,compound='center',border=0,borderwidth=0)
        self.ping_label.grid(row=1, column=0, padx=30, pady=6)

        #create widgets for midlle frame
        self.download_label=tk.Label(self.middle_tests_frame,text="-",font=(50,50), image=self.download_img,compound='center',border=0,borderwidth=0)
        self.download_label.grid(row=0, column=0, padx=30, pady=40,sticky='n')

        self.run_network_test_button=ttk.Button(self.middle_tests_frame,text="Run Test",takefocus=False,padding=(100,20),command=self.start_network_test)
        self.run_network_test_button.grid(row=1, column=0, padx=30, pady=6)

        self.loading_animation_canvas = tk.Canvas(self.middle_tests_frame, width=300, height=300,background='gray35',border=0,borderwidth=0,relief='flat', highlightthickness=0, highlightbackground='gray35')
        self.loading_animation_canvas.grid(row=2, column=0, padx=125, pady=6,sticky='e')
        self.frames = [ImageTk.PhotoImage(Image.open(f'loading_gif\\frame({i}).gif').resize((100,100)))for i in range(1, 30)]

        #create widgets for right frame
        self.bandwidth_label = tk.Label(self.right_tests_frame,text="-",font=(40,40), image=self.bandwidth_img,compound='center',border=0,borderwidth=0)
        self.bandwidth_label.grid(row=0, column=0, padx=30, pady=6)

        self.latency_label = tk.Label(self.right_tests_frame,text="-",font=(40,40), image=self.latency_img,compound='center',border=0,borderwidth=0)
        self.latency_label.grid(row=1, column=0, padx=30, pady=6)

        #create frames for password checker
        self.password_frame=ttk.Frame(self.password_testing_frame)
        self.password_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.tests_frame=ttk.Frame(self.password_testing_frame,borderwidth=6,border=6,relief="groove",padding=5)
        self.tests_frame.pack(fill=tk.X, padx=5, pady=5)

        self.generate_frame=ttk.Frame(self.password_testing_frame)
        self.generate_frame.pack(side=tk.BOTTOM,fill=tk.X, padx=5, pady=5)

        # create widgets for the password frame
        self.pass_tester=password_tester()

        self.your_pass_label=ttk.Label(self.password_frame,text="Your Password:",font=(15,15))
        self.your_pass_label.grid(row=0, column=0, padx=8, pady=5)

        self.pass_label=tk.Label(self.password_frame,text=self.pass_tester.password,font=(15,15))
        self.pass_label.grid(row=0, column=1, padx=8, pady=5)
        self.update_password()

        self.pass_option=tk.BooleanVar(value=False)

        ttk.Style().configure('TCheckbutton', font=("arial", 9))
        self.enter_pass_option=ttk.Checkbutton(self.password_frame,variable=self.pass_option,text="Wrong / want to test another one?",padding=(0, 0, 0, 0),takefocus=False)
        self.enter_pass_option.grid(row=0, column=2, padx=8, pady=5)

        self.pass_option.trace("w", self.on_pass_option_changed)

        self.password_entry=ttk.Entry(self.password_frame,width=35,state="disabled")
        self.password_entry.grid(row=0, column=3, padx=8, pady=5)

        self.no_pass=False
        self.run_pass_test_button=ttk.Button(self.password_frame,text="Run Test",width=12,image=self.run_img,compound="right",takefocus=False,command=self.run_pass_test,state=tk.DISABLED)
        self.run_pass_test_button.grid(row=0, column=4, padx=8, pady=5)

        self.password_frame.place(relx=0.5,rely=0.05,anchor=tk.CENTER)

        #create widgets for the tests frame

        self.tests_heading_label=ttk.Label(self.tests_frame,text="Tests:",font=('times new roman',20))
        self.underline_font = tkFont.Font(self.tests_heading_label, self.tests_heading_label.cget("font"))
        self.underline_font.configure(underline = True)
        self.tests_heading_label.configure(font=self.underline_font)
        self.tests_heading_label.grid(row=0,column=0,padx=5,pady=10,sticky="w")

        self.test1_label=ttk.Label(self.tests_frame,text="Contains at least 12 characters: ",image=self.question_img,compound="right",font=(11,11,'bold'))
        self.important1_label=ttk.Label(self.tests_frame,text="(critical)",style="Red.TLabel",font=(9,9))
        self.test1_label.grid(row=1,column=0,padx=5,pady=8,sticky="w")
        self.important1_label.grid(row=1,column=1,padx=(0,50),pady=8)

        self.test2_label=ttk.Label(self.tests_frame,text="Contains at least one lower character: ",image=self.question_img,compound="right",font=(11,11,'bold'))
        self.important2_label=ttk.Label(self.tests_frame,text="(critical)",style="Red.TLabel",font=(9,9))
        self.test2_label.grid(row=1,column=2,padx=5,pady=8,sticky="w")
        self.important2_label.grid(row=1,column=3,padx=5,pady=8)

        self.test3_label=ttk.Label(self.tests_frame,text="Contains at least one upper character: ",image=self.question_img,compound="right",font=(11,11,'bold'))
        self.important3_label=ttk.Label(self.tests_frame,text="(critical)",style="Red.TLabel",font=(9,9))
        self.test3_label.grid(row=2,column=0,padx=5,pady=8,sticky="w")
        self.important3_label.grid(row=2,column=1,padx=(0,50),pady=8)

        self.test4_label=ttk.Label(self.tests_frame,text="Contains at least one number: ",image=self.question_img,compound="right",font=(11,11,'bold'))
        self.important4_label=ttk.Label(self.tests_frame,text="(critical)",style="Red.TLabel",font=(9,9))
        self.test4_label.grid(row=2,column=2,padx=5,pady=8,sticky="w")
        self.important4_label.grid(row=2,column=3,padx=5,pady=8)

        self.test5_label=ttk.Label(self.tests_frame,text="Contains at least one special characters: ",image=self.question_img,compound="right",font=(11,11,'bold'))
        self.important5_label=ttk.Label(self.tests_frame,text="(critical)",style="Red.TLabel",font=(9,9))
        self.test5_label.grid(row=3,column=0,padx=5,pady=8,sticky="w")
        self.important5_label.grid(row=3,column=1,padx=(0,50),pady=8)

        self.test6_label=ttk.Label(self.tests_frame,text="Doesn't contain any weak substirngs in it (password,123456,qwerty,admin,letmein): ",image=self.question_img,compound="right",font=(11,11,'bold'))
        self.important6_label=ttk.Label(self.tests_frame,text="(important)",style="Orange.TLabel",font=(9,9))
        self.test6_label.grid(row=3,column=2,padx=5,pady=8,sticky="w")
        self.important6_label.grid(row=3,column=3,padx=5,pady=8)

        self.test7_label=ttk.Label(self.tests_frame,text="Doesnt't contain three or more consecutive identical characters: ",image=self.question_img,compound="right",font=(11,11,'bold'))
        self.important7_label=ttk.Label(self.tests_frame,text="(important)",style="Orange.TLabel",font=(9,9))
        self.test7_label.grid(row=4,column=0,padx=5,pady=8,sticky="w")
        self.important7_label.grid(row=4,column=1,padx=(0,50),pady=8)

        self.test8_label=ttk.Label(self.tests_frame,text="Doesn't contain any three sequential characters: ",image=self.question_img,compound="right",font=(11,11,'bold'))
        self.important8_label=ttk.Label(self.tests_frame,text="(important)",style="Orange.TLabel",font=(9,9))
        self.test8_label.grid(row=4,column=2,padx=5,pady=8,sticky="w")
        self.important8_label.grid(row=4,column=3,padx=5,pady=8)

        self.test9_label=ttk.Label(self.tests_frame,text="Doesn't contain any of the keyboard patterns (qwert,asdfg,zxcvb,poiuy,lkjhgf,mnbvc): ",image=self.question_img,compound="right",font=(11,11,'bold'))
        self.important9_label=ttk.Label(self.tests_frame,text="(recommended)",style="Yellow.TLabel",font=(9,9))
        self.test9_label.grid(row=5,column=0,padx=5,pady=8,sticky="w")
        self.important9_label.grid(row=5,column=1,padx=(0,50),pady=8)

        self.test10_label=ttk.Label(self.tests_frame,text="Doesn't contain a date: ",image=self.question_img,compound="right",font=(11,11,'bold'))
        self.important10_label=ttk.Label(self.tests_frame,text="(recommended)",style="Yellow.TLabel",font=(9,9))
        self.test10_label.grid(row=5,column=2,padx=5,pady=8,sticky="w")
        self.important10_label.grid(row=5,column=3,padx=5,pady=8)

        self.test11_label=ttk.Label(self.tests_frame,text="Wasn't found in a weak passwords list: ",image=self.question_img,compound="right",font=(11,11,'bold'))
        self.important11_label=ttk.Label(self.tests_frame,text="(important)",style="Orange.TLabel",font=(9,9))
        self.test11_label.grid(row=6,column=0,padx=5,pady=8,sticky="w")
        self.important11_label.grid(row=6,column=1,padx=(0,50),pady=8)

        self.test12_label=ttk.Label(self.tests_frame,text="Doesnt contain any dictionary words: ",image=self.question_img,compound="right",font=(11,11,'bold'))
        self.important12_label=ttk.Label(self.tests_frame,text="(recommended)",style="Yellow.TLabel",font=(9,9))
        self.test12_label.grid(row=6,column=2,padx=5,pady=8,sticky="w")
        self.important12_label.grid(row=6,column=3,padx=5,pady=8)

        self.test_label_list=[self.test1_label,self.test2_label,self.test3_label,self.test4_label,self.test5_label,self.test6_label,self.test7_label,self.test8_label,self.test9_label,self.test10_label,self.test11_label,self.test12_label]

        self.pass_results_frame=ttk.Frame(self.tests_frame)
        self.pass_results_frame.grid(row=7,column=0,columnspan=4,padx=0,pady=(20,5),sticky='ew')

        self.separator = ttk.Separator(self.pass_results_frame, orient='horizontal')
        self.separator.pack(fill=tk.X,padx=0,pady=5)

        self.overall_results_label=ttk.Label(self.pass_results_frame,text="Overall, the password passed - out of 12 tests:",font=(13,13,'bold'))
        self.overall_results_label.pack(padx=5,pady=5)

        self.critical_results_label=ttk.Label(self.pass_results_frame,text="-/5 critical tests",style="Red.TLabel",font=(13,13,'bold'))
        self.critical_results_label.pack(padx=5,pady=5)

        self.important_results_label=ttk.Label(self.pass_results_frame,text="-/4 important tests",style="Orange.TLabel",font=(13,13,'bold'))
        self.important_results_label.pack(padx=5,pady=5)

        self.recommended_results_label=ttk.Label(self.pass_results_frame,text="-/3 recommended tests",style="Yellow.TLabel",font=(13,13,'bold'))
        self.recommended_results_label.pack(padx=5,pady=5)

        self.changing_recommendation_label=ttk.Label(self.pass_results_frame,text="   ",font=(13,13,'bold'))
        self.changing_recommendation_label.pack(padx=5,pady=5)

        self.tests_frame.place(relx=0.5,rely=0.45,anchor=tk.CENTER)

        #create widgets for the generate frame
        self.generate_heading_label=ttk.Label(self.generate_frame,text="Strong Password Generation",font=('times new roman',20),anchor=tk.CENTER)
        self.generate_heading_label.configure(font=self.underline_font)
        self.generate_heading_label.grid(row=0,columnspan=3,padx=8,pady=(5,30))

        self.generated_password_label=ttk.Label(self.generate_frame,text=self.pass_tester.generate_password(),font=(20,20),background="aquamarine")
        self.generated_password_label.configure(border=10,borderwidth=10, relief="solid")
        self.generated_password_label.grid(row=1,column=0,padx=8,pady=5)

        self.generete_button=ttk.Button(self.generate_frame,text="Generate Password",image=self.run_img,compound="right",takefocus=False,command=self.generate_password)
        self.generete_button.grid(row=1,column=1,padx=8,pady=5)

        self.copy_generated_password_button=ttk.Button(self.generate_frame,text="Copy Password",takefocus=False,command=self.copy_password)
        self.copy_generated_password_button.grid(row=1,column=2,padx=8,pady=5)

        self.generate_frame.place(relx=0.5,rely=0.89,anchor=tk.CENTER)

        # create frames for network scanner
        self.scan_frame = ttk.Frame(self.network_scanner_frame)
        self.scan_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.progress_bar_frame = ttk.Frame(self.network_scanner_frame)
        self.progress_bar_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5)

        self.devices_frame = ttk.Frame(self.network_scanner_frame)
        self.devices_frame.pack(side=tk.TOP, fill=tk.BOTH, padx=5, pady=5, expand=True)

        # create widgets for the scan frame
        self.scan_button = ttk.Button(self.scan_frame, text="Scan",width=8,image=self.run_img,compound="right",takefocus=False)
        self.scan_button.grid(row=0, column=0, padx=5, pady=5)
        self.scan_button.config(command=self.start_scan)

        self.stop_button = ttk.Button(self.scan_frame, text="Stop", command=self.stop_scan,width=8,image=self.stop_img,compound="right",takefocus=False)
        self.stop_button.grid(row=0, column=1, padx=5, pady=5)
        self.stop_button.config(state=tk.DISABLED)

        self.scan_range_options = ttk.Combobox(self.scan_frame, values=["Manual", "Full Network"], state="readonly",style="TCombobox",takefocus=False)
        self.scan_range_options.current(1)
        self.scan_range_options.grid(row=0, column=2, padx=5, pady=5)

        self.ip_input = ttk.Entry(self.scan_frame, width=110)
        self.ip_input.insert(0, "Example: 192.168.1.1-255")
        self.ip_input.grid(row=0, column=3, padx=5, pady=5)
        self.ip_input.config(state=tk.DISABLED)

        self.names_button = ttk.Button(self.scan_frame, text="Resolve Names",command=self.resolve_all_names,takefocus=False)
        self.names_button.grid(row=0, column=4, padx=5, pady=5)
        self.names_button.config(state=tk.DISABLED)

        self.ps_button = ttk.Button(self.scan_frame, text="Scan Popular Ports",command=self.port_scan_all_devices,takefocus=False)
        self.ps_button.grid(row=0, column=5, padx=5, pady=5)
        self.ps_button.config(state=tk.DISABLED)

        # create widgets for devices frame
        self.headings = ["name", "ip", "mac", "mac vendor", 'Data Transfered With Me']
        self.selected_table_row = 0
        self.device_table = ttk.Treeview(self.devices_frame, columns=self.headings, height=31)
        self.device_table.heading("#0", text="status", anchor='center')
        self.device_table.column("#0", width=50,minwidth=50, stretch=False)

        for i,header in enumerate(self.headings,start=1):   
            self.device_table.heading(f'#{i}', text=header, anchor=tk.W)
            self.device_table.column(header, width=200, minwidth=150, stretch=True)

        self.device_table.bind("<ButtonRelease-1>", lambda event: self.get_selected_table_row(event))

        self.device_table.pack(side=tk.LEFT, fill=tk.BOTH, padx=5, pady=5, expand=True)

        self.scrollbar = ttk.Scrollbar(self.devices_frame, orient="vertical", command=self.device_table.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.device_table.config(yscrollcommand=self.scrollbar.set)

        ttk.Style().configure('my.Horizontal.TProgressbar', barcolor='#0f0', thickness=1)
        self.progress_bar = ttk.Progressbar(self.progress_bar_frame, orient=tk.HORIZONTAL, length=2000, mode='determinate',style='my.Horizontal.TProgressbar')
        self.progress_bar.pack(padx=5, pady=5)

        self.scan_range_options.bind("<<ComboboxSelected>>", lambda event: self.toggle_ip_input(self.scan_range_options, self.ip_input))

        # add widgets to devices frame
        self.device_table.bind("<ButtonRelease-3>", lambda event: self.show_popup_menu(event))

        # start main loop
        self.root.mainloop()

        #Close every running opperation
        self.attack_detecter.scanning=False

        self.net_scanner.stop_flag=True

        self.net_scanner.close_all_tools()

    # function to update device table
    def update_device_table(self):
        # enable Power Status button if devices are not all powered and button is disabled
        if not self.net_scanner.is_ps_all and tk.DISABLED in self.ps_button.state() and len(self.device_table.get_children()) > 0:
            self.ps_button.config(state=tk.NORMAL)
        
        # enable Resolve Names button if names are not resolving and button is disabled
        if not self.net_scanner.is_resolving_names and tk.DISABLED in self.names_button.state() and len(self.device_table.get_children()) > 0:
            self.names_button.config(state=tk.NORMAL)
        
        # check if network scanning has stopped
        if self.scanning and not self.net_scanner.scanning:
            # enable IP input field if scanning range is manual
            if self.scan_range_options.get() == "Manual":
                self.ip_input.config(state=tk.NORMAL)
            
            # reset progress bar, disable Stop button, and set scanning flag to False
            self.progress_bar["value"] = 0
            self.stop_button.config(state=tk.DISABLED)
            self.scanning = False
            
            # enable Scan button, scanning range options, and set scanning range options to readonly
            self.scan_button.config(state=tk.NORMAL)
            self.scan_range_options.config(state=tk.NORMAL)
            self.scan_range_options.config(state="readonly")
            
            # clear device table and insert device data
            self.device_table.delete(*self.device_table.get_children())
            devices = self.net_scanner.devices
            for i, device in enumerate(devices):
                # set device icon based on device status
                if device.is_alive:
                    image = self.device_img
                else:
                    image = self.dead_device_img
                
                added = ''
                # add label to device name if it's the user's device or the router
                if device.ip == self.my_ip:
                    added = ' (You)'
                    image = self.me_img
                elif device.ip == self.router_ip:
                    added = ' (Default Gateway)'
                    image = self.router_img

                # insert device data into table
                device_row = self.device_table.insert("", "end", str(i), text='', image=image, values=[device.name+added, device.ip, device.mac, device.mac_vendor, f'{device.data_transfered} Bytes'])
                self.device_table.insert(device_row, "end", device_row+"_0", values=[" Open Ports:"]+device.get_port_desc())
            
            # enable Network Test button after scan is complete
            self.run_network_test_button.config(state=tk.NORMAL)
        else:
            try:
                # update device data in table for each device
                for i, item_id in enumerate(self.device_table.get_children()):
                    device = self.net_scanner.devices[i]
                    self.net_scanner.update_data_transfered()
                    
                    added = ''
                    # set device icon based on device status
                    if device.is_alive:
                        image = self.device_img
                    else:
                        image = self.dead_device_img
                    
                    added = ''
                    # add label to device name if it's the user's device or the router
                    if device.ip == self.my_ip:
                        added = ' (You)'
                        image = self.me_img
                    elif device.ip == self.router_ip:
                        added = ' (Default Gateway)'
                        image = self.router_img

                    # update device data in table
                    self.device_table.item(item_id, text='', image=image, values=[device.name+added, device.ip, device.mac, device.mac_vendor, f'{device.data_transfered} Bytes'])
                    if device.currently_port_scanning:
                        #Add port scaning in progress image
                        self.device_table.item(item_id+"_0",text='',image=self.ps_load_img,values=[" Open Ports:"]+device.get_port_desc())
                    else:
                        self.device_table.item(item_id+"_0",image=tk.PhotoImage(),values=[" Open Ports:"]+device.get_port_desc())
            except Exception as e:
                print(e)

        self.root.update()

        #Run this function again in 700 ms (0.7 seconds)
        self.root.after(700,self.update_device_table)

    def update_progress_bar(self):
        #Function to update the progress bar while scanning the network
        if not self.scanning:
            self.progress_bar["value"]=0
        
        if self.progress_bar["value"]>=len(self.net_scanner.ips_to_scan) and self.progress_bar["value"]+10<len(self.net_scanner.ips_to_scan)+140:
            self.progress_bar["value"]+=10
            self.root.after(1000,self.update_progress_bar)
        elif self.progress_bar["value"]<len(self.net_scanner.ips_to_scan):
            self.progress_bar["value"]=self.net_scanner.finished_scanning_count
            self.root.after(100,self.update_progress_bar)

    # function to handle start scanning button press
    def start_scan(self):
        # if the scanning range option is set to manual
        if self.scan_range_options.get() == "Manual":
            # parse the IP input entered by the user
            succeded=self.net_scanner.parse_ip_input(self.ip_input.get())
            # if the parsing failed, show an error message and return
            if not succeded:
                messagebox.showerror("Error", "Invalid Ip range, Check Input!")
                return
        # otherwise, set the IP range to the network IP range
        else:
            self.net_scanner.ips_to_scan=get_net_info.get_ip_info()[3]

        # set scanning flag to true
        self.net_scanner.scanning=True
        self.scanning = True
        # start a new thread to scan the network
        self.scanning_thr=threading.Thread(target=self.net_scanner.scan_network)
        self.scanning_thr.start()

        # set the maximum value of the progress bar
        self.progress_bar["maximum"]=len(self.net_scanner.ips_to_scan)+140

        # enable the stop button and disable the network test and scan buttons
        self.stop_button.config(state=tk.NORMAL)
        self.run_network_test_button.config(state=tk.DISABLED)
        # update the progress bar
        self.update_progress_bar()
        # if the device table is empty, update it
        if len(self.device_table.get_children())==0:
            self.update_device_table()
        # disable the scan button and scan range option
        self.scan_button.config(state=tk.DISABLED)
        self.scan_range_options.config(state=tk.DISABLED)
        # disable the IP input
        self.ip_input.config(state=tk.DISABLED)

    # function to handle stop scanning button press
    def stop_scan(self):
        # disable the stop button and set the stop flag
        self.stop_button.config(state=tk.DISABLED)
        self.net_scanner.stop_flag=True

    # function to get selected row in device table
    def get_selected_table_row(self,event):
        # get the ID of the selected row in the table
        self.selected_table_row = self.device_table.identify_row(event.y).removesuffix("_0")

    def toggle_ip_input(self,scan_range_options, ip_input):
        # if the scanning range option is set to manual, enable the IP input
        if scan_range_options.get() == "Manual":
            ip_input.config(state=tk.NORMAL)
        # otherwise, disable the IP input
        else:
            ip_input.config(state=tk.DISABLED)

    #Function to display the right click menu
    def show_popup_menu(self,event):
        # Get the ID of the row that was clicked on
        row_id = self.device_table.identify_row(event.y).removesuffix("_0")
        
        # If the row ID is invalid, return early
        if not row_id:
            return
        
        # Convert the row ID to a numeric value
        row_num=int(row_id)
        if row_num != "":
            # Create a popup menu object
            popup_menu = tk.Menu(self.root, tearoff=0)
            
            # Add scan options to the popup menu if the device is currently alive
            if self.net_scanner.devices[row_num].is_alive:
                # Add a command to try to resolve the name of the device
                popup_menu.add_command(label="Try to resolve name",command=lambda:self.try_to_resolve_name(row_num))
                
                # If the device is not currently being port scanned, add port scanning options
                if not self.net_scanner.devices[row_num].currently_port_scanning:
                    # Add a command to scan popular ports
                    popup_menu.add_command(label="Scan Popular Ports",command=lambda:self.popular_port_scan(row_num))
                    # Add a command to perform an intense port scan
                    popup_menu.add_command(label="Intense Port Scan",command=lambda:self.create_port_scan_popup(row_num))
                # Otherwise, disable the port scanning options
                else:
                    popup_menu.add_command(label="Scan Popular Ports",command=lambda:self.popular_port_scan(row_num),state=tk.DISABLED)
                    popup_menu.add_command(label="Intense Port Scan",command=lambda:self.create_port_scan_popup(row_num),state=tk.DISABLED)
            # If the device is not alive, disable all scan options
            else:
                popup_menu.add_command(label="Try to resolve name",command=lambda:self.try_to_resolve_name(row_num),state=tk.DISABLED)
                popup_menu.add_command(label="Scan Popular Ports",command=lambda:self.popular_port_scan(row_num),state=tk.DISABLED)
                popup_menu.add_command(label="Intense Port Scan",command=lambda:self.create_port_scan_popup(row_num),state=tk.DISABLED)

        # Add a separator between the scan options and the CMD tools
        popup_menu.add_separator()
        
        # Create a submenu for CMD tools
        cmd_menu=tk.Menu(popup_menu,tearoff=False)
        popup_menu.add_cascade(label="CMD tools", menu=cmd_menu)
        
        # Add items to the CMD tools submenu
        ip=self.device_table.item(row_id, "values")[1]
        cmd_menu.add_command(label="ping",command=lambda:threading.Thread(target=lambda:os.system(f'start cmd /k "mode con: cols=300 lines=1500 && ping {ip}"')).start())
        cmd_menu.add_command(label="tracert",command=lambda:threading.Thread(target=lambda:os.system(f'start cmd /k "mode con: cols=300 lines=1500 && tracert {ip}"')).start())
        cmd_menu.add_command(label="arp -a",command=lambda:threading.Thread(target=lambda:os.system(f'start cmd /k "mode con: cols=300 lines=1500 && arp -a"')).start())
        cmd_menu.add_command(label="netstat -a",command=lambda:threading.Thread(target=lambda:os.system(f'start cmd /k "mode con: cols=300 lines=1500 && netstat -a"')).start())
        cmd_menu.add_command(label="ipconfig",command=lambda:threading.Thread(target=lambda:os.system(f'start cmd /k "mode con: cols=300 lines=1500 && ipconfig"')).start())
        cmd_menu.add_command(label="nbtstat",command=lambda:threading.Thread(target=lambda:os.system(f'start cmd /k "mode con: cols=300 lines=1500 && nbtstat -a {ip}"')).start())

        # Add a separator between the CMD tools and the copy options
        popup_menu.add_separator()
        #add all copy options
        popup_menu.add_command(label="Copy IP Address", command=lambda: self.copy_to_clipboard(self.device_table.item(row_id, "values")[1]))
        popup_menu.add_command(label="Copy MAC Address", command=lambda: self.copy_to_clipboard(self.device_table.item(row_id, "values")[2]))
        popup_menu.add_command(label="Copy MAC Vendor", command=lambda: self.copy_to_clipboard(self.device_table.item(row_id, "values")[3]))
        popup_menu.add_command(label="Copy Data Transfered", command=lambda: self.copy_to_clipboard(self.device_table.item(row_id, "values")[4]))
        popup_menu.add_command(label="Copy Open Ports", command=lambda: self.copy_to_clipboard(' '.join(self.net_scanner.devices[row_num].get_port_desc())))

        #Add the shutdown and restart options to the menu
        popup_menu.add_separator()
        popup_menu.add_command(label="Shutdown", command=lambda: self.shutdown_restart_window(self.device_table.item(row_id, "values")[1],'Shutdown'))
        popup_menu.add_command(label="Restart", command=lambda: self.shutdown_restart_window(self.device_table.item(row_id, "values")[1],'Restart'))

        #Display the menu where the right click accured
        popup_menu.post(event.x_root, event.y_root)

    def run_shutdown_restart_action(self,popup,ip,action,run_button,wait_time_entry,message_entry,result_value_label):
        #Function to execute the shutdown and menu functions according to the action selected
        run_button.config(state=tk.DISABLED)

        #Check if the user entered a valid time
        if not re.match(r'^\d+$',wait_time_entry.get()) or int(wait_time_entry.get())>315360000:
            if not re.match(r'^\d+$',wait_time_entry.get()) :
                messagebox.showerror("Error", "Invalid Wait Time Input! Check It and try again!")
            else:
                messagebox.showerror("Error", "Wait time has to be smaller than 315360000 seconds (ten years)")
            #Get all the current values and create a new window
            message=message_entry.get("1.0", "end-1c")
            time=wait_time_entry.get()
            status=result_value_label.cget("text")
            popup.destroy()
            self.shutdown_restart_window(ip,action,message,time,status)
            return
        
        #create a list to hold the result of the action
        output=[]

        #Exsecute the selected function
        if action=="Shutdown":
            action_thr=threading.Thread(target=lambda:shutdown_restart.shutdown(output,ip,wait_time_entry.get(),message_entry.get("1.0", "end-1c")))
        if action=="Restart":
            action_thr=threading.Thread(target=lambda:shutdown_restart.restart(output,ip,wait_time_entry.get(),message_entry.get("1.0", "end-1c")))
        
        action_thr.start()

        #start waiting for the result of the action
        self.wait_for_shutdown_restart_result(popup,output,result_value_label,run_button)

    def wait_for_shutdown_restart_result(self,popup,output,result_value_label,run_button):
        #A function that waits for the results of the shutdown or restart function and updates it when the action has finished
        #If there is no output yet, return to waiting
        if len(output)==0:
            popup.after(50,lambda: self.wait_for_shutdown_restart_result(popup,output,result_value_label,run_button))
            return
                
        #Devide the results to lines
        self.line_width = 50
        splited_text ="\n".join(textwrap.wrap(output[0], width=self.line_width))
        #Color the result area
        if "Succes!" in output[0]:
            result_value_label.config(text=splited_text,background="green")
        else:
            result_value_label.config(text=splited_text,background="red")

        #Reactivate the option to run the action   
        run_button.config(state=tk.NORMAL)

    def shutdown_restart_window(self,ip,action,message='',time='',status='\n\n'):
        #Create the window for the shutdown and restart actions
        # Create a new popup window
        popup = tk.Toplevel(self.root)
        popup.title(f"{action} {ip}")
        popup.resizable(False,False)

        # Add a label and entry for wait time
        wait_time_label = ttk.Label(popup, text="Wait Time (seconds):")
        wait_time_label.pack() 
        wait_time_entry = ttk.Entry(popup,width=17)
        wait_time_entry.insert(0,time)
        wait_time_entry.pack()

        # Add a label and entry for message
        message_label = ttk.Label(popup, text="Message:")
        message_label.pack()
        message_entry = tk.Text(popup, width=30,height=5)
        message_entry.insert('1.0',message)
        message_entry.pack(padx=10)

        # Add buttons for run and cancel
        run_button = ttk.Button(popup, text="Run",width=14, command=lambda:self.run_shutdown_restart_action(popup,ip,action,run_button,wait_time_entry,message_entry,result_value_label))
        run_button.pack(pady=5)

        # Add a label for result
        result_label = ttk.Label(popup, text="Result:")
        result_label.pack()
        result_value_label = tk.Label(popup,justify=tk.LEFT,text=status,anchor=tk.W)
        result_value_label.pack(anchor='w')

        popup.mainloop()

    def copy_to_clipboard(self,value):
        #A Function that copies a value to the clipboard
        self.root.clipboard_clear()
        self.root.clipboard_append(value)

    def try_to_resolve_name(self,device_pos):
        #A Function that tries to resolve the name of the selected device
        device:Device.Device = self.net_scanner.devices[device_pos]
        threading.Thread(target=device.resolve_name).start()

    def popular_port_scan(self,device_pos):
        #A Function that scan popular on the selected device
        device:Device.Device = self.net_scanner.devices[device_pos]
        threading.Thread(target=device.popular_port_scan).start()

    def check_threads_ratio(self,start_port, end_port, chunk_size):
        #Check if the values the user provided do not create a problem with the threads
        num_ports = end_port - start_port + 1
        if chunk_size>num_ports:
            return "Chunk size Bigger than the number of ports to scan!"
        if num_ports/chunk_size>100:
            return "Too many threads will be created, increase the chunk size"
        if chunk_size>1000:
            return "The scan will take a lot of time, decrease chunk size!"
        if end_port<start_port:
            return "End port must be bigger than start port!"
        if start_port<0 and end_port<0 or chunk_size<0:
            return "Input cannot be negative!"
        if end_port>65535:
            "Max end port is 65535(tcp)!"
        return ''

    def scan_ports(self,start_port_entry,end_port_entry,chunk_size_entry,popup,device_pos,accuracy):
        #A function that executes an intense port scan on the selected device
        try:
            start_port = int(start_port_entry.get())
            end_port = int(end_port_entry.get())
            chunk_size = int(chunk_size_entry.get())
        except:
            #if one or more of the int() fail
            messagebox.showerror("Error", "Invalid Input! Check It and try again!")
            return
        
        device:Device.Device = self.net_scanner.devices[device_pos]

        #Check for a problem with the tread ration and show an error with it
        if self.check_threads_ratio(start_port, end_port, chunk_size)!='':
            messagebox.showerror("Error",self.check_threads_ratio(start_port, end_port, chunk_size))
            return
        #start the scan
        threading.Thread(target=lambda:device.intense_port_scan(start_port,end_port,chunk_size,accuracy)).start()
        
        # Destroy popup window before performing port scan
        popup.destroy()

    def create_port_scan_popup(self,device_pos,start=0,end=65535,chunk=771):
        # Create popup window
        popup = tk.Toplevel(self.root)
        popup.title("Port Scan Options")
        popup.grab_set()
        popup.resizable(False,False)

        # Disclaimer label
        start_port_label = ttk.Label(popup, text="Do not use without permission!",style="Red.TLabel")
        start_port_label.pack()

        # Start Port label and entry
        start_port_label = ttk.Label(popup, text="Start Port")
        start_port_label.pack()
        start_port_entry = ttk.Entry(popup)
        start_port_entry.insert(0,start)
        start_port_entry.pack()

        # End Port label and entry
        end_port_label = ttk.Label(popup, text="End Port")
        end_port_label.pack()
        end_port_entry = ttk.Entry(popup)
        end_port_entry.insert(0,end)
        end_port_entry.pack()

        # Chunk Size label and entry
        chunk_size_label = ttk.Label(popup, text="Chunk Size (ports per thread)")
        chunk_size_label.pack()
        chunk_size_entry = ttk.Entry(popup)
        chunk_size_entry.insert(0,chunk)
        chunk_size_entry.pack()

        #options for accuracy(more wait time per port)
        accuracy_label = ttk.Label(popup, text="Accuracy")
        accuracy_label.pack()
        accuracy_options = ttk.Combobox(popup,values=["1","2","3","4","5","6","7"],state="readonly",style="TCombobox")
        accuracy_options.current(3)
        accuracy_options.pack()
        more_time_label = ttk.Label(popup, text="(Higher accuracy means more scan time)")
        more_time_label.pack()

        # Scan button
        self.ports_scan_button = ttk.Button(popup, text="Scan Ports",width=14, command=lambda:self.scan_ports(start_port_entry,end_port_entry,chunk_size_entry,popup,device_pos,int(accuracy_options.get())))
        self.ports_scan_button.pack()

    def port_scan_all_devices(self):
        #A function that scans popular ports on all the devices
        threading.Thread(target=self.net_scanner.port_scan_all_devices).start()
        self.ps_button.config(state=tk.DISABLED)

    def resolve_all_names(self):
        #A function that tries to resolve all the names of the devices
        threading.Thread(target=self.net_scanner.resolve_all_names).start()
        self.names_button.config(state=tk.DISABLED)

    def update_password(self):
        #Check if the network password has been found or if a problem accoured
        if self.pass_tester.password!='Finding...':
            self.pass_label.config(text=self.pass_tester.password)
            if self.pass_tester.password not in ['Failed to find password','Open network, no password']:
                self.run_pass_test_button.config(state=tk.NORMAL)
            else:
                self.no_pass=True

        else:
            #If the password is still being resolved, try again in 0.1 seconds
            self.root.after(100,self.update_password)

    def on_pass_option_changed(self,*args):
        # Check if the password option is selected
        if self.pass_option.get():
            # Enable the run password test button if the "no_pass" flag is set
            if self.no_pass:
                self.run_pass_test_button.config(state=tk.NORMAL)
            # Enable the password entry widget
            self.password_entry.config(state="normal")
        else:
            # Disable the run password test button if the "no_pass" flag is set
            if self.no_pass:
                self.run_pass_test_button.config(state=tk.DISABLED)
            # Disable the password entry widget
            self.password_entry.config(state="disabled")

    def run_pass_test(self):
        # Get the password from the password entry widget or use the default password if the "no_pass" flag is set
        if self.pass_option.get():
            password=self.password_entry.get()
        else:
            password=self.pass_tester.password
            
        # Check if the password is valid
        if not password or password=='Finding...':
            messagebox.showerror("Error",'Error handaling password. check input ot try again!')
            return
        
        # Test the password and get the results
        results=self.pass_tester.is_good_pass(password)

        # Initialize a dictionary to count the number of critical, important, and recommended tests passed
        level_count={"c":0,"i":0,"r":0}

        # Loop through the test results and update the GUI based on the result of each test
        for i in range(len(results)):
            if results[i]==1:
                # Increment the count of tests passed for the corresponding level of severity
                level_count[self.pass_tester.level_dict[i]]+=1
                # Update the image of the corresponding test label to the "passed" image
                self.test_label_list[i].config(image=self.passed_img)
            else:
                # Update the image of the corresponding test label to the "failed" image
                self.test_label_list[i].config(image=self.failed_img)

        # Update the overall test results label with the number of tests passed
        self.overall_results_label.config(text=f"Overall, the password passed {results.count(1)} out of 12 tests:")

        # Update the critical results label with the number of critical tests passed
        self.critical_results_label.config(text=f"{level_count['c']}/5 critical tests")

        # Update the important results label with the number of important tests passed
        self.important_results_label.config(text=f"{level_count['i']}/4 important tests")

        # Update the recommended results label with the number of recommended tests passed
        self.recommended_results_label.config(text=f"{level_count['r']}/3 recommended tests")

        # Update the recommendation label based on the number of tests passed and their level of severity
        if level_count['c']!=5 or level_count['i']<3 or level_count['r']==0:
            self.changing_recommendation_label.config(text="It is highly recommended that you change your password!")
        elif results.count(1)!=12:
            self.changing_recommendation_label.config(text="Your password is strong enough but it would be good to change it")
        else:
            self.changing_recommendation_label.config(text="Your password is very strong! Good Job!")

    def copy_password(self):
        # Clear the clipboard and append the generated password to it
        self.root.clipboard_clear()
        self.root.clipboard_append(self.generated_password_label.cget("text"))

    def generate_password(self):
        # Generate a new password using the password tester object and update the GUI with the new password
        self.generated_password_label.configure(text=self.pass_tester.generate_password())

    def update_network_test_results(self):
        # If network tester is not scanning, enable buttons and update labels with results
        if not self.network_tester.scanning:
            self.run_network_test_button.config(state=tk.NORMAL)
            self.download_label.config(text=f"{self.network_tester.download}")
            self.upload_label.config(text=f"{self.network_tester.upload}")
            self.ping_label.config(text=f"{self.network_tester.ping}")
            self.latency_label.config(text=f"{self.network_tester.latency}")
            self.bandwidth_label.config(text=f"{self.network_tester.bandwidth}")
            self.scan_button.config(state=tk.NORMAL)
        else:
            # If still scanning, wait 100ms and try again
            self.root.after(100,self.update_network_test_results)

    def start_network_test(self):
        # Disable network test button and start a new thread for network testing
        self.run_network_test_button.config(state=tk.DISABLED)
        threading.Thread(target=self.network_tester.full_test).start()
        # Disable scan button and start animation
        self.scan_button.config(state=tk.DISABLED)
        self.animate_loading_gif()
        # Start updating the network test results
        self.update_network_test_results()

    def animate_loading_gif(self,frame_idx=0):
        # Delete current animation frame and show the next one
        self.loading_animation_canvas.delete("all")
        self.loading_animation_canvas.create_image(0, 0, anchor="nw", image=self.frames[frame_idx])
        frame_idx = (frame_idx + 1) % len(self.frames)
        # If network test is still ongoing, wait 20ms and show the next frame
        if self.network_tester.scanning:
            self.loading_animation_canvas.after(20, self.animate_loading_gif, frame_idx)
        else:
            # Otherwise, stop the animation
            self.loading_animation_canvas.delete("all")

    def update_attack_logs(self):
        # Enable all attack logs
        logs=[self.arp_log,self.dos_log,self.brodcast_log,self.ps_log,self.malware_log]
        for log in logs:
            log.config(state='normal')

        # Update attack logs with new records, if any
        for i,record in enumerate(self.attack_detecter.attacks_records.values()):
            for event in record:
                # If event is not already in the log, wrap text and add it
                if event.replace(' ','').replace('\n','') not in logs[i].get('1.0','end').replace(' ','').replace('\n',''):
                    self.line_width = 30
                    self.lined_text ="\n".join(textwrap.wrap(event, width=self.line_width))
                    self.lined_text+='\n\n'
                    logs[i].insert('end',self.lined_text)

        # Disable all attack logs
        for log in logs:
            log.config(state='disabled')
        
        # Start updating attack logs again in 1.5 seconds
        self.root.after(1500,self.update_attack_logs)

    def update_scale_value(self,val):
        #Update the value of the scale when it is changed
        self.scale_value.set(str(int(float(val))))

    def control_request(self):
        # Get IP from input field
        ip=self.controlled_ip_input.get()
        
        # Validate IP address
        if len(ip)<7 or re.search(r"[^0-9.]", ip) or ip.count('.')!=3:
            # Show error message if invalid IP address
            messagebox.showerror("Error", "Invalid Ip, Check Input!")
            return
        ip_parts = ip.split('.')
        for part in ip_parts:
            if len(part)==0:
                # Show error message if invalid IP address
                messagebox.showerror("Error", "Invalid Ip, Check Input!")
                return
        if not self.net_scanner.is_in_lan(ip):
            # Show error message if IP address is not in LAN
            messagebox.showerror("Error", "Invalid Ip or not in lan, Check Input!")
            return
        if ip==self.my_ip:
            # Show error message if IP address is the same as the current machine's IP
            messagebox.showerror("Error","Ip cannot be your ip, Check Input!")
            return
        
        try:
            # Validate IP address
            socket.inet_aton(ip)
            if int(ip_parts[-1])==0:
                # Show error message if invalid IP address
                messagebox.showerror("Error", "Invalid Ip or not in lan, Check Input!")
                return 
        except:
            # Show error message if invalid IP address
            messagebox.showerror("Error", "Invalid Ip or not in lan, Check Input!")
            return
        
        # Get name and reason from input fields
        name=self.controller_name_input.get()
        reason=self.controller_reason_input.get()

        if re.search(r"[^a-zA-Z\s]", reason) or re.search(r"[^a-zA-Z\s]", name):
            # Show error message if name or reason contains non-letter characters
            messagebox.showerror("Error", "Name and Reason can only contain letters")
            return

        if len(name)<3 or len(name)>30:
            # Show error message if name is too short or too long
            messagebox.showerror("Error", "Name has to be longer than 3 letters and shorter than 30!")
            return
        
        if len(reason)<5 or len(reason)>40:
            # Show error message if reason is too short or too long
            messagebox.showerror("Error", "Reason has to be longer than 5 letters and shorter than 40!")
            return
        
        # Disable control button to prevent multiple requests
        self.control_button.config(state=tk.DISABLED)
        
        # Start a new thread to send the control request to the remote machine
        t=threading.Thread(target=self.send_rc_request,args=(ip,name,reason))
        t.start()

    def send_rc_request(self, ip, name, reason):
        # Create a new instance of encrypted_client using the given IP address and port number
        client = encrypted_client(ip, 11123)

        try:
            # Attempt to start the server and listen for incoming connections
            client.run_server()
        except:
            # If the connection couldn't be initiated, show an error message and enable the control button again
            self.rc_request_result_label.config(text="could not initiate connection", style='Red.TLabel')
            self.control_button.config(state=tk.NORMAL)
            return

        try:
            # Send the name, reason, and scale value to the connected client
            client.send(f'{name},{reason},{self.scale_value.get()}')
            # Update the UI to show that the request was sent
            self.rc_request_result_label.config(text="sent request...", style='Grey.TLabel')
            # Wait for a response from the client
            response = client.recieve()

            if response == 'approved':
                # If the client approves the request, update the UI to show that the connection is being established
                self.rc_request_result_label.config(text="connecting...", style='Grey.TLabel')
                # Wait for 2 seconds to ensure that the client has enough time to establish the connection
                time.sleep(2)
                # Create a new instance of RemoteController using the given IP address
                rc = RemoteController(ip)
                # Create a pipe for communication between the current process and the newly created process
                this_pipe, other_pipe = multiprocessing.Pipe()
                # Start a new process that will handle the connection
                p = multiprocessing.Process(target=rc.start_connection, args=(other_pipe,))
                p.start()
                # Wait for the child process to send a message through the pipe
                exit_reason = this_pipe.recv()
                if exit_reason == 'controlled computer disconnected':
                    # If the controlled computer disconnected during the session, show an error message
                    self.rc_request_result_label.config(text="controlled computer stopped control or experienced a problem/shut down!", style='Red.TLabel')
                else:
                    # If the session was terminated for some other reason, clear the error message
                    self.rc_request_result_label.config(text="")
                # Maximize the window to cover the entire screen
                self.root.state('zoomed')
                # Enable the control button again
                self.control_button.config(state=tk.NORMAL)
            else:
                # If the client denies the request, show an error message and enable the control button again
                self.rc_request_result_label.config(text="connection denied!", style='Red.TLabel')
                self.control_button.config(state=tk.NORMAL)
        except:
            # If the request fails for some other reason, show an error message and enable the control button again
            self.rc_request_result_label.config(text="request failed!", style='Red.TLabel')
            self.control_button.config(state=tk.NORMAL)

    def send_sniff_request(self,ip,name,reason):
        # Create an instance of the encrypted client
        client=encrypted_client(ip,28245)
        
        try:
            # Try to run the server
            client.run_server()
        except:
            # If there is an error, show an error message and return
            self.sniff_request_result_label.config(text="could not initiate connection",style='Red.TLabel')
            self.sniff_button.config(state=tk.NORMAL)
            return
        
        try:
            # If the server is running, send the request
            client.send(f'{name},{reason}')
            self.sniff_request_result_label.config(text="sent request...",style='Grey.TLabel')
            
            # Wait for the response from the server
            response=client.recieve()
            
            # If the response is 'approved', start recieving data
            if response=='approved':
                self.sniff_request_result_label.config(text="recieving data...",style='Grey.TLabel')
                
                # Create another instance of the encrypted client for sniffing
                sniff_client=encrypted_client(ip,45689)
                sniff_client.run_server()
                
                # Wait for 2 seconds before proceeding
                time.sleep(2)

                # Get the length of the data to be recieved
                length=int(sniff_client.recieve())
                
                # Send an acknowledgement to the server
                sniff_client.send('recieved')
                
                # Receive the data in chunks and append it to a byte string
                recieved_bytes=b''
                while len(recieved_bytes)<length:
                    res=sniff_client.recieve(1_000_000,isBytes=True)
                    sniff_client.send('recieved')
                    recieved_bytes+=res

                # Write the recieved bytes to a file
                with open('recieved_pcap.pcap','wb') as f:
                    f.write(recieved_bytes)

                # Load the pcap file
                pcap = rdpcap('recieved_pcap.pcap')

                # Get the size of the pcap file
                size = os.path.getsize('recieved_pcap.pcap')
                kbsize=round(size/1000)
                self.pcap_size_value_label.config(text=str(kbsize)+' kbs')

                # Get the number of packets in the pcap file
                num_packets = len(pcap)
                self.pcap_pnum_value_label.config(text=str(num_packets))

                # Get the oldest packet date
                oldest_packet = min(pcap, key=lambda p: p.time)
                dt = datetime.datetime.fromtimestamp(int(oldest_packet.time))

                # Extract the date, hour, minute, and second components
                date = dt.strftime('%Y-%m-%d')
                hour = dt.strftime('%H')
                minute = dt.strftime('%M')
                second = dt.strftime('%S')
                self.pcap_oldest_value_label.config(text=f'{date} {hour}:{minute}:{second}')

                try:
                    # Close the client socket and delete the instance
                    sniff_client.soc.close()
                    del sniff_client
                finally:
                    # Enable buttons and show a success message
                    self.open_file_button.config(state=tk.NORMAL)
                    self.save_file_button.config(state=tk.NORMAL)
                    self.sniff_button.config(state=tk.NORMAL)
                    self.sniff_request_result_label.config(text="share completed",style='Grey.TLabel')
            else:
                # If the response is not 'approved', show a denial message
                self.sniff_request_result_label.config(text="request denied!",style='Red.TLabel')
                self.sniff_button.config(state=tk.NORMAL)
        except Exception as e:
            # If there is an error, show an error message and return
            self.sniff_request_result_label.config(text="request failed!",style='Red.TLabel')
            self.sniff_button.config(state=tk.NORMAL)

    def sniff_request(self):
        # Get the IP address entered by the user
        ip = self.sender_ip_input.get()

        # Check if the IP address is valid
        if len(ip) < 7 or re.search(r"[^0-9.]", ip) or ip.count('.') != 3:
            messagebox.showerror("Error", "Invalid Ip, Check Input!")
            return

        # Split the IP address into its parts and check each part
        ip_parts = ip.split('.')
        for part in ip_parts:
            if len(part) == 0:
                messagebox.showerror("Error", "Invalid Ip, Check Input!")
                return

        # Check if the IP address is in the local network
        if not self.net_scanner.is_in_lan(ip):
            messagebox.showerror("Error", "Invalid Ip or not in lan, Check Input!")
            return

        # Check if the IP address is not the same as the user's own IP address
        if ip == self.my_ip:
            messagebox.showerror("Error", "Ip cannot be your ip, Check Input!")
            return

        # Check if the IP address is valid using the socket module
        try:
            socket.inet_aton(ip)
            if int(ip_parts[-1]) == 0:
                messagebox.showerror("Error", "Invalid Ip or not in lan, Check Input!")
                return
        except:
            messagebox.showerror("Error", "Invalid Ip or not in lan, Check Input!")
            return

        # Get the reciever's name and reason for sniffing
        name = self.reciever_name_input.get()
        reason = self.reciever_reason_input.get()

        # Check if the name and reason contain only letters
        if re.search(r"[^a-zA-Z\s]", reason) or re.search(r"[^a-zA-Z\s]", name):
            messagebox.showerror("Error", "Name and Reason can only contain letters")
            return

        # Check if the name is between 3 and 30 characters and the reason is between 5 and 40 characters
        if len(name) < 3 or len(name) > 30:
            messagebox.showerror("Error", "Name has to be longer than 3 letters and shorter than 30!")
            return

        if len(reason) < 5 or len(reason) > 40:
            messagebox.showerror("Error", "Reason has to be longer than 5 letters and shorter than 40!")
            return

        # Disable the "Sniff" button
        self.sniff_button.config(state=tk.DISABLED)

        # Start a new thread to send the sniff request
        t = threading.Thread(target=self.send_sniff_request, args=(ip, name, reason))
        t.start()

    def save_file(self):
        # Prompt the user to choose a location to save the file
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap")
        if file_path:
            # Copy the file to the chosen location
            shutil.copy("recieved_pcap.pcap", file_path)

    def open_file(self):
        try:
            # Open the file
            os.system(f"recieved_pcap.pcap")
        except:
            # Show an error message if the file cannot be opened
            messagebox.showerror('Error','File opening failed. Open menually or try again!')
            return

    def check_connection(self):
        while True:
            # If scanning is not in progress, exit the loop and the function
            if not self.attack_detecter.scanning:
                sys.exit()
            try:
                # Get network information and wait for 0.1 seconds
                get_net_info.get_ip_info()
                time.sleep(0.1)
            except:
                # Show an error message if a problem is detected with the network
                messagebox.showerror("Error", "A problem in network was detected. Check connection and restart the app!")
                # Stop scanning, close all tools, and exit the program
                self.attack_detecter.scanning=False
                self.net_scanner.stop_flag=True
                self.net_scanner.close_all_tools()
                sys.exit()

    def on_click_link(self,event, link):
        # Open the link in the default web browser
        import webbrowser
        webbrowser.open_new(link)

if __name__=='__main__':
    # Ensure that the program runs correctly on Windows
    multiprocessing.freeze_support()
    # Create a GUI object and start the application
    app=gui()