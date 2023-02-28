import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from network_scanner import network_scanner
import threading
import get_net_info
import Device
from PIL import Image,ImageTk

 # function to update device table
def update_device_table():
    global scanning,scanning_thr,scan_button,selected_table_row
    if not net_scanner.is_ps_all and tk.DISABLED in ps_button.state() and len(device_table.get_children())>0:
        ps_button.config(state=tk.NORMAL)
    
    if not net_scanner.is_resolving_names and tk.DISABLED in names_button.state() and len(device_table.get_children())>0:
        names_button.config(state=tk.NORMAL)

    if scanning and not net_scanner.scanning:
        if scan_range_options.get()=="Manual":
            ip_input.config(state=tk.NORMAL)
        progress_bar["value"]=0
        stop_button.config(state=tk.DISABLED)
        scanning=False
        scan_button.config(state=tk.NORMAL)
        scan_range_options.config(state=tk.NORMAL)
        scan_range_options.config(state="readonly")
        scan_range_options.config(state=tk.NORMAL)
        device_table.delete(*device_table.get_children())
        devices = net_scanner.devices
        for i,device in enumerate(devices):
            if device.is_alive:
                image=device_img
            else:
                image=dead_device_img
            added=''
            if device.ip==my_ip:
                added=' (You)'
                image=me_img
            elif device.ip==router_ip:
                added=' (Default Gateway)'
                image=router_img

            device_row=device_table.insert("", "end",str(i),text='',image=image, values=[device.name+added,device.ip,device.mac,device.mac_vendor,f'{device.data_transfered} Bytes'])
            device_table.insert(device_row,"end",device_row+"_0",values=[" Open Ports:"]+device.get_port_desc())
    else:
        try:
            for i,item_id in enumerate(device_table.get_children()):
                device=net_scanner.devices[i]
                net_scanner.update_data_transfered()
                added=''

                if device.is_alive:
                    image=device_img
                else:
                    image=dead_device_img

                added=''
                if device.ip==my_ip:
                    added=' (You)'
                    image=me_img
                elif device.ip==router_ip:
                    added=' (Default Gateway)'
                    image=router_img

                device_table.item(item_id,text='',image=image,values=[device.name+added,device.ip,device.mac,device.mac_vendor,f'{device.data_transfered} Bytes'])
                if device.currently_port_scanning:
                    device_table.item(item_id+"_0",text='',image=ps_load_img,values=[" Open Ports:"]+device.get_port_desc())
                else:
                    device_table.item(item_id+"_0",image=tk.PhotoImage(),values=[" Open Ports:"]+device.get_port_desc())
        except Exception as e:
            print(e)
            pass
    
    root.update()

    root.after(400,update_device_table)

def update_progress_bar():
    if not scanning:
        progress_bar["value"]=0
    
    if progress_bar["value"]>=len(net_scanner.ips_to_scan) and progress_bar["value"]+10<len(net_scanner.ips_to_scan)+100:
        progress_bar["value"]+=10
        root.after(1000,update_progress_bar)
    elif progress_bar["value"]<len(net_scanner.ips_to_scan):
        progress_bar["value"]=net_scanner.finished_scanning_count
        root.after(100,update_progress_bar)

# function to handle start scanning button press
def start_scan():
    global scanning,scan_button,scanning_thr

    if scan_range_options.get() == "Manual":
        succeded=net_scanner.parse_ip_input(ip_input.get())
        if not succeded:
            messagebox.showerror("Error", "Invalid Ip range, Check Input!")
            return
    else:
        net_scanner.ips_to_scan=get_net_info.get_ip_info()[3]

    net_scanner.scanning=True
    scanning = True
    scanning_thr=threading.Thread(target=net_scanner.scan_network)
    scanning_thr.start()

    progress_bar["maximum"]=len(net_scanner.ips_to_scan)+100

    stop_button.config(state=tk.NORMAL)
    update_progress_bar()
    if len(device_table.get_children())==0:
        update_device_table()
    scan_button.config(state=tk.DISABLED)
    scan_range_options.config(state=tk.DISABLED)
    ip_input.config(state=tk.DISABLED)

# function to handle stop scanning button press
def stop_scan():
    stop_button.config(state=tk.DISABLED)
    net_scanner.stop_flag=True

# function to get selected row in device table
def get_selected_table_row(event):
    global selected_table_row,device_table
    selected_table_row = device_table.identify_row(event.y).removesuffix("_0")

def toggle_ip_input(scan_range_options, ip_input):
    if scan_range_options.get() == "Manual":
        ip_input.config(state=tk.NORMAL)
    else:
        ip_input.config(state=tk.DISABLED)

def show_popup_menu(event):
    global selected_table_row,device_table
    row_id = device_table.identify_row(event.y).removesuffix("_0")
    if not row_id:
        return
    row_num=int(row_id)
    if row_num != "":
        popup_menu = tk.Menu(root, tearoff=0)
        if net_scanner.devices[row_num].is_alive:
            popup_menu.add_command(label="Try to resolve name",command=lambda:try_to_resolve_name(row_num))
            if not net_scanner.devices[row_num].currently_port_scanning:
                popup_menu.add_command(label="Scan Popular Ports",command=lambda:popular_port_scan(row_num))
                popup_menu.add_command(label="Intense Port Scan",command=lambda:create_port_scan_popup(row_num))
            else:
                popup_menu.add_command(label="Scan Popular Ports",command=lambda:popular_port_scan(row_num),state=tk.DISABLED)
                popup_menu.add_command(label="Intense Port Scan",command=lambda:create_port_scan_popup(row_num),state=tk.DISABLED)
        else:
            popup_menu.add_command(label="Try to resolve name",command=lambda:try_to_resolve_name(row_num),state=tk.DISABLED)
            popup_menu.add_command(label="Scan Popular Ports",command=lambda:popular_port_scan(row_num),state=tk.DISABLED)
            popup_menu.add_command(label="Intense Port Scan",command=lambda:create_port_scan_popup(row_num),state=tk.DISABLED)
        popup_menu.add_separator()
        popup_menu.add_command(label="Copy IP Address", command=lambda: copy_to_clipboard(device_table.item(row_id, "values")[1]))
        popup_menu.add_command(label="Copy MAC Address", command=lambda: copy_to_clipboard(device_table.item(row_id, "values")[2]))
        popup_menu.add_command(label="Copy MAC Vendor", command=lambda: copy_to_clipboard(device_table.item(row_id, "values")[3]))
        popup_menu.add_command(label="Copy Data Transfered", command=lambda: copy_to_clipboard(device_table.item(row_id, "values")[4]))
        popup_menu.add_command(label="Copy Open Ports", command=lambda: copy_to_clipboard(' '.join(net_scanner.devices[row_num].get_port_desc())))

        popup_menu.post(event.x_root, event.y_root)

def copy_to_clipboard(value):
    root.clipboard_clear()
    root.clipboard_append(value)

def try_to_resolve_name(device_pos):
    device:Device.Device = net_scanner.devices[device_pos]
    threading.Thread(target=device.resolve_name).start()

def popular_port_scan(device_pos):
    device:Device.Device = net_scanner.devices[device_pos]
    threading.Thread(target=device.popular_port_scan).start()

def check_ratio(start_port, end_port, chunk_size):
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

def scan_ports(start_port_entry,end_port_entry,chunk_size_entry,popup,device_pos,accuracy):
    try:
        start_port = int(start_port_entry.get())
        end_port = int(end_port_entry.get())
        chunk_size = int(chunk_size_entry.get())
    except:
        messagebox.showerror("Error", "Invalid Input! Check It and try again!")
        return
    
    device:Device.Device = net_scanner.devices[device_pos]

    if check_ratio(start_port, end_port, chunk_size)!='':
        messagebox.showerror("Error",check_ratio(start_port, end_port, chunk_size))
        return
    device
    threading.Thread(target=lambda:device.intense_port_scan(start_port,end_port,chunk_size,accuracy)).start()
    
    # Destroy popup window before performing port scan
    popup.destroy()

def create_port_scan_popup(device_pos,start=0,end=65535,chunk=771):
    # Create popup window
    popup = tk.Toplevel(root)
    popup.title("Port Scan Options")
    popup.grab_set()
    popup.resizable(False,False)

     # Disclaimer label
    ttk.Style().configure("Red.TLabel",foreground="red")
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
    scan_button = ttk.Button(popup, text="Scan Ports", command=lambda:scan_ports(start_port_entry,end_port_entry,chunk_size_entry,popup,device_pos,int(accuracy_options.get())))
    scan_button.pack()

def port_scan_all_devices():
    threading.Thread(target=net_scanner.port_scan_all_devices).start()
    ps_button.config(state=tk.DISABLED)

def resolve_all_names():
    threading.Thread(target=net_scanner.resolve_all_names).start()
    names_button.config(state=tk.DISABLED)

my_ip = get_net_info.get_ip_info()[0]
router_ip = get_net_info.get_ip_info()[1]

net_scanner = network_scanner()
scanning = False
scanning_thr=threading.Thread()

root = tk.Tk()
root.state('zoomed')
root.title("NetScanner")

# create menu bar
menu_bar = tk.Menu(root)
file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Exit", command=root.quit)
menu_bar.add_cascade(label="File", menu=file_menu)

settings_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Settings", menu=settings_menu)

help_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Help", menu=help_menu)

root.config(menu=menu_bar)
font_family = "Courier New"
font_size = 14

# create styles
ttk.Style().configure("Treeview", font=(font_family, font_size), rowheight=36)
ttk.Style().configure("TButton", font=(font_family, font_size),padding=5)
ttk.Style().configure("TEntry", font=(font_family, font_size),padding=5,height=3)
ttk.Style().configure("TRadiobutton", font=(font_family, font_size))
ttk.Style().configure("TCheckbutton", font=(font_family, font_size))
ttk.Style().configure("TCombobox", font=(font_family, font_size),height=100)

#load all images
device_img = Image.open("device.png")
device_img = device_img.resize((20, 20))  # Resize image
device_img = ImageTk.PhotoImage(device_img)

dead_device_img = Image.open("dead_device.png")
dead_device_img = dead_device_img.resize((20, 20))  # Resize image
dead_device_img = ImageTk.PhotoImage(dead_device_img)

router_img = Image.open("router.png")
router_img = router_img.resize((20, 20))  # Resize image
router_img = ImageTk.PhotoImage(router_img)

me_img = Image.open("me.png")
me_img = me_img.resize((20, 20))  # Resize image
me_img = ImageTk.PhotoImage(me_img)

scan_img = Image.open("scan.png")
scan_img = scan_img.resize((20, 20))  # Resize image
scan_img = ImageTk.PhotoImage(scan_img)

stop_img = Image.open("stop.png")
stop_img = stop_img.resize((20, 20))  # Resize image
stop_img = ImageTk.PhotoImage(stop_img)

ps_load_img= Image.open("port_scan_load.png")
ps_load_img = ps_load_img.resize((20, 20))  # Resize image
ps_load_img = ImageTk.PhotoImage(ps_load_img)

# create frames
scan_frame = ttk.Frame(root)
scan_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

progress_bar_frame = ttk.Frame(root)
progress_bar_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5)

devices_frame = ttk.Frame(root)
devices_frame.pack(side=tk.TOP, fill=tk.BOTH, padx=5, pady=5, expand=True)

# create widgets for the scan frame
scan_button = ttk.Button(scan_frame, text="Scan",width=8,image=scan_img,compound="right")
scan_button.grid(row=0, column=0, padx=5, pady=5)
scan_button.config(command=start_scan)

stop_button = ttk.Button(scan_frame, text="Stop", command=stop_scan,width=8,image=stop_img,compound="right")
stop_button.grid(row=0, column=1, padx=5, pady=5)
stop_button.config(state=tk.DISABLED)

scan_range_options = ttk.Combobox(scan_frame, values=["Manual", "Full Network"], state="readonly",style="TCombobox")
scan_range_options.current(1)
scan_range_options.grid(row=0, column=2, padx=5, pady=5)

ip_input = ttk.Entry(scan_frame, width=110)
ip_input.insert(0, "Example: 192.168.1.1-255")
ip_input.grid(row=0, column=3, padx=5, pady=5)
ip_input.config(state=tk.DISABLED)

names_button = ttk.Button(scan_frame, text="Resolve Names",command=resolve_all_names)
names_button.grid(row=0, column=4, padx=5, pady=5)
names_button.config(state=tk.DISABLED)

ps_button = ttk.Button(scan_frame, text="Scan Popular Ports",command=port_scan_all_devices)
ps_button.grid(row=0, column=5, padx=5, pady=5)
ps_button.config(state=tk.DISABLED)

# create widgets for devices frame
headings = ["name", "ip", "mac", "mac vendor", 'Data Transfered With Me']
selected_table_row = 0
device_table = ttk.Treeview(devices_frame, columns=headings, height=31)
device_table.heading("#0", text="status", anchor='center')
device_table.column("#0", width=50,minwidth=50, stretch=False)

for i,header in enumerate(headings,start=1):   
    device_table.heading(f'#{i}', text=header, anchor=tk.W)
    device_table.column(header, width=200, minwidth=150, stretch=True)

device_table.bind("<ButtonRelease-1>", lambda event: get_selected_table_row(event))

device_table.pack(side=tk.LEFT, fill=tk.BOTH, padx=5, pady=5, expand=True)

scrollbar = ttk.Scrollbar(devices_frame, orient="vertical", command=device_table.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

device_table.config(yscrollcommand=scrollbar.set)

ttk.Style().configure('my.Horizontal.TProgressbar', barcolor='#0f0', thickness=1)
progress_bar = ttk.Progressbar(progress_bar_frame, orient=tk.HORIZONTAL, length=2000, mode='determinate',style='my.Horizontal.TProgressbar')
progress_bar.pack(padx=5, pady=5)

scan_range_options.bind("<<ComboboxSelected>>", lambda event: toggle_ip_input(scan_range_options, ip_input))

# add widgets to devices frame
device_table.bind("<ButtonRelease-3>", lambda event: show_popup_menu(event))

# start main loop
root.mainloop()

net_scanner.stop_flag=True
net_scanner.close_all_tools()