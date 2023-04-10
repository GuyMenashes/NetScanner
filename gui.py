import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import tkinter.font as tkFont
from network_scanner import network_scanner
import threading
import get_net_info
import Device
from PIL import Image,ImageTk
from shutdown_restart import *
import textwrap
import re
from wifi_pass_tester import password_tester
import traffic_testing
import attacks_detection

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
    
    if progress_bar["value"]>=len(net_scanner.ips_to_scan) and progress_bar["value"]+10<len(net_scanner.ips_to_scan)+140:
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

    progress_bar["maximum"]=len(net_scanner.ips_to_scan)+140

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

        popup_menu.add_separator()
        popup_menu.add_command(label="Shutdown", command=lambda: shutdown_restart_window(device_table.item(row_id, "values")[1],'Shutdown'))
        popup_menu.add_command(label="Restart", command=lambda: shutdown_restart_window(device_table.item(row_id, "values")[1],'Restart'))

        popup_menu.post(event.x_root, event.y_root)

def run_action(popup,ip,action,run_button,wait_time_entry,message_entry,result_value_label):
    run_button.config(state=tk.DISABLED)

    if not re.match(r'^\d+$',wait_time_entry.get()) or int(wait_time_entry.get())>315360000:
        if not re.match(r'^\d+$',wait_time_entry.get()) :
            messagebox.showerror("Error", "Invalid Wait Time Input! Check It and try again!")
        else:
            messagebox.showerror("Error", "Wait time has to be smaller than 315360000 seconds (ten years)")
        message=message_entry.get("1.0", "end-1c")
        time=wait_time_entry.get()
        status=result_value_label.cget("text")
        popup.destroy()
        shutdown_restart_window(ip,action,message,time,status)
        return
    
    output=[]

    if action=="Shutdown":
        action_thr=threading.Thread(target=lambda:shutdown(output,ip,wait_time_entry.get(),message_entry.get("1.0", "end-1c")))
    if action=="Restart":
        action_thr=threading.Thread(target=lambda:restart(output,ip,wait_time_entry.get(),message_entry.get("1.0", "end-1c")))
    
    action_thr.start()

    wait_for_result(popup,output,result_value_label,run_button)

def wait_for_result(popup,output,result_value_label,run_button):
    if len(output)==0:
        popup.after(50,lambda: wait_for_result(popup,output,result_value_label,run_button))
        return
            
    line_width = 50
    splited_text ="\n".join(textwrap.wrap(output[0], width=line_width))
    if "Succes!" in output[0]:
        result_value_label.config(text=splited_text,background="green")
    else:
        result_value_label.config(text=splited_text,background="red")

    run_button.config(state=tk.NORMAL)

def shutdown_restart_window(ip,action,message='',time='',status='\n\n'):
    # Create a new popup window
    popup = tk.Toplevel(root)
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
    run_button = ttk.Button(popup, text="Run",width=14, command=lambda:run_action(popup,ip,action,run_button,wait_time_entry,message_entry,result_value_label))
    run_button.pack(pady=5)

    # Add a label for result
    result_label = ttk.Label(popup, text="Result:")
    result_label.pack()
    result_value_label = tk.Label(popup,justify=tk.LEFT,text=status,anchor=tk.W)
    result_value_label.pack(anchor='w')

    popup.mainloop()

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
    scan_button = ttk.Button(popup, text="Scan Ports",width=14, command=lambda:scan_ports(start_port_entry,end_port_entry,chunk_size_entry,popup,device_pos,int(accuracy_options.get())))
    scan_button.pack()

def port_scan_all_devices():
    threading.Thread(target=net_scanner.port_scan_all_devices).start()
    ps_button.config(state=tk.DISABLED)

def resolve_all_names():
    threading.Thread(target=net_scanner.resolve_all_names).start()
    names_button.config(state=tk.DISABLED)

def update_password():
    global no_pass
    if pass_tester.password!='Finding...':
        pass_label.config(text=pass_tester.password)
        if pass_tester.password not in ['Failed to find password','Open network, no password']:
            run_pass_test_button.config(state=tk.NORMAL)
        else:
            no_pass=True

    else:
        root.after(100,update_password)

def on_pass_option_changed(*args):
    if pass_option.get():
        if no_pass:
            run_pass_test_button.config(state=tk.NORMAL)
        password_entry.config(state="normal")
    else:
        if no_pass:
            run_pass_test_button.config(state=tk.DISABLED)
        password_entry.config(state="disabled")

def run_pass_test():
    if pass_option.get():
        password=password_entry.get()
    else:
        password=pass_tester.password

    results=pass_tester.is_good_pass(password)

    level_count={"c":0,"i":0,"r":0}

    for i in range(len(results)):
        if results[i]==1:
            level_count[pass_tester.level_dict[i]]+=1
            test_label_list[i].config(image=passed_img)
        else:
            test_label_list[i].config(image=failed_img)

    overall_results_label.config(text=f"Overall, the password passed {results.count(1)} out of 12 tests:")

    critical_results_label.config(text=f"{level_count['c']}/5 critical tests")

    important_results_label.config(text=f"{level_count['i']}/4 important tests")

    recommended_results_label.config(text=f"{level_count['r']}/3 recommended tests")

    if level_count['c']!=5 or level_count['i']<3 or level_count['r']==0:
        changing_recommendation_label.config(text="It is highy recommended that you change your password!")
    elif results.count(1)!=12:
        changing_recommendation_label.config(text="Your password is strong enough but it would be good to change it")
    else:
        changing_recommendation_label.config(text="Your password is very strong! Good Job!")

def copy_password():
    root.clipboard_clear()
    root.clipboard_append(generated_password_label.cget("text"))

def generate_password():
    generated_password_label.configure(text=pass_tester.generate_password())

def update_network_test_results():
    if not network_tester.scanning:
        run_network_test_button.config(state=tk.NORMAL)
        download_label.config(text=f"{network_tester.download}")
        upload_label.config(text=f"{network_tester.upload}")
        ping_label.config(text=f"{network_tester.ping}")
        latency_label.config(text=f"{network_tester.latency}")
        bandwidth_label.config(text=f"{network_tester.bandwidth}")
    else:
        root.after(100,update_network_test_results)

def start_network_test():
    run_network_test_button.config(state=tk.DISABLED)
    threading.Thread(target=network_tester.full_test).start()
    animate_loading_gif()
    update_network_test_results()

def animate_loading_gif(frame_idx=0):
    loading_animation_canvas.delete("all")
    loading_animation_canvas.create_image(0, 0, anchor="nw", image=frames[frame_idx])
    frame_idx = (frame_idx + 1) % len(frames)
    if network_tester.scanning:
        loading_animation_canvas.after(20, animate_loading_gif, frame_idx)
    else:
        loading_animation_canvas.delete("all")

def update_attack_logs():
    logs=[arp_log,dos_log,brodcast_log,ps_log,malware_log]

    for log in logs:
        log.config(state='normal')

    for i,record in enumerate(attack_detecter.attacks_records.values()):
        for event in record:
            if event.replace(' ','').replace('\n','') not in logs[i].get('1.0','end').replace(' ','').replace('\n',''):
                line_width = 30
                lined_text ="\n".join(textwrap.wrap(event, width=line_width))
                lined_text+='\n\n'
                logs[i].insert('end',lined_text)

    for log in logs:
        log.config(state='disabled')
    
    root.after(1500,update_attack_logs)

my_ip = get_net_info.get_ip_info()[0]
router_ip = get_net_info.get_ip_info()[1]

net_scanner = network_scanner()
scanning = False
scanning_thr=threading.Thread()

root = tk.Tk()
root.state('zoomed')
root.title("Network Manager")

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
ttk.Style().configure("Red.TLabel",foreground="red")
ttk.Style().configure("Orange.TLabel",foreground="DarkOrange3")
ttk.Style().configure("Yellow.TLabel",foreground="goldenrod1")

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

run_img = Image.open("run.png")
run_img = run_img.resize((20, 20))  # Resize image
run_img = ImageTk.PhotoImage(run_img)

stop_img = Image.open("stop.png")
stop_img = stop_img.resize((20, 20))  # Resize image
stop_img = ImageTk.PhotoImage(stop_img)

ps_load_img= Image.open("port_scan_load.png")
ps_load_img = ps_load_img.resize((20, 20))  # Resize image
ps_load_img = ImageTk.PhotoImage(ps_load_img)

passed_img= Image.open("passed.png")
passed_img = passed_img.resize((20, 20))  # Resize image
passed_img = ImageTk.PhotoImage(passed_img)

failed_img= Image.open("x.png")
failed_img = failed_img.resize((20, 20))  # Resize image
failed_img = ImageTk.PhotoImage(failed_img)

question_img= Image.open("question_mark.png")
question_img = question_img.resize((20, 20))  # Resize image
question_img = ImageTk.PhotoImage(question_img)

upload_img=Image.open("upload.png")
upload_img=upload_img.resize((300,350))
upload_img = ImageTk.PhotoImage(upload_img)

ping_img=Image.open("ping.png")
ping_img=ping_img.resize((300,350))
ping_img = ImageTk.PhotoImage(ping_img)

bandwidth_img=Image.open("bandwidth.png")
bandwidth_img=bandwidth_img.resize((300,350))
bandwidth_img = ImageTk.PhotoImage(bandwidth_img)

latency_img=Image.open("latency.png")
latency_img=latency_img.resize((300,350))
latency_img = ImageTk.PhotoImage(latency_img)

download_img=Image.open("download.png")
download_img = ImageTk.PhotoImage(download_img)

#create action bar and add all window frames
ttk.Style().configure('Custom.TNotebook', tabmargins=[2, 5, 2, 0])
ttk.Style().configure('Custom.TNotebook.Tab', foreground='black', padding=[10, 5])

action_bar = ttk.Notebook(root,style="Custom.TNotebook",takefocus=False)
action_bar.pack(fill='x')

network_scanner_frame=ttk.Frame(action_bar)
action_bar.add(network_scanner_frame,text="Network Scanner")

password_testing_frame=ttk.Frame(action_bar)
action_bar.add(password_testing_frame,text="Password Tester")

ttk.Style().configure('Custom.TFrame', background='gray35')
network_testing_frame=ttk.Frame(action_bar,style='Custom.TFrame')
action_bar.add(network_testing_frame,text="Netwotk Tester")

attack_detection_frame=ttk.Frame(action_bar)
action_bar.add(attack_detection_frame,text="Attack Detector")

sniff_share_frame=ttk.Frame(action_bar)
action_bar.add(sniff_share_frame,text="Sniff Share")

remote_control_frame=ttk.Frame(action_bar)
action_bar.add(remote_control_frame,text="Remote Control")

#create widgets for attack detection window
attack_detecter=attacks_detection.network_attack_detector()
attack_detecter.start_sniffers()

arp_headline=ttk.Label(attack_detection_frame,text="Arp Spoffing:",font=('Arial',20))
arp_headline.grid(row=0, column=0, padx=5, pady=5)
arp_log=tk.Text(attack_detection_frame,width=34,height=38)
arp_log.grid(row=1, column=0, padx=5, pady=5)
arp_scrollbar=tk.Scrollbar(attack_detection_frame,background='red',troughcolor='red', orient='vertical')
arp_scrollbar.grid(row=1, column=1, padx=0, pady=5,sticky='ns')
arp_log.config(yscrollcommand=arp_scrollbar.set)
arp_scrollbar.config(command=arp_log.yview)
exp_text="ARP spoofing consists of sending falsified arp messages in order to link the attacker's MAC address with the IP address of another device (usually the router). This allows the attacker to intercept and manipulate network traffic."
line_width = 59
lined_text ="\n".join(textwrap.wrap(exp_text, width=line_width))
arp_explanation_label=ttk.Label(attack_detection_frame,text=lined_text,width=49,font=('Arial',8),borderwidth=5,relief='solid')
arp_explanation_label.grid(row=2, column=0,columnspan=2, padx=5, pady=5)

dos_headline=ttk.Label(attack_detection_frame,text="Dos Attack:",font=('Arial',20))
dos_headline.grid(row=0, column=2, padx=5, pady=5)
dos_log=tk.Text(attack_detection_frame,width=34,height=38)
dos_log.grid(row=1, column=2, padx=5, pady=5)
dos_scrollbar=tk.Scrollbar(attack_detection_frame,background='red',troughcolor='red', orient='vertical')
dos_scrollbar.grid(row=1, column=3, padx=0, pady=5,sticky='ns')
dos_log.config(yscrollcommand=dos_scrollbar.set)
dos_scrollbar.config(command=dos_log.yview)
line_width = 59
exp_text="A Denial-of-Service attack (DOS) aims to disrupt the availability of a network, website, or other online service by overwhelming it with traffic or other requests, usually using TCP, UPD or ICMP packets"
lined_text ="\n".join(textwrap.wrap(exp_text, width=line_width))
dos_explanation_label=ttk.Label(attack_detection_frame,text=lined_text,width=49,font=('Arial',8),borderwidth=5,relief='solid')
dos_explanation_label.grid(row=2, column=2,columnspan=2, padx=5, pady=5)

brodcast_headline=ttk.Label(attack_detection_frame,text="Brodcast Storm:",font=('Arial',20))
brodcast_headline.grid(row=0, column=4, padx=5, pady=5)
brodcast_log=tk.Text(attack_detection_frame,width=34,height=38)
brodcast_log.grid(row=1, column=4, padx=5, pady=5)
brodcast_scrollbar=tk.Scrollbar(attack_detection_frame,background='red',troughcolor='red', orient='vertical')
brodcast_scrollbar.grid(row=1, column=5, padx=0, pady=5,sticky='ns')
brodcast_log.config(yscrollcommand=brodcast_scrollbar.set)
brodcast_scrollbar.config(command=brodcast_log.yview)
exp_text="A broadcast storm is when a broadcast or multicast packet is continuously transmitted and retransmitted by every device on a network, creating a loop of excessive traffic that can significantly slow down or even crash the network."
line_width = 59
lined_text ="\n".join(textwrap.wrap(exp_text, width=line_width))
brodcast_explanation_label=ttk.Label(attack_detection_frame,text=lined_text,width=49,font=('Arial',8),borderwidth=5,relief='solid')
brodcast_explanation_label.grid(row=2, column=4,columnspan=2, padx=5, pady=5)

ps_headline=ttk.Label(attack_detection_frame,text="Port Scanning:",font=('Arial',20))
ps_headline.grid(row=0, column=6, padx=5, pady=5)
ps_log=tk.Text(attack_detection_frame,width=34,height=38)
ps_log.grid(row=1, column=6, padx=5, pady=5)
ps_scrollbar=tk.Scrollbar(attack_detection_frame,background='red',troughcolor='red', orient='vertical')
ps_scrollbar.grid(row=1, column=7, padx=0, pady=5,sticky='ns')
ps_log.config(yscrollcommand=ps_scrollbar.set)
ps_scrollbar.config(command=ps_log.yview)
exp_text="Port scanning is used to discover which network ports are open on a target computer or device. Hackers may use port scanning to identify open ports that could be used as entry points for a cyber attack."
line_width = 59
lined_text ="\n".join(textwrap.wrap(exp_text, width=line_width))
ps_explanation_label=ttk.Label(attack_detection_frame,text=lined_text,width=49,font=('Arial',8),borderwidth=5,relief='solid')
ps_explanation_label.grid(row=2, column=6,columnspan=2, padx=5, pady=5)

malware_headline=ttk.Label(attack_detection_frame,text="Malware Signatures:",font=('Arial',20))
malware_headline.grid(row=0, column=8, padx=5, pady=5)
malware_log=tk.Text(attack_detection_frame,width=34,height=38)
malware_log.grid(row=1, column=8, padx=5, pady=5)
malware_scrollbar=tk.Scrollbar(attack_detection_frame,background='red',troughcolor='red', orient='vertical')
malware_scrollbar.grid(row=1, column=9, padx=0, pady=5,sticky='ns')
malware_log.config(yscrollcommand=malware_scrollbar.set)
malware_scrollbar.config(command=malware_log.yview)
exp_text="Malware signatures are unique identifiers that can be used to identify a particular piece of malware, based on its code or behavior. This searches for malware on network packets."
line_width = 58
lined_text ="\n".join(textwrap.wrap(exp_text, width=line_width))
malware_explanation_label=ttk.Label(attack_detection_frame,text=lined_text,width=48,font=('Arial',8),borderwidth=5,relief='solid')
malware_explanation_label.grid(row=2, column=8,columnspan=2, padx=5, pady=5)

update_attack_logs()

#create frames for network tester
network_tester=traffic_testing.traffic_tester()

left_tests_frame=ttk.Frame(network_testing_frame,style='Custom.TFrame')
left_tests_frame.pack(side=tk.LEFT,padx=5, pady=5)

middle_tests_frame=ttk.Frame(network_testing_frame,style='Custom.TFrame')
middle_tests_frame.pack(side=tk.LEFT,padx=5, pady=5)

right_tests_frame=ttk.Frame(network_testing_frame,style='Custom.TFrame')
right_tests_frame.pack(side=tk.RIGHT,padx=5, pady=5)

#create widgets for left frame
upload_label = tk.Label(left_tests_frame,text="-",font=(40,40) ,image=upload_img,compound='center',border=0,borderwidth=0)
upload_label.grid(row=0, column=0, padx=30, pady=6)

ping_label = tk.Label(left_tests_frame,text="-",font=(40,40), image=ping_img,compound='center',border=0,borderwidth=0)
ping_label.grid(row=1, column=0, padx=30, pady=6)

#create widgets for midlle frame
download_label=tk.Label(middle_tests_frame,text="-",font=(50,50), image=download_img,compound='center',border=0,borderwidth=0)
download_label.grid(row=0, column=0, padx=30, pady=40,sticky='n')

run_network_test_button=ttk.Button(middle_tests_frame,text="Run Test",takefocus=False,padding=(100,20),command=start_network_test)
run_network_test_button.grid(row=1, column=0, padx=30, pady=6)

loading_animation_canvas = tk.Canvas(middle_tests_frame, width=300, height=300,background='gray35',border=0,borderwidth=0,relief='flat', highlightthickness=0, highlightbackground='gray35')
loading_animation_canvas.grid(row=2, column=0, padx=125, pady=6,sticky='e')
frames = [ImageTk.PhotoImage(Image.open(f'loading_gif\\frame({i}).gif').resize((100,100)))for i in range(1, 30)]

#create widgets for right frame
bandwidth_label = tk.Label(right_tests_frame,text="-",font=(40,40), image=bandwidth_img,compound='center',border=0,borderwidth=0)
bandwidth_label.grid(row=0, column=0, padx=30, pady=6)

latency_label = tk.Label(right_tests_frame,text="-",font=(40,40), image=latency_img,compound='center',border=0,borderwidth=0)
latency_label.grid(row=1, column=0, padx=30, pady=6)

#create frames for password checker
password_frame=ttk.Frame(password_testing_frame)
password_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

tests_frame=ttk.Frame(password_testing_frame,borderwidth=6,border=6,relief="groove",padding=5)
tests_frame.pack(fill=tk.X, padx=5, pady=5)

generate_frame=ttk.Frame(password_testing_frame)
generate_frame.pack(side=tk.BOTTOM,fill=tk.X, padx=5, pady=5)

# create widgets for the password frame
pass_tester=password_tester()

your_pass_label=ttk.Label(password_frame,text="Your Password:",font=(15,15))
your_pass_label.grid(row=0, column=0, padx=8, pady=5)

pass_label=tk.Label(password_frame,text=pass_tester.password,font=(15,15))
pass_label.grid(row=0, column=1, padx=8, pady=5)
update_password()

pass_option=tk.BooleanVar(value=False)

ttk.Style().configure('TCheckbutton', font=("arial", 9))
enter_pass_option=ttk.Checkbutton(password_frame,variable=pass_option,text="Wrong / want to test another one?",padding=(0, 0, 0, 0),takefocus=False)
enter_pass_option.grid(row=0, column=2, padx=8, pady=5)

pass_option.trace("w", on_pass_option_changed)

password_entry=ttk.Entry(password_frame,width=35,state="disabled")
password_entry.grid(row=0, column=3, padx=8, pady=5)

no_pass=False
run_pass_test_button=ttk.Button(password_frame,text="Run Test",width=12,image=run_img,compound="right",takefocus=False,command=run_pass_test,state=tk.DISABLED)
run_pass_test_button.grid(row=0, column=4, padx=8, pady=5)

password_frame.place(relx=0.5,rely=0.05,anchor=tk.CENTER)

#create widgets for the tests frame

tests_heading_label=ttk.Label(tests_frame,text="Tests:",font=('times new roman',20))
underline_font = tkFont.Font(tests_heading_label, tests_heading_label.cget("font"))
underline_font.configure(underline = True)
tests_heading_label.configure(font=underline_font)
tests_heading_label.grid(row=0,column=0,padx=5,pady=10,sticky="w")

test1_label=ttk.Label(tests_frame,text="Contains at least 12 characters: ",image=question_img,compound="right",font=(11,11,'bold'))
important1_label=ttk.Label(tests_frame,text="(critical)",style="Red.TLabel",font=(9,9))
test1_label.grid(row=1,column=0,padx=5,pady=8,sticky="w")
important1_label.grid(row=1,column=1,padx=(0,50),pady=8)

test2_label=ttk.Label(tests_frame,text="Contains at least one lower character: ",image=question_img,compound="right",font=(11,11,'bold'))
important2_label=ttk.Label(tests_frame,text="(critical)",style="Red.TLabel",font=(9,9))
test2_label.grid(row=1,column=2,padx=5,pady=8,sticky="w")
important2_label.grid(row=1,column=3,padx=5,pady=8)

test3_label=ttk.Label(tests_frame,text="Contains at least one upper character: ",image=question_img,compound="right",font=(11,11,'bold'))
important3_label=ttk.Label(tests_frame,text="(critical)",style="Red.TLabel",font=(9,9))
test3_label.grid(row=2,column=0,padx=5,pady=8,sticky="w")
important3_label.grid(row=2,column=1,padx=(0,50),pady=8)

test4_label=ttk.Label(tests_frame,text="Contains at least one number: ",image=question_img,compound="right",font=(11,11,'bold'))
important4_label=ttk.Label(tests_frame,text="(critical)",style="Red.TLabel",font=(9,9))
test4_label.grid(row=2,column=2,padx=5,pady=8,sticky="w")
important4_label.grid(row=2,column=3,padx=5,pady=8)

test5_label=ttk.Label(tests_frame,text="Contains at least one special characters: ",image=question_img,compound="right",font=(11,11,'bold'))
important5_label=ttk.Label(tests_frame,text="(critical)",style="Red.TLabel",font=(9,9))
test5_label.grid(row=3,column=0,padx=5,pady=8,sticky="w")
important5_label.grid(row=3,column=1,padx=(0,50),pady=8)

test6_label=ttk.Label(tests_frame,text="Doesn't contain any weak substirngs in it (password,123456,qwerty,admin,letmein): ",image=question_img,compound="right",font=(11,11,'bold'))
important6_label=ttk.Label(tests_frame,text="(important)",style="Orange.TLabel",font=(9,9))
test6_label.grid(row=3,column=2,padx=5,pady=8,sticky="w")
important6_label.grid(row=3,column=3,padx=5,pady=8)

test7_label=ttk.Label(tests_frame,text="Doesnt't contain three or more consecutive identical characters: ",image=question_img,compound="right",font=(11,11,'bold'))
important7_label=ttk.Label(tests_frame,text="(important)",style="Orange.TLabel",font=(9,9))
test7_label.grid(row=4,column=0,padx=5,pady=8,sticky="w")
important7_label.grid(row=4,column=1,padx=(0,50),pady=8)

test8_label=ttk.Label(tests_frame,text="Doesn't contain any three sequential characters: ",image=question_img,compound="right",font=(11,11,'bold'))
important8_label=ttk.Label(tests_frame,text="(important)",style="Orange.TLabel",font=(9,9))
test8_label.grid(row=4,column=2,padx=5,pady=8,sticky="w")
important8_label.grid(row=4,column=3,padx=5,pady=8)

test9_label=ttk.Label(tests_frame,text="Doesn't contain any of the keyboard patterns (qwert,asdfg,zxcvb,poiuy,lkjhgf,mnbvc): ",image=question_img,compound="right",font=(11,11,'bold'))
important9_label=ttk.Label(tests_frame,text="(recommended)",style="Yellow.TLabel",font=(9,9))
test9_label.grid(row=5,column=0,padx=5,pady=8,sticky="w")
important9_label.grid(row=5,column=1,padx=(0,50),pady=8)

test10_label=ttk.Label(tests_frame,text="Doesn't contain a date: ",image=question_img,compound="right",font=(11,11,'bold'))
important10_label=ttk.Label(tests_frame,text="(recommended)",style="Yellow.TLabel",font=(9,9))
test10_label.grid(row=5,column=2,padx=5,pady=8,sticky="w")
important10_label.grid(row=5,column=3,padx=5,pady=8)

test11_label=ttk.Label(tests_frame,text="Wasn't found in a weak passwords list: ",image=question_img,compound="right",font=(11,11,'bold'))
important11_label=ttk.Label(tests_frame,text="(important)",style="Orange.TLabel",font=(9,9))
test11_label.grid(row=6,column=0,padx=5,pady=8,sticky="w")
important11_label.grid(row=6,column=1,padx=(0,50),pady=8)

test12_label=ttk.Label(tests_frame,text="Doesnt contain any dictionary words: ",image=question_img,compound="right",font=(11,11,'bold'))
important12_label=ttk.Label(tests_frame,text="(recommended)",style="Yellow.TLabel",font=(9,9))
test12_label.grid(row=6,column=2,padx=5,pady=8,sticky="w")
important12_label.grid(row=6,column=3,padx=5,pady=8)

test_label_list=[test1_label,test2_label,test3_label,test4_label,test5_label,test6_label,test7_label,test8_label,test9_label,test10_label,test11_label,test12_label]

pass_results_frame=ttk.Frame(tests_frame)
pass_results_frame.grid(row=7,column=0,columnspan=4,padx=0,pady=(20,5),sticky='ew')

separator = ttk.Separator(pass_results_frame, orient='horizontal')
separator.pack(fill=tk.X,padx=0,pady=5)

overall_results_label=ttk.Label(pass_results_frame,text="Overall, the password passed - out of 12 tests:",font=(13,13,'bold'))
overall_results_label.pack(padx=5,pady=5)

critical_results_label=ttk.Label(pass_results_frame,text="-/5 critical tests",style="Red.TLabel",font=(13,13,'bold'))
critical_results_label.pack(padx=5,pady=5)

important_results_label=ttk.Label(pass_results_frame,text="-/4 important tests",style="Orange.TLabel",font=(13,13,'bold'))
important_results_label.pack(padx=5,pady=5)

recommended_results_label=ttk.Label(pass_results_frame,text="-/3 recommended tests",style="Yellow.TLabel",font=(13,13,'bold'))
recommended_results_label.pack(padx=5,pady=5)

changing_recommendation_label=ttk.Label(pass_results_frame,text="   ",font=(13,13,'bold'))
changing_recommendation_label.pack(padx=5,pady=5)

tests_frame.place(relx=0.5,rely=0.45,anchor=tk.CENTER)

#create widgets for the generate frame

generate_heading_label=ttk.Label(generate_frame,text="Strong Password Generation",font=('times new roman',20),anchor=tk.CENTER)
generate_heading_label.configure(font=underline_font)
generate_heading_label.grid(row=0,columnspan=3,padx=8,pady=(5,30))

generated_password_label=ttk.Label(generate_frame,text=pass_tester.generate_password(),font=(20,20),background="aquamarine")
generated_password_label.configure(border=10,borderwidth=10, relief="solid")
generated_password_label.grid(row=1,column=0,padx=8,pady=5)

generete_button=ttk.Button(generate_frame,text="Generate Password",image=run_img,compound="right",takefocus=False,command=generate_password)
generete_button.grid(row=1,column=1,padx=8,pady=5)

copy_generated_password_button=ttk.Button(generate_frame,text="Copy Password",takefocus=False,command=copy_password)
copy_generated_password_button.grid(row=1,column=2,padx=8,pady=5)

generate_frame.place(relx=0.5,rely=0.89,anchor=tk.CENTER)

# create frames for network scanner
scan_frame = ttk.Frame(network_scanner_frame)
scan_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

progress_bar_frame = ttk.Frame(network_scanner_frame)
progress_bar_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5)

devices_frame = ttk.Frame(network_scanner_frame)
devices_frame.pack(side=tk.TOP, fill=tk.BOTH, padx=5, pady=5, expand=True)

# create widgets for the scan frame
scan_button = ttk.Button(scan_frame, text="Scan",width=8,image=run_img,compound="right",takefocus=False)
scan_button.grid(row=0, column=0, padx=5, pady=5)
scan_button.config(command=start_scan)

stop_button = ttk.Button(scan_frame, text="Stop", command=stop_scan,width=8,image=stop_img,compound="right",takefocus=False)
stop_button.grid(row=0, column=1, padx=5, pady=5)
stop_button.config(state=tk.DISABLED)

scan_range_options = ttk.Combobox(scan_frame, values=["Manual", "Full Network"], state="readonly",style="TCombobox",takefocus=False)
scan_range_options.current(1)
scan_range_options.grid(row=0, column=2, padx=5, pady=5)

ip_input = ttk.Entry(scan_frame, width=110)
ip_input.insert(0, "Example: 192.168.1.1-255")
ip_input.grid(row=0, column=3, padx=5, pady=5)
ip_input.config(state=tk.DISABLED)

names_button = ttk.Button(scan_frame, text="Resolve Names",command=resolve_all_names,takefocus=False)
names_button.grid(row=0, column=4, padx=5, pady=5)
names_button.config(state=tk.DISABLED)

ps_button = ttk.Button(scan_frame, text="Scan Popular Ports",command=port_scan_all_devices,takefocus=False)
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

attack_detecter.scanning=False

net_scanner.stop_flag=True

net_scanner.close_all_tools()