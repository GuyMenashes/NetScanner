import PySimpleGUI as sg
from network_scanner import network_scanner
import threading
import get_net_info

def main_window():
    my_ip=get_net_info.get_ip_info()[0]
    router_ip=get_net_info.get_ip_info()[1]

    #define table before aplying theme
    headings=["name                 ","ip            ","mac                  ","mac vendor                       ",'Data Transfered           ']
    device_table=sg.Table([],
                        headings,
                        background_color="white",
                        text_color="Black",
                        header_background_color="white",
                        size=(10,31),
                        right_click_selects=True,
                        justification="left",
                        key="DEVICE_TABLE",
                        selected_row_colors=('black','sky blue'),
                        alternating_row_color="light blue",
                        border_width=2,
                        sbar_background_color="ivory3",
                        right_click_menu = ['&Right', ["Try to resolve name","Port scan"]],
                        enable_events=True)
    selected_table_row=0

    sg.theme("Default1")
    font_family="Courior New"
    font_size=14
    sg.set_options(font=(font_family,font_size))

    menu_def=[["File",["Exit"]],["Settings",[]],["Help",[]]]

    first_frame=[[sg.Button("Scan",size=(7,1)),sg.Combo(["Menual","Full Network"],size=(15,10),readonly=True,default_value="Full Network",key="SCAN_RANGE_OPTIONS",enable_events=True),sg.Input(visible=False,s=80,key="IP_INPUT",default_text="Example: 192.168.1.1-255")]]

    layout=[[sg.MenuBar(menu_def)],
            [sg.Frame('',first_frame,background_color="gray89",size=(10000,40),pad=0,border_width=0)],
            [device_table],
            [sg.ProgressBar(max_value=20, orientation='h', size=(137, 20), key='LOADING_BAR',bar_color=("green2","white"))]]

    bar_value=0

    window=sg.Window("NetScanner",layout,resizable=True,margins=(0,0)).Finalize()
    window.Maximize()

    net_scanner=network_scanner()
    scanning=False
    while True:
        event,values=window.read(timeout=100)

        if window.is_closed():
            break

        if event and event in [sg.WINDOW_CLOSED,"Exit"]:
            break
            
        if event and event=="Scan":
            if not scanning:
                window.Element("DEVICE_TABLE").update(values=[])
                scan_thr=threading.Thread(target=net_scanner.scan_network)
                scan_thr.start()
                scanning=True
        
        if event and event =="SCAN_RANGE_OPTIONS":
            if values["SCAN_RANGE_OPTIONS"]=="Menual":
                window.Element("IP_INPUT").update("Example: 192.168.1.1-255",visible=True)
            else:
                window.Element("IP_INPUT").update(visible=False)

        if event == 'DEVICE_TABLE':
            if len(values['DEVICE_TABLE'])!=0:
                selected_table_row=values['DEVICE_TABLE'][0]
        
        if event=="Try to resolve name":
            name_thr=threading.Thread(target=net_scanner.devices[selected_table_row].resolve_name)
            name_thr.start()
        
        if event =="Port scan":
            ps_thr=threading.Thread(target=net_scanner.devices[selected_table_row].port_scan)
            ps_thr.start()
        
        #Check if finished scanning and add devices to the table
        if scanning and not scan_thr.is_alive():
            bar_value=0
            window.Element('LOADING_BAR').update(0)
            devices_detailes=[]
            for device in net_scanner.devices:
                added=''
                if device.ip==my_ip:
                    added=' (You)'
                elif device.ip==router_ip:
                    added=' (Default Gateway)'

                devices_detailes.extend([[device.name+added,device.ip,device.mac,device.mac_vendor,f'{device.data_transfered} Bytes'],["   Open Ports:"]])

            window.Element("DEVICE_TABLE").update(values=devices_detailes)
        
        elif scanning:
            bar_value+=1
            window.Element('LOADING_BAR').update(bar_value)
            if bar_value>20:
                bar_value=0

        net_scanner.update_data_transfered()

    net_scanner.close_all_tools()
    window.close()

if __name__=="__main__":
    main_window()