import tkinter as tk
from tkinter import ttk

root=tk.Tk()
root.title("ee")

table=ttk.Treeview(root, columns=["1","2","3"], show="headings", height=31)
table.pack()
table.insert("","end",text="---",values=["","",""])
table.tag_configure("oddrow", foreground="red")

root.mainloop()