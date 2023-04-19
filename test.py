import tkinter as tk
from tkinter import filedialog
import shutil

def save_file():
    # Set the path to the example file
    example_file_path = "test.pcap"

    # Prompt the user to choose a location to save the file
    file_path = filedialog.asksaveasfilename(defaultextension=".pcap")
    if file_path:
        # Copy the example file to the chosen location
        shutil.copy(example_file_path, file_path)

root = tk.Tk()

root.title("Save Pcap File")

# Create a button widget to save the file
save_button = tk.Button(root, text="Save Pcap File", command=save_file)
save_button.pack(padx=10, pady=10)

root.mainloop()