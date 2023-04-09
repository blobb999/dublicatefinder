import os
import sys
import zlib
import threading
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from collections import defaultdict
import subprocess
import platform

stop_search = False

def crc32(file_path):
    BUF_SIZE = 65536
    crc = 0

    try:
        with open(file_path, "rb") as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                crc = zlib.crc32(data, crc)
    except PermissionError:
        return None

    return crc & 0xFFFFFFFF

def open_file_in_explorer(file_path):
    directory = os.path.dirname(file_path)

    if platform.system() == "Windows":
        os.startfile(os.path.normpath(directory), 'explore')
    elif platform.system() == "Darwin":
        subprocess.run(["open", directory])
    else:
        subprocess.run(["xdg-open", directory])

def on_double_click_listbox(event):
    listbox = event.widget
    selection = listbox.curselection()
    if selection:
        selected_text = listbox.get(selection[0])
        if not selected_text.startswith("----- Duplicate Group -----"):
            open_file_in_explorer(selected_text)

def find_duplicates(directory, progress_var):
    global stop_search
    file_size_dict = defaultdict(list)
    total_files = 0

    # Group files by their size
    for foldername, subfolders, filenames in os.walk(directory):
        if stop_search:
            break
        for filename in filenames:
            if stop_search:
                break
            file_path = os.path.join(foldername, filename)
            file_size = os.path.getsize(file_path)
            file_size_dict[file_size].append(file_path)
            total_files += 1
            progress_var.set(f"Files processed: {total_files}")

    # Calculate hashes only for files with matching sizes
    hashes = defaultdict(list)
    for file_paths in file_size_dict.values():
        if len(file_paths) > 1:
            for file_path in file_paths:
                if stop_search:
                    break
                file_hash = crc32(file_path)
                if file_hash is not None:
                    hashes[file_hash].append(file_path)

    duplicates = [file_paths for file_paths in hashes.values() if len(file_paths) > 1]

    return duplicates

def browse_directory():
    directory = filedialog.askdirectory(title="Select Directory")
    folder_path.set(directory)

def show_result(duplicates):
    result_window = tk.Toplevel(app)
    result_window.title("Duplicate Files")

    result_frame = tk.Frame(result_window)
    result_frame.pack(fill=tk.BOTH, expand=True)

    x_scrollbar = tk.Scrollbar(result_frame, orient=tk.HORIZONTAL)
    x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

    y_scrollbar = tk.Scrollbar(result_frame)
    y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    listbox = tk.Listbox(result_frame, xscrollcommand=x_scrollbar.set, yscrollcommand=y_scrollbar.set, width=100, height=30)
    for duplicate_group in duplicates:
        listbox.insert(tk.END, "----- Duplicate Group -----")
        for file_path in duplicate_group:
            listbox.insert(tk.END, file_path)
    listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    listbox.bind("<Double-1>", on_double_click_listbox)

    x_scrollbar.config(command=listbox.xview)
    y_scrollbar.config(command=listbox.yview)
    
def start_search():
    global stop_search
    stop_search = False
    directory = folder_path.get()

    def search_thread():
        duplicates = find_duplicates(directory, progress_var)
        if not stop_search:
            if duplicates:
                show_result(duplicates)
            else:
                messagebox.showinfo("Result", "No duplicate files found.")
            progress_var.set("")

    t = threading.Thread(target=search_thread)
    t.start()

def stop_search_handler():
    global stop_search
    stop_search = True

app = tk.Tk()
app.title("Duplicate Files Finder")

folder_path = tk.StringVar()
progress_var = tk.StringVar()

frame = tk.Frame(app)
frame.pack(padx=10, pady=10)

folder_label = tk.Label(frame, text="Directory:")
folder_label.grid(row=0, column=0, sticky="e", pady=(0, 10))

folder_entry = tk.Entry(frame, textvariable=folder_path, width=40)
folder_entry.grid(row=0, column=1, pady=(0, 10))

browse_button = tk.Button(frame, text="Browse", command=browse_directory)
browse_button.grid(row=0, column=2, padx=(10, 0), pady=(0, 10))

search_button = tk.Button(frame, text="Start Search", command=start_search)
search_button.grid(row=1, column=0, pady=(0, 10))

stop_button = tk.Button(frame, text="Stop Search", command=stop_search_handler)
stop_button.grid(row=1, column=1, pady=(0, 10))

progress_label = tk.Label(frame, textvariable=progress_var, width=25, anchor="w")
progress_label.grid(row=1, column=2, padx=(10, 0), pady=(0, 10))

app.mainloop()
