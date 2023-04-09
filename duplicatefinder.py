import os
import sys
import zlib
import threading
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from collections import defaultdict
import subprocess
import platform
import concurrent.futures

BUF_SIZE = 65536
stop_search = False

class DuplicateFilesFinder:
    def __init__(self):
        self.setup_ui()

    def setup_ui(self):
        app = tk.Tk()
        app.title("Duplicate Files Finder")

        app.columnconfigure(0, weight=1)
        app.rowconfigure(1, weight=1)

        self.folder_path = tk.StringVar()
        self.files_processed_var = tk.StringVar()
        self.current_file_var = tk.StringVar()
        self.duplicated_files_var = tk.StringVar()

        frame = tk.Frame(app)
        frame.grid(row=0, column=0, sticky="nsew")

        for i in range(3):
            frame.columnconfigure(i, weight=1)
        frame.rowconfigure(3, weight=1)

        self.create_widgets(frame, app)

        app.mainloop()

    def create_widgets(self, frame, app):
        folder_label = tk.Label(frame, text="Directory:")
        folder_label.grid(row=0, column=0, sticky="e", pady=(0, 10))

        folder_entry = tk.Entry(frame, textvariable=self.folder_path, width=40)
        folder_entry.grid(row=0, column=1, pady=(0, 10))

        browse_button = tk.Button(frame, text="Browse", command=self.browse_directory)
        browse_button.grid(row=0, column=2, padx=(10, 0), pady=(0, 10))

        search_button = tk.Button(frame, text="Start Search", command=self.start_search)
        search_button.grid(row=1, column=0, pady=(0, 10))

        stop_button = tk.Button(frame, text="Stop Search", command=self.stop_search_handler)
        stop_button.grid(row=1, column=1, pady=(0, 10))

        files_processed_label = tk.Label(frame, textvariable=self.files_processed_var, width=25, anchor="w")
        files_processed_label.grid(row=1, column=2, padx=(10, 0), pady=(0, 10))

        duplicated_files_label = tk.Label(frame, textvariable=self.duplicated_files_var, width=25, anchor="w")
        duplicated_files_label.grid(row=2, column=2, padx=(10, 0), pady=(0, 10))

        current_file_label = tk.Label(frame, textvariable=self.current_file_var, width=40, anchor="w")
        current_file_label.grid(row=2, column=1, pady=(0, 10))

        listbox_frame = tk.Frame(app)
        listbox_frame.grid(row=1, column=0, sticky="nsew")

        x_scrollbar = tk.Scrollbar(listbox_frame, orient=tk.HORIZONTAL)
        x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

        y_scrollbar = tk.Scrollbar(listbox_frame)
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.listbox = tk.Listbox(listbox_frame, xscrollcommand=x_scrollbar.set, yscrollcommand=y_scrollbar.set)
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.listbox.bind("<Double-1>", self.on_double_click_listbox)

        x_scrollbar.config(command=self.listbox.xview)
        y_scrollbar.config(command=self.listbox.yview)

        sizegrip = tk.ttk.Sizegrip(app)
        sizegrip.grid(row=2, column=0, sticky="se")

    def crc32(self, file_path):
        crc = 0

        try:
            with open(file_path, "rb") as f:
                while True:
                    data = f.read(BUF_SIZE)
                    if not data:
                        break
                    crc = zlib.crc32(data, crc)
        except (PermissionError, OSError):
            return None

        return crc & 0xFFFFFFFF

    def hash_files(self, file_paths):
        hashes = defaultdict(list)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {executor.submit(self.crc32, file_path): file_path for file_path in file_paths}
            for future in concurrent.futures.as_completed(futures):
                file_path = futures[future]
                file_hash = future.result()
                if file_hash is not None:
                    hashes[file_hash].append(file_path)
        return hashes

    def open_file_in_explorer(self, file_path):
        directory = os.path.dirname(file_path)

        if platform.system() == "Windows":
            os.startfile(os.path.normpath(directory), 'explore')
        elif platform.system() == "Darwin":
            subprocess.run(["open", directory])
        else:
            subprocess.run(["xdg-open", directory])

    def on_double_click_listbox(self, event):
        listbox = event.widget
        selection = listbox.curselection()
        if selection:
            selected_text = listbox.get(selection[0])
            if not selected_text.startswith("----- Duplicate Group -----"):
                self.open_file_in_explorer(selected_text)

    def find_duplicates(self, directory):
        global stop_search
        file_size_dict = defaultdict(list)
        total_files = 0
        duplicated_files_count = 0

        for foldername, subfolders, filenames in os.walk(directory):
            if stop_search:
                break
            for filename in filenames:
                if stop_search:
                    break
                file_path = os.path.join(foldername, filename)
                try:
                    file_size = os.path.getsize(file_path)
                    file_size_dict[file_size].append(file_path)
                except OSError as e:
                    print(f"Error getting file size for {file_path}: {e}")
                total_files += 1
                self.files_processed_var.set(f"Files processed: {total_files}")
                self.current_file_var.set(f"Current file: {os.path.basename(file_path)}")

        hashes = defaultdict(list)
        for file_paths in file_size_dict.values():
            if len(file_paths) > 1:
                if stop_search:
                    break
                file_hashes = self.hash_files(file_paths)
                for file_hash, hashed_file_paths in file_hashes.items():
                    hashes[file_hash].extend(hashed_file_paths)
                    if len(hashed_file_paths) > 1:
                        duplicated_files_count += len(hashed_file_paths) - 1
                        self.duplicated_files_var.set(f"Duplicated files: {duplicated_files_count}")
                        self.add_duplicates_to_listbox([hashed_file_paths])

        return hashes

    def browse_directory(self):
        directory = filedialog.askdirectory(title="Select Directory")
        self.folder_path.set(directory)

    def add_duplicates_to_listbox(self, duplicates):
        for duplicate_group in duplicates:
            self.listbox.insert(tk.END, "----- Duplicate Group -----")
            for file_path in duplicate_group:
                self.listbox.insert(tk.END, file_path)

    def start_search(self):
        global stop_search
        stop_search = False
        directory = self.folder_path.get()

        # Reset the variables for a new search
        self.files_processed_var.set("Files processed: 0")
        self.duplicated_files_var.set("Duplicated files: 0")
        self.current_file_var.set("")

        def search_thread():
            self.listbox.delete(0, tk.END)
            self.find_duplicates(directory)
            if not stop_search:
                self.current_file_var.set("")

        t = threading.Thread(target=search_thread)
        t.start()

    def stop_search_handler(self):
        global stop_search
        stop_search = True

if __name__ == "__main__":
    DuplicateFilesFinder()
