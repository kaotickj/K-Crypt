# filename: secure_xor_gui.py

import os
import base64
import json
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import stat

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_AVAILABLE = True
except ImportError:
    DND_AVAILABLE = False
    print("[Warning] tkinterDnD2 not installed. Drag-and-drop support disabled.")

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC_HEADER = b"XENC001\n"
KEYFILE_NAME = ".dmrc"

# Hardcoded 32-byte (256-bit) AES key - replace with your own securely generated key
HARDCODED_AES_KEY = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88'

class XORCipher:
    def __init__(self, key: str):
        self.key = key

    def process(self, data: bytes) -> bytes:
        key_len = len(self.key)
        return bytes([b ^ ord(self.key[i % key_len]) for i, b in enumerate(data)])

    def encrypt_file(self, path: str):
        with open(path, 'rb') as f:
            original_data = f.read()

        if original_data.startswith(MAGIC_HEADER):
            raise ValueError("File is already encrypted.")

        encrypted = MAGIC_HEADER + self.process(original_data)

        with open(path, 'wb') as f:
            f.write(encrypted)

    def decrypt_file(self, path: str):
        with open(path, 'rb') as f:
            data = f.read()

        if not data.startswith(MAGIC_HEADER):
            raise ValueError("File is not encrypted with this tool.")

        decrypted = self.process(data[len(MAGIC_HEADER):])

        with open(path, 'wb') as f:
            f.write(decrypted)

class KeyManager:
    def __init__(self, key: str):
        self.key = key

    def save_key(self, directory: str):
        aesgcm = AESGCM(HARDCODED_AES_KEY)
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, self.key.encode(), None)

        data = {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(encrypted).decode()
        }

        path = os.path.join(directory, KEYFILE_NAME)
        with open(path, 'w') as f:
            json.dump(data, f)
        os.chmod(path, 0o600)

    @staticmethod
    def load_key(directory: str):
        path = directory if os.path.isdir(directory) else os.path.dirname(directory)
        path = os.path.join(path, KEYFILE_NAME)
        if not os.path.exists(path):
            return None

        with open(path, 'r') as f:
            data = json.load(f)

        nonce = base64.b64decode(data["nonce"])
        ciphertext = base64.b64decode(data["ciphertext"])

        aesgcm = AESGCM(HARDCODED_AES_KEY)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)

        return decrypted.decode()

def is_document_file(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    return ext not in ('', '.dmrc')

def preserve_timestamps(func):
    def wrapper(*args, **kwargs):
        filepath = args[1]
        statinfo = os.stat(filepath)
        result = func(*args, **kwargs)
        os.utime(filepath, (statinfo.st_atime, statinfo.st_mtime))
        return result
    return wrapper

@preserve_timestamps
def safe_encrypt(cipher: XORCipher, filepath: str):
    cipher.encrypt_file(filepath)

@preserve_timestamps
def safe_decrypt(cipher: XORCipher, filepath: str):
    cipher.decrypt_file(filepath)

class SecureXORGUI:
    def __init__(self, master):
        self.master = master
        master.title("K-Crypt")

        self.menubar = tk.Menu(master)
        master.config(menu=self.menubar)

        file_menu = tk.Menu(self.menubar, tearoff=0)
        file_menu.add_command(label="Browse File", command=self.browse_file_menu)
        file_menu.add_command(label="Browse Folder", command=self.browse_folder_menu)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=master.quit)
        self.menubar.add_cascade(label="File", menu=file_menu)

        self.mode = tk.StringVar(value="encrypt")
        mode_menu = tk.Menu(self.menubar, tearoff=0)
        mode_menu.add_radiobutton(label="Encrypt", variable=self.mode, value="encrypt")
        mode_menu.add_radiobutton(label="Decrypt", variable=self.mode, value="decrypt")
        self.menubar.add_cascade(label="Mode", menu=mode_menu)

        help_menu = tk.Menu(self.menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        self.menubar.add_cascade(label="Help", menu=help_menu)

        self.file_mode = tk.BooleanVar(value=False)

        tk.Label(master, text="File/Folder Path:").grid(row=0, column=0, sticky='e')
        self.path_entry = tk.Entry(master, width=60)
        self.path_entry.grid(row=0, column=1)
        tk.Button(master, text="Browse", command=self.browse).grid(row=0, column=2)

        if DND_AVAILABLE:
            self.path_entry.drop_target_register(DND_FILES)
            self.path_entry.dnd_bind('<<Drop>>', self.drop_path)

        tk.Label(master, text="Key:").grid(row=1, column=0, sticky='e')
        self.key_entry = tk.Entry(master, show='*', width=60)
        self.key_entry.grid(row=1, column=1)

        tk.Checkbutton(master, text="Single File Mode", variable=self.file_mode).grid(row=2, column=1, sticky='w')
        tk.Radiobutton(master, text="Encrypt", variable=self.mode, value="encrypt").grid(row=3, column=0)
        tk.Radiobutton(master, text="Decrypt", variable=self.mode, value="decrypt").grid(row=3, column=1, sticky='w')

        self.progress = ttk.Progressbar(master, length=400, mode='determinate')
        self.progress.grid(row=4, column=0, columnspan=3, pady=5)

        tk.Button(master, text="Start", command=self.start).grid(row=5, column=1, pady=10)

        self.log = scrolledtext.ScrolledText(master, width=80, height=10)
        self.log.grid(row=6, column=0, columnspan=3, pady=5)

    def browse_file_menu(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_mode.set(True)
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, path)

    def browse_folder_menu(self):
        path = filedialog.askdirectory()
        if path:
            self.file_mode.set(False)
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, path)

    def show_about(self):
        messagebox.showinfo("About Secure XOR Encryptor",
                            "K-Crypt\n"
                            "Version 1.0\n"
                            "Author: KaotickJ\n\n"
                            "Encrypts files or folders with XOR and AES-GCM protected key storage.")

    def log_message(self, msg):
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)

    def browse(self):
        if self.file_mode.get():
            path = filedialog.askopenfilename()
        else:
            path = filedialog.askdirectory()
        if path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, path)

    def drop_path(self, event):
        self.path_entry.delete(0, tk.END)
        self.path_entry.insert(0, event.data.strip('{').strip('}'))

    def start(self):
        path = self.path_entry.get().strip()
        key = self.key_entry.get().strip()

        if not path:
            messagebox.showerror("Error", "No path selected.")
            return

        if self.mode.get() == "encrypt" and not key:
            messagebox.showerror("Error", "Encryption key is required.")
            return

        try:
            if not key and self.mode.get() == "decrypt":
                key = KeyManager.load_key(path)
                if not key:
                    raise ValueError("No key provided and .dmrc not found.")

            cipher = XORCipher(key)

            if self.file_mode.get():
                files = [path]
            else:
                files = []
                for root, _, filenames in os.walk(path):
                    for fname in filenames:
                        full_path = os.path.join(root, fname)
                        if is_document_file(full_path):
                            files.append(full_path)

            self.progress['maximum'] = len(files)
            self.progress['value'] = 0

            for i, file in enumerate(files):
                try:
                    if self.mode.get() == "encrypt":
                        safe_encrypt(cipher, file)
                    else:
                        safe_decrypt(cipher, file)
                    self.log_message(f"{self.mode.get().capitalize()}ed: {file}")
                except Exception as e:
                    self.log_message(f"Error on {file}: {str(e)}")
                self.progress['value'] = i + 1
                self.master.update_idletasks()

            if self.mode.get() == "encrypt":
                key_save_path = os.path.dirname(path) if self.file_mode.get() else path
                KeyManager(key).save_key(key_save_path)
            elif self.mode.get() == "decrypt":
                keyfile = os.path.join(path if os.path.isdir(path) else os.path.dirname(path), KEYFILE_NAME)
                if os.path.exists(keyfile):
                    try:
                        os.remove(keyfile)
                        self.log_message(f"Deleted key file: {keyfile}")
                    except Exception as e:
                        self.log_message(f"Warning: Failed to delete {keyfile}: {e}")

            messagebox.showinfo("Done", f"{self.mode.get().capitalize()}ion complete.")

        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == '__main__':
    root = TkinterDnD.Tk() if DND_AVAILABLE else tk.Tk()
    app = SecureXORGUI(root)
    root.mainloop()
