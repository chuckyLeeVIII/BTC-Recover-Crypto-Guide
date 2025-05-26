import os
import string
import tkinter as tk
from tkinter import messagebox
from tkinter import scrolledtext

# Placeholder: this script provides a simple GUI skeleton for recovering
# a wallet and preparing a transfer to a new address. Real blockchain
# interaction would require additional libraries such as `bitcoinlib`
# and access to network nodes. This script focuses on user interaction
# and seed phrase confirmation.

def get_available_drives():
    """Return a list of drive paths for the current platform."""
    drives = []
    if os.name == 'nt':
        try:
            from ctypes import windll
            bitmask = windll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    drives.append(f"{letter}:\\")
                bitmask >>= 1
        except Exception:
            drives = ["C:\\"]
    else:
        drives.append('/')
        for mount in ('/media', '/mnt'):
            if os.path.isdir(mount):
                for entry in os.listdir(mount):
                    drives.append(os.path.join(mount, entry))
    return drives


class DriveSelectionDialog(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title('Select Drives')
        self.selected = []
        self.vars = []
        tk.Label(self, text='Select drives to search for wallets').pack(pady=5)
        for d in get_available_drives():
            var = tk.BooleanVar(value=True)
            cb = tk.Checkbutton(self, text=d, variable=var)
            cb.pack(anchor='w')
            self.vars.append((var, d))
        tk.Button(self, text='Continue', command=self._continue).pack(pady=5)

    def _continue(self):
        self.selected = [d for var, d in self.vars if var.get()]
        if not self.selected:
            messagebox.showerror('Error', 'Select at least one drive')
            return
        self.destroy()


class RecoveryApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Wallet Recovery')
        self.geometry('600x400')

        self.selected_drives = []
        self.show_drive_dialog()
        self.build_main_screen()

    def show_drive_dialog(self):
        dlg = DriveSelectionDialog(self)
        self.wait_window(dlg)
        self.selected_drives = dlg.selected

    def build_main_screen(self):
        
        # Seed phrase entry
        tk.Label(self, text='Enter 24-word seed phrase').pack()
        self.seed_entry = scrolledtext.ScrolledText(self, height=4)
        self.seed_entry.pack(fill=tk.X, padx=5)

        # Private key entry (optional)
        tk.Label(self, text='Or enter a private key (.dat or WIF)').pack()
        self.key_entry = tk.Entry(self, width=80)
        self.key_entry.pack(fill=tk.X, padx=5)

        # New address entry
        tk.Label(self, text='New destination address').pack()
        self.dest_entry = tk.Entry(self, width=80)
        self.dest_entry.pack(fill=tk.X, padx=5)

        tk.Button(self, text='Validate', command=self.validate_inputs).pack(pady=10)
        self.result_label = tk.Label(self, text='')
        self.result_label.pack()

    def validate_inputs(self):
        seed = self.seed_entry.get('1.0', tk.END).strip()
        key = self.key_entry.get().strip()
        dest = self.dest_entry.get().strip()

        if not dest:
            messagebox.showerror('Error', 'Destination address required')
            return

        if seed:
            words = seed.split()
            if len(words) not in (12, 24):
                messagebox.showerror('Error', 'Seed phrase must be 12 or 24 words')
                return
            # confirm specific words for accuracy
            try:
                confirmations = [words[2], words[5], words[8], words[22]]
            except IndexError:
                messagebox.showerror('Error', 'Seed phrase appears incomplete')
                return
            confirm = messagebox.askquestion(
                'Confirm Words',
                f"Please confirm words 3, 6, 9, and 23:\n{confirmations}"
            )
            if confirm != 'yes':
                return
        elif not key:
            messagebox.showerror('Error', 'Seed phrase or private key required')
            return

        messagebox.showinfo(
            'Success',
            'Inputs validated. Prepare transaction offline using your preferred library.'
        )
        self.result_label.config(text='Verified. Create and sign transaction using external tools.')

if __name__ == '__main__':
    app = RecoveryApp()
    app.mainloop()
