import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import scrolledtext
import os

# Placeholder: this script provides a simple GUI skeleton for recovering
# a wallet and preparing a transfer to a new address. Real blockchain
# interaction would require additional libraries such as `bitcoinlib`
# and access to network nodes. This script focuses on user interaction
# and seed phrase confirmation.

class RecoveryApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Wallet Recovery')
        self.geometry('600x400')

        # Menu bar with a search option
        menu_bar = tk.Menu(self)
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label='Search Wallets...', command=self.search_wallets)
        file_menu.add_separator()
        file_menu.add_command(label='Exit', command=self.quit)
        menu_bar.add_cascade(label='File', menu=file_menu)
        self.config(menu=menu_bar)

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

    def search_wallets(self):
        """Search selected directory for common wallet file names."""
        directory = filedialog.askdirectory(title='Select folder to search')
        if not directory:
            return
        wallet_files = []
        for root_dir, _, files in os.walk(directory):
            for name in files:
                lower = name.lower()
                if lower in ('wallet.dat',) or lower.endswith(('.wallet', '.dat')):
                    wallet_files.append(os.path.join(root_dir, name))
        if wallet_files:
            messagebox.showinfo('Wallets Found', '\n'.join(wallet_files))
        else:
            messagebox.showinfo('Wallets Found', 'No wallet files found.')

if __name__ == '__main__':
    app = RecoveryApp()
    app.mainloop()
