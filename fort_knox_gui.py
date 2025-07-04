import os
import tkinter as tk
from tkinter import messagebox, filedialog

# This script offers a minimal interface for creating CPFP or RBF
# transactions or preparing a standard send command for Bitcoin Core.
# It does not broadcast transactions by itself but simply shows the
# command that should be executed in your local Core node.


class CoreTxApp(tk.Tk):
    """Local GUI for preparing Bitcoin Core commands."""

    def __init__(self):
        super().__init__()
        self.title('Core Transaction Tools')
        self.geometry('600x350')

        # Menu for searching wallet files
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label='Search Wallets...', command=self.search_wallets)
        menubar.add_cascade(label='File', menu=file_menu)
        self.config(menu=menubar)

        tk.Label(self, text='Action').pack()
        self.method_var = tk.StringVar(value='CPFP')
        methods = ['CPFP', 'RBF', 'Send']
        tk.OptionMenu(self, self.method_var, *methods).pack(fill=tk.X)

        # Transaction or parent txid
        tk.Label(self, text='TXID / Parent TXID').pack()
        self.txid_entry = tk.Entry(self, width=80)
        self.txid_entry.pack(fill=tk.X, padx=5)

        tk.Label(self, text='Destination address').pack()
        self.dest_entry = tk.Entry(self, width=80)
        self.dest_entry.pack(fill=tk.X, padx=5)

        tk.Label(self, text='Amount (BTC)').pack()
        self.amount_entry = tk.Entry(self, width=80)
        self.amount_entry.pack(fill=tk.X, padx=5)

        tk.Label(self, text='Fee rate (sat/vB)').pack()
        self.fee_entry = tk.Entry(self, width=80)
        self.fee_entry.pack(fill=tk.X, padx=5)

        tk.Button(self, text='Prepare', command=self.run_action).pack(pady=10)
        self.result_label = tk.Label(self, text='')
        self.result_label.pack()

    def search_wallets(self):
        """Search selected folder for wallet files."""
        folder = filedialog.askdirectory(title='Select folder to search')
        if not folder:
            return
        matches = []
        for root_dir, _dirs, files in os.walk(folder):
            for name in files:
                lower = name.lower()
                if lower == 'wallet.dat' or lower.endswith('.wallet') or lower.endswith('.json'):
                    matches.append(os.path.join(root_dir, name))
        if matches:
            msg = 'Found wallet files:\n' + '\n'.join(matches)
        else:
            msg = 'No wallet files found.'
        messagebox.showinfo('Search Results', msg)

    def run_action(self):
        """Show a bitcoin-cli command based on the selected method."""

        method = self.method_var.get()
        txid = self.txid_entry.get().strip()
        dest = self.dest_entry.get().strip()
        amount = self.amount_entry.get().strip()
        fee = self.fee_entry.get().strip()

        if method == 'Send':
            if not dest or not amount:
                messagebox.showerror('Error', 'Destination and amount required')
                return
            cmd = f"bitcoin-cli sendtoaddress {dest} {amount} fee_rate={fee}"
        elif method == 'CPFP':
            if not txid or not dest:
                messagebox.showerror('Error', 'Parent TXID and destination required')
                return
            cmd = f"bitcoin-cli cpfp {txid} {dest} fee_rate={fee}"
        else:  # RBF
            if not txid:
                messagebox.showerror('Error', 'TXID required for RBF')
                return
            cmd = f"bitcoin-cli bumpfee {txid} fee_rate={fee}"

        self.result_label.config(text=cmd)
        messagebox.showinfo('Prepared', cmd)

if __name__ == '__main__':
    app = CoreTxApp()
    app.mainloop()
