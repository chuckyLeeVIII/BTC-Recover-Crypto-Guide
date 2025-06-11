"""
Graphical User Interface for Blockchain Recovery System
Provides a user-friendly interface for wallet recovery operations
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import json
from datetime import datetime
from typing import Optional, Dict, Any
import logging

from blockchain_recovery import BlockchainRecoverySystem, RecoveredAsset
from security_utils import SecureStorage, KeyValidator, AuditLogger

class RecoveryGUI:
    """Main GUI application for blockchain recovery"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Blockchain Recovery System")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Initialize components
        self.recovery_system = None
        self.audit_logger = AuditLogger()
        self.recovered_assets = []
        
        # Setup GUI
        self._setup_styles()
        self._create_widgets()
        self._setup_logging()
        
        # Security features
        self.session_active = False
        self.max_attempts = 3
        self.current_attempts = 0
    
    def _setup_styles(self):
        """Configure GUI styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure custom styles
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Heading.TLabel', font=('Arial', 12, 'bold'))
        style.configure('Success.TLabel', foreground='green')
        style.configure('Error.TLabel', foreground='red')
        style.configure('Warning.TLabel', foreground='orange')
    
    def _create_widgets(self):
        """Create and layout GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Blockchain Recovery System", style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Recovery method selection
        method_frame = ttk.LabelFrame(main_frame, text="Recovery Method", padding="10")
        method_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        method_frame.columnconfigure(1, weight=1)
        
        self.recovery_method = tk.StringVar(value="mnemonic")
        
        ttk.Radiobutton(method_frame, text="BIP39 Mnemonic Phrase", 
                       variable=self.recovery_method, value="mnemonic",
                       command=self._on_method_change).grid(row=0, column=0, sticky=tk.W)
        
        ttk.Radiobutton(method_frame, text="Private Key", 
                       variable=self.recovery_method, value="private_key",
                       command=self._on_method_change).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Radiobutton(method_frame, text="Wallet File", 
                       variable=self.recovery_method, value="wallet_file",
                       command=self._on_method_change).grid(row=0, column=2, sticky=tk.W)
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Recovery Input", padding="10")
        input_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        input_frame.columnconfigure(1, weight=1)
        
        # Mnemonic input
        self.mnemonic_frame = ttk.Frame(input_frame)
        self.mnemonic_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E))
        self.mnemonic_frame.columnconfigure(1, weight=1)
        
        ttk.Label(self.mnemonic_frame, text="Mnemonic Phrase:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.mnemonic_text = scrolledtext.ScrolledText(self.mnemonic_frame, height=3, width=50)
        self.mnemonic_text.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 5))
        
        # Private key input
        self.private_key_frame = ttk.Frame(input_frame)
        self.private_key_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E))
        self.private_key_frame.columnconfigure(1, weight=1)
        
        ttk.Label(self.private_key_frame, text="Private Key:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.private_key_entry = ttk.Entry(self.private_key_frame, show="*", width=70)
        self.private_key_entry.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 5))
        
        ttk.Label(self.private_key_frame, text="Key Type:").grid(row=2, column=0, sticky=tk.W, pady=(5, 0))
        self.key_type_var = tk.StringVar(value="auto")
        key_type_combo = ttk.Combobox(self.private_key_frame, textvariable=self.key_type_var,
                                     values=["auto", "bitcoin", "ethereum"], state="readonly")
        key_type_combo.grid(row=2, column=1, sticky=tk.W, pady=(5, 0))
        
        # Wallet file input
        self.wallet_file_frame = ttk.Frame(input_frame)
        self.wallet_file_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E))
        self.wallet_file_frame.columnconfigure(1, weight=1)
        
        ttk.Label(self.wallet_file_frame, text="Wallet File:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.wallet_file_var = tk.StringVar()
        ttk.Entry(self.wallet_file_frame, textvariable=self.wallet_file_var, state="readonly").grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        ttk.Button(self.wallet_file_frame, text="Browse", command=self._browse_wallet_file).grid(row=1, column=1, padx=(5, 0))
        
        # Network configuration
        network_frame = ttk.LabelFrame(main_frame, text="Network Configuration", padding="10")
        network_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        network_frame.columnconfigure(1, weight=1)
        network_frame.columnconfigure(3, weight=1)
        
        ttk.Label(network_frame, text="Bitcoin Network:").grid(row=0, column=0, sticky=tk.W)
        self.btc_network_var = tk.StringVar(value="bitcoin")
        btc_network_combo = ttk.Combobox(network_frame, textvariable=self.btc_network_var,
                                        values=["bitcoin", "testnet"], state="readonly")
        btc_network_combo.grid(row=0, column=1, sticky=tk.W, padx=(5, 20))
        
        ttk.Label(network_frame, text="Ethereum RPC:").grid(row=0, column=2, sticky=tk.W)
        self.eth_rpc_var = tk.StringVar(value="https://mainnet.infura.io/v3/YOUR_PROJECT_ID")
        eth_rpc_entry = ttk.Entry(network_frame, textvariable=self.eth_rpc_var, width=40)
        eth_rpc_entry.grid(row=0, column=3, sticky=(tk.W, tk.E), padx=(5, 0))
        
        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=(0, 10))
        
        self.scan_button = ttk.Button(button_frame, text="Scan for Assets", command=self._start_scan)
        self.scan_button.grid(row=0, column=0, padx=(0, 10))
        
        self.validate_button = ttk.Button(button_frame, text="Validate Input", command=self._validate_input)
        self.validate_button.grid(row=0, column=1, padx=(0, 10))
        
        self.consolidate_button = ttk.Button(button_frame, text="Consolidate Funds", 
                                           command=self._start_consolidation, state="disabled")
        self.consolidate_button.grid(row=0, column=2)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Results area
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        results_frame.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(6, weight=1)
        
        # Results tree
        self.results_tree = ttk.Treeview(results_frame, columns=('Type', 'Address', 'Balance', 'Status'), show='headings')
        self.results_tree.heading('Type', text='Asset Type')
        self.results_tree.heading('Address', text='Address')
        self.results_tree.heading('Balance', text='Balance')
        self.results_tree.heading('Status', text='Status')
        
        self.results_tree.column('Type', width=80)
        self.results_tree.column('Address', width=300)
        self.results_tree.column('Balance', width=120)
        self.results_tree.column('Status', width=100)
        
        self.results_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Scrollbar for results
        results_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        results_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.results_tree.configure(yscrollcommand=results_scrollbar.set)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E))
        
        # Initially hide non-selected input methods
        self._on_method_change()
    
    def _setup_logging(self):
        """Setup logging for GUI"""
        # Create a custom handler to display logs in GUI
        class GUILogHandler(logging.Handler):
            def __init__(self, status_var):
                super().__init__()
                self.status_var = status_var
            
            def emit(self, record):
                msg = self.format(record)
                self.status_var.set(msg)
        
        # Add GUI handler to root logger
        gui_handler = GUILogHandler(self.status_var)
        gui_handler.setLevel(logging.INFO)
        logging.getLogger().addHandler(gui_handler)
    
    def _on_method_change(self):
        """Handle recovery method change"""
        method = self.recovery_method.get()
        
        # Hide all frames
        self.mnemonic_frame.grid_remove()
        self.private_key_frame.grid_remove()
        self.wallet_file_frame.grid_remove()
        
        # Show selected frame
        if method == "mnemonic":
            self.mnemonic_frame.grid()
        elif method == "private_key":
            self.private_key_frame.grid()
        elif method == "wallet_file":
            self.wallet_file_frame.grid()
    
    def _browse_wallet_file(self):
        """Browse for wallet file"""
        filename = filedialog.askopenfilename(
            title="Select Wallet File",
            filetypes=[
                ("Wallet files", "*.wallet *.dat *.json"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.wallet_file_var.set(filename)
    
    def _validate_input(self):
        """Validate user input"""
        method = self.recovery_method.get()
        
        try:
            if method == "mnemonic":
                mnemonic = self.mnemonic_text.get("1.0", tk.END).strip()
                if not mnemonic:
                    messagebox.showerror("Error", "Please enter a mnemonic phrase")
                    return
                
                # Validate mnemonic
                from bitcoinlib.mnemonic import Mnemonic
                if not Mnemonic().check(mnemonic):
                    messagebox.showerror("Error", "Invalid mnemonic phrase")
                    return
                
                messagebox.showinfo("Success", "Mnemonic phrase is valid")
                
            elif method == "private_key":
                private_key = self.private_key_entry.get().strip()
                key_type = self.key_type_var.get()
                
                if not private_key:
                    messagebox.showerror("Error", "Please enter a private key")
                    return
                
                # Validate private key
                validation_result = KeyValidator.validate_private_key_strength(private_key, key_type)
                
                if not validation_result['is_valid']:
                    messagebox.showerror("Error", "Invalid private key format")
                    return
                
                # Show validation results
                message = f"Private key is valid\nStrength Score: {validation_result['strength_score']}/100"
                if validation_result['warnings']:
                    message += f"\nWarnings: {', '.join(validation_result['warnings'])}"
                
                messagebox.showinfo("Validation Result", message)
                
            elif method == "wallet_file":
                wallet_file = self.wallet_file_var.get()
                if not wallet_file:
                    messagebox.showerror("Error", "Please select a wallet file")
                    return
                
                import os
                if not os.path.exists(wallet_file):
                    messagebox.showerror("Error", "Wallet file does not exist")
                    return
                
                messagebox.showinfo("Success", "Wallet file is accessible")
                
        except Exception as e:
            messagebox.showerror("Validation Error", f"Error during validation: {str(e)}")
    
    def _start_scan(self):
        """Start asset scanning in background thread"""
        # Disable buttons during scan
        self.scan_button.config(state="disabled")
        self.consolidate_button.config(state="disabled")
        self.progress.start()
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Start scanning thread
        thread = threading.Thread(target=self._perform_scan)
        thread.daemon = True
        thread.start()
    
    def _perform_scan(self):
        """Perform asset scanning (runs in background thread)"""
        try:
            # Initialize recovery system
            self.recovery_system = BlockchainRecoverySystem(
                btc_network=self.btc_network_var.get(),
                eth_rpc_url=self.eth_rpc_var.get() if self.eth_rpc_var.get() != "https://mainnet.infura.io/v3/YOUR_PROJECT_ID" else None
            )
            
            method = self.recovery_method.get()
            assets = []
            
            if method == "mnemonic":
                mnemonic = self.mnemonic_text.get("1.0", tk.END).strip()
                assets = self.recovery_system.recover_from_mnemonic(mnemonic)
                
            elif method == "private_key":
                private_key = self.private_key_entry.get().strip()
                key_type = self.key_type_var.get()
                assets = self.recovery_system.recover_from_private_key(private_key, key_type)
            
            # Store recovered assets
            self.recovered_assets = assets
            
            # Update GUI in main thread
            self.root.after(0, self._update_results, assets)
            
        except Exception as e:
            self.root.after(0, self._show_error, f"Scan error: {str(e)}")
        finally:
            self.root.after(0, self._scan_complete)
    
    def _update_results(self, assets):
        """Update results display"""
        for asset in assets:
            status = "Found"
            if asset.is_staked:
                status = "Staked"
            elif asset.is_locked:
                status = "Locked"
            
            self.results_tree.insert('', 'end', values=(
                asset.asset_type,
                asset.address,
                f"{asset.balance:.8f}",
                status
            ))
        
        # Update status
        total_btc = sum(a.balance for a in assets if a.asset_type == 'BTC')
        total_eth = sum(a.balance for a in assets if a.asset_type == 'ETH')
        
        self.status_var.set(f"Scan complete: {len(assets)} assets found - {total_btc:.8f} BTC, {total_eth:.8f} ETH")
        
        # Enable consolidation if assets found
        if assets:
            self.consolidate_button.config(state="normal")
    
    def _scan_complete(self):
        """Handle scan completion"""
        self.progress.stop()
        self.scan_button.config(state="normal")
    
    def _show_error(self, error_message):
        """Show error message"""
        messagebox.showerror("Error", error_message)
        self.status_var.set("Error occurred")
    
    def _start_consolidation(self):
        """Start fund consolidation"""
        if not self.recovered_assets:
            messagebox.showwarning("Warning", "No assets to consolidate")
            return
        
        # Show consolidation dialog
        dialog = ConsolidationDialog(self.root, self.recovered_assets)
        if dialog.result:
            # Start consolidation in background
            self.consolidate_button.config(state="disabled")
            self.progress.start()
            
            thread = threading.Thread(target=self._perform_consolidation, args=(dialog.result,))
            thread.daemon = True
            thread.start()
    
    def _perform_consolidation(self, consolidation_config):
        """Perform fund consolidation"""
        try:
            results = self.recovery_system.consolidate_funds(
                destination_btc=consolidation_config.get('btc_address'),
                destination_eth=consolidation_config.get('eth_address')
            )
            
            self.root.after(0, self._consolidation_complete, results)
            
        except Exception as e:
            self.root.after(0, self._show_error, f"Consolidation error: {str(e)}")
        finally:
            self.root.after(0, lambda: self.progress.stop())
            self.root.after(0, lambda: self.consolidate_button.config(state="normal"))
    
    def _consolidation_complete(self, results):
        """Handle consolidation completion"""
        successful_btc = sum(1 for r in results['btc'] if r.success)
        successful_eth = sum(1 for r in results['eth'] if r.success)
        
        message = f"Consolidation complete:\n"
        message += f"BTC transfers: {successful_btc}/{len(results['btc'])} successful\n"
        message += f"ETH transfers: {successful_eth}/{len(results['eth'])} successful"
        
        messagebox.showinfo("Consolidation Complete", message)
        self.status_var.set("Consolidation complete")
    
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()

class ConsolidationDialog:
    """Dialog for configuring fund consolidation"""
    
    def __init__(self, parent, assets):
        self.result = None
        self.assets = assets
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Consolidate Funds")
        self.dialog.geometry("500x400")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self._create_widgets()
        
        # Center dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (self.dialog.winfo_width() // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")
    
    def _create_widgets(self):
        """Create dialog widgets"""
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="Fund Consolidation", style='Title.TLabel').pack(pady=(0, 20))
        
        # Asset summary
        summary_frame = ttk.LabelFrame(main_frame, text="Assets to Consolidate", padding="10")
        summary_frame.pack(fill=tk.X, pady=(0, 20))
        
        btc_assets = [a for a in self.assets if a.asset_type == 'BTC']
        eth_assets = [a for a in self.assets if a.asset_type == 'ETH']
        
        total_btc = sum(a.balance for a in btc_assets)
        total_eth = sum(a.balance for a in eth_assets)
        
        ttk.Label(summary_frame, text=f"Bitcoin: {len(btc_assets)} addresses, {total_btc:.8f} BTC total").pack(anchor=tk.W)
        ttk.Label(summary_frame, text=f"Ethereum: {len(eth_assets)} addresses, {total_eth:.8f} ETH total").pack(anchor=tk.W)
        
        # Destination addresses
        dest_frame = ttk.LabelFrame(main_frame, text="Destination Addresses", padding="10")
        dest_frame.pack(fill=tk.X, pady=(0, 20))
        
        # BTC destination
        if btc_assets:
            ttk.Label(dest_frame, text="Bitcoin Address:").pack(anchor=tk.W)
            self.btc_address_var = tk.StringVar()
            btc_entry = ttk.Entry(dest_frame, textvariable=self.btc_address_var, width=60)
            btc_entry.pack(fill=tk.X, pady=(0, 10))
            
            ttk.Button(dest_frame, text="Generate New BTC Address", 
                      command=self._generate_btc_address).pack(anchor=tk.W, pady=(0, 10))
        
        # ETH destination
        if eth_assets:
            ttk.Label(dest_frame, text="Ethereum Address:").pack(anchor=tk.W)
            self.eth_address_var = tk.StringVar()
            eth_entry = ttk.Entry(dest_frame, textvariable=self.eth_address_var, width=60)
            eth_entry.pack(fill=tk.X, pady=(0, 10))
            
            ttk.Button(dest_frame, text="Generate New ETH Address", 
                      command=self._generate_eth_address).pack(anchor=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        ttk.Button(button_frame, text="Cancel", command=self._cancel).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(button_frame, text="Consolidate", command=self._consolidate).pack(side=tk.RIGHT)
    
    def _generate_btc_address(self):
        """Generate new Bitcoin address"""
        # This would integrate with the recovery system to generate a new address
        messagebox.showinfo("Info", "Please enter a Bitcoin address manually for now")
    
    def _generate_eth_address(self):
        """Generate new Ethereum address"""
        # This would integrate with the recovery system to generate a new address
        messagebox.showinfo("Info", "Please enter an Ethereum address manually for now")
    
    def _consolidate(self):
        """Start consolidation"""
        config = {}
        
        if hasattr(self, 'btc_address_var'):
            btc_addr = self.btc_address_var.get().strip()
            if btc_addr:
                config['btc_address'] = btc_addr
        
        if hasattr(self, 'eth_address_var'):
            eth_addr = self.eth_address_var.get().strip()
            if eth_addr:
                config['eth_address'] = eth_addr
        
        if not config:
            messagebox.showerror("Error", "Please provide at least one destination address")
            return
        
        self.result = config
        self.dialog.destroy()
    
    def _cancel(self):
        """Cancel consolidation"""
        self.dialog.destroy()

if __name__ == "__main__":
    app = RecoveryGUI()
    app.run()