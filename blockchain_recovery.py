#!/usr/bin/env python3
"""
Advanced Blockchain Transaction Recovery System
Performs secure key recovery, asset scanning, and fund consolidation
with comprehensive error handling and security validation.
"""

import os
import sys
import json
import logging
import hashlib
import secrets
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path

# Required imports with error handling
try:
    from bitcoinlib.wallets import HDWallet, wallet_delete_if_exists
    from bitcoinlib.keys import HDKey
    from bitcoinlib.mnemonic import Mnemonic
    from bitcoinlib.transactions import Transaction
    from bitcoinlib.services.services import Service
except ImportError as e:
    print(f"Error: bitcoinlib not installed. Run: pip install bitcoinlib")
    sys.exit(1)

try:
    from web3 import Web3
    from eth_account import Account
    from eth_utils import to_checksum_address
except ImportError as e:
    print(f"Error: web3 libraries not installed. Run: pip install web3 eth-account")
    sys.exit(1)

try:
    import requests
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
except ImportError as e:
    print(f"Error: Additional libraries needed. Run: pip install requests cryptography")
    sys.exit(1)

@dataclass
class RecoveredAsset:
    """Data structure for recovered blockchain assets"""
    asset_type: str  # 'BTC', 'ETH', 'ERC20'
    address: str
    balance: float
    balance_wei: int = 0
    private_key: str = ""
    derivation_path: str = ""
    is_staked: bool = False
    is_locked: bool = False
    unlock_time: Optional[datetime] = None

@dataclass
class TransactionResult:
    """Result of a blockchain transaction"""
    success: bool
    txid: str = ""
    error_message: str = ""
    gas_used: int = 0
    fee_paid: float = 0.0
    amount_transferred: float = 0.0

class SecurityValidator:
    """Handles cryptographic validation and security checks"""
    
    @staticmethod
    def validate_private_key(key: str, key_type: str = "bitcoin") -> bool:
        """Validate private key format and cryptographic properties"""
        try:
            if key_type.lower() == "bitcoin":
                # Validate Bitcoin WIF or hex format
                if len(key) == 51 or len(key) == 52:  # WIF format
                    hd_key = HDKey(key)
                    return hd_key.is_private
                elif len(key) == 64:  # Hex format
                    int(key, 16)  # Validate hex
                    return True
            elif key_type.lower() == "ethereum":
                # Validate Ethereum private key
                if key.startswith('0x'):
                    key = key[2:]
                if len(key) == 64:
                    int(key, 16)  # Validate hex
                    return True
            return False
        except Exception:
            return False
    
    @staticmethod
    def validate_mnemonic(phrase: str) -> bool:
        """Validate BIP39 mnemonic phrase"""
        try:
            mnemonic = Mnemonic()
            return mnemonic.check(phrase)
        except Exception:
            return False
    
    @staticmethod
    def generate_secure_wallet_name() -> str:
        """Generate cryptographically secure wallet name"""
        return f"recovery_wallet_{secrets.token_hex(16)}"

class BlockchainScanner:
    """Scans blockchain for assets and transaction history"""
    
    def __init__(self, btc_network: str = "bitcoin", eth_rpc_url: str = None):
        self.btc_network = btc_network
        self.eth_rpc_url = eth_rpc_url
        self.w3 = None
        
        if eth_rpc_url:
            try:
                self.w3 = Web3(Web3.HTTPProvider(eth_rpc_url))
                if not self.w3.is_connected():
                    logging.warning(f"Cannot connect to Ethereum RPC: {eth_rpc_url}")
                    self.w3 = None
            except Exception as e:
                logging.error(f"Ethereum connection error: {e}")
                self.w3 = None
    
    def scan_bitcoin_address(self, address: str) -> Dict[str, Any]:
        """Comprehensive Bitcoin address scanning"""
        try:
            service = Service(network=self.btc_network)
            
            # Get basic balance
            balance = service.getbalance(address)
            
            # Get transaction history
            transactions = service.gettransactions(address)
            
            # Check for unspent outputs
            utxos = service.getutxos(address)
            
            # Analyze for RBF transactions
            rbf_txs = []
            for tx in transactions:
                if hasattr(tx, 'replace_by_fee') and tx.replace_by_fee:
                    rbf_txs.append(tx.txid)
            
            return {
                'balance': balance,
                'transaction_count': len(transactions),
                'utxos': utxos,
                'rbf_transactions': rbf_txs,
                'last_activity': max([tx.date for tx in transactions]) if transactions else None
            }
        except Exception as e:
            logging.error(f"Bitcoin scanning error for {address}: {e}")
            return {'error': str(e)}
    
    def scan_ethereum_address(self, address: str) -> Dict[str, Any]:
        """Comprehensive Ethereum address scanning"""
        if not self.w3:
            return {'error': 'Ethereum connection not available'}
        
        try:
            # Get ETH balance
            balance_wei = self.w3.eth.get_balance(address)
            balance_eth = Web3.from_wei(balance_wei, 'ether')
            
            # Get transaction count (nonce)
            tx_count = self.w3.eth.get_transaction_count(address)
            
            # Check for staking (simplified check)
            # In practice, you'd check specific staking contracts
            is_staked = self._check_eth_staking(address)
            
            return {
                'balance_wei': balance_wei,
                'balance_eth': float(balance_eth),
                'transaction_count': tx_count,
                'is_staked': is_staked,
                'block_number': self.w3.eth.block_number
            }
        except Exception as e:
            logging.error(f"Ethereum scanning error for {address}: {e}")
            return {'error': str(e)}
    
    def _check_eth_staking(self, address: str) -> bool:
        """Check if address has staked ETH (simplified)"""
        # This is a placeholder - real implementation would check
        # specific staking contracts like ETH2 deposit contract
        try:
            # ETH2 Deposit Contract
            deposit_contract = "0x00000000219ab540356cBB839Cbe05303d7705Fa"
            # Check if address has interacted with staking contracts
            # This is simplified - real implementation needs more logic
            return False
        except Exception:
            return False

class TransactionExecutor:
    """Handles secure transaction creation and execution"""
    
    def __init__(self, btc_network: str = "bitcoin", eth_rpc_url: str = None):
        self.btc_network = btc_network
        self.eth_rpc_url = eth_rpc_url
        self.w3 = None
        
        if eth_rpc_url:
            self.w3 = Web3(Web3.HTTPProvider(eth_rpc_url))
    
    def create_new_wallet(self) -> Tuple[str, str, str]:
        """Create new secure wallet and return address, private key, mnemonic"""
        try:
            # Generate new mnemonic
            mnemonic = Mnemonic().generate()
            
            # Create wallet from mnemonic
            wallet_name = SecurityValidator.generate_secure_wallet_name()
            wallet = HDWallet.create(wallet_name, keys=mnemonic, network=self.btc_network)
            
            # Get primary address and private key
            key = wallet.get_key()
            address = key.address
            private_key = key.wif()
            
            # Clean up wallet
            wallet_delete_if_exists(wallet_name, force=True)
            
            return address, private_key, mnemonic
            
        except Exception as e:
            logging.error(f"Wallet creation error: {e}")
            raise
    
    def execute_bitcoin_transfer(self, from_key: str, to_address: str, 
                                amount: Optional[float] = None) -> TransactionResult:
        """Execute Bitcoin transaction with comprehensive error handling"""
        wallet_name = None
        try:
            # Validate inputs
            if not SecurityValidator.validate_private_key(from_key, "bitcoin"):
                return TransactionResult(False, error_message="Invalid Bitcoin private key")
            
            # Create temporary wallet
            wallet_name = SecurityValidator.generate_secure_wallet_name()
            wallet = HDWallet.create(wallet_name, keys=from_key, network=self.btc_network)
            
            # Update UTXOs
            wallet.utxos_update()
            current_balance = wallet.balance()
            
            if current_balance <= 0:
                return TransactionResult(False, error_message="Insufficient balance")
            
            # Calculate fee and amount
            if amount is None:
                # Sweep all funds
                tx = wallet.sweep(to_address, min_confirms=0)
            else:
                # Send specific amount
                amount_satoshi = int(amount * 100000000)  # Convert to satoshi
                if amount_satoshi >= current_balance:
                    return TransactionResult(False, error_message="Amount exceeds balance")
                tx = wallet.send_to(to_address, amount_satoshi, min_confirms=0)
            
            # Sign transaction
            tx.sign()
            
            # Validate transaction before sending
            if not tx.verified:
                return TransactionResult(False, error_message="Transaction verification failed")
            
            # Send transaction
            result = tx.send()
            
            if tx.error:
                return TransactionResult(False, error_message=f"Transaction failed: {tx.error}")
            
            return TransactionResult(
                success=True,
                txid=tx.txid,
                fee_paid=tx.fee / 100000000,  # Convert to BTC
                amount_transferred=(tx.output_total - tx.fee) / 100000000
            )
            
        except Exception as e:
            logging.error(f"Bitcoin transaction error: {e}")
            return TransactionResult(False, error_message=str(e))
        finally:
            if wallet_name:
                try:
                    wallet_delete_if_exists(wallet_name, force=True)
                except Exception:
                    pass
    
    def execute_ethereum_transfer(self, from_key: str, to_address: str, 
                                 amount: Optional[float] = None) -> TransactionResult:
        """Execute Ethereum transaction with gas optimization"""
        if not self.w3:
            return TransactionResult(False, error_message="Ethereum connection not available")
        
        try:
            # Validate inputs
            if not SecurityValidator.validate_private_key(from_key, "ethereum"):
                return TransactionResult(False, error_message="Invalid Ethereum private key")
            
            # Prepare private key
            if not from_key.startswith('0x'):
                from_key = '0x' + from_key
            
            # Create account
            account = Account.from_key(from_key)
            from_address = account.address
            
            # Get current balance
            balance_wei = self.w3.eth.get_balance(from_address)
            
            if balance_wei <= 0:
                return TransactionResult(False, error_message="Insufficient balance")
            
            # Get gas price and estimate gas
            gas_price = self.w3.eth.gas_price
            gas_limit = 21000  # Standard ETH transfer
            
            # Calculate transaction cost
            gas_cost = gas_price * gas_limit
            
            if amount is None:
                # Send all available funds minus gas
                if balance_wei <= gas_cost:
                    return TransactionResult(False, error_message="Balance insufficient for gas fees")
                value = balance_wei - gas_cost
            else:
                # Send specific amount
                value = Web3.to_wei(amount, 'ether')
                if value + gas_cost > balance_wei:
                    return TransactionResult(False, error_message="Insufficient balance including gas")
            
            # Build transaction
            transaction = {
                'nonce': self.w3.eth.get_transaction_count(from_address),
                'to': to_checksum_address(to_address),
                'value': value,
                'gas': gas_limit,
                'gasPrice': gas_price,
                'chainId': self.w3.eth.chain_id
            }
            
            # Sign transaction
            signed_txn = account.sign_transaction(transaction)
            
            # Send transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            return TransactionResult(
                success=True,
                txid=tx_hash.hex(),
                gas_used=gas_limit,
                fee_paid=Web3.from_wei(gas_cost, 'ether'),
                amount_transferred=Web3.from_wei(value, 'ether')
            )
            
        except Exception as e:
            logging.error(f"Ethereum transaction error: {e}")
            return TransactionResult(False, error_message=str(e))

class BlockchainRecoverySystem:
    """Main recovery system orchestrating all operations"""
    
    def __init__(self, btc_network: str = "bitcoin", eth_rpc_url: str = None):
        self.btc_network = btc_network
        self.eth_rpc_url = eth_rpc_url
        self.scanner = BlockchainScanner(btc_network, eth_rpc_url)
        self.executor = TransactionExecutor(btc_network, eth_rpc_url)
        self.recovered_assets: List[RecoveredAsset] = []
        
        # Setup logging
        self._setup_logging()
    
    def _setup_logging(self):
        """Configure comprehensive logging"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = f"blockchain_recovery_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        logging.info("Blockchain Recovery System initialized")
        logging.info(f"Log file: {log_file}")
    
    def recover_from_mnemonic(self, mnemonic: str, derivation_paths: List[str] = None) -> List[RecoveredAsset]:
        """Recover assets from BIP39 mnemonic phrase"""
        if not SecurityValidator.validate_mnemonic(mnemonic):
            logging.error("Invalid mnemonic phrase provided")
            return []
        
        if derivation_paths is None:
            derivation_paths = [
                "m/44'/0'/0'/0/0",    # BIP44 Bitcoin
                "m/49'/0'/0'/0/0",    # BIP49 Bitcoin (P2SH-P2WPKH)
                "m/84'/0'/0'/0/0",    # BIP84 Bitcoin (P2WPKH)
                "m/44'/60'/0'/0/0",   # BIP44 Ethereum
            ]
        
        assets = []
        wallet_name = None
        
        try:
            wallet_name = SecurityValidator.generate_secure_wallet_name()
            
            for path in derivation_paths:
                try:
                    logging.info(f"Checking derivation path: {path}")
                    
                    # Create wallet for this derivation path
                    if "60'" in path:  # Ethereum path
                        # Handle Ethereum derivation
                        hd_key = HDKey.from_seed(Mnemonic().to_seed(mnemonic))
                        derived_key = hd_key.subkey_for_path(path)
                        private_key = derived_key.private_hex
                        
                        # Get Ethereum address
                        account = Account.from_key(private_key)
                        address = account.address
                        
                        # Scan for assets
                        scan_result = self.scanner.scan_ethereum_address(address)
                        
                        if 'error' not in scan_result and scan_result['balance_eth'] > 0:
                            asset = RecoveredAsset(
                                asset_type='ETH',
                                address=address,
                                balance=scan_result['balance_eth'],
                                balance_wei=scan_result['balance_wei'],
                                private_key=private_key,
                                derivation_path=path,
                                is_staked=scan_result.get('is_staked', False)
                            )
                            assets.append(asset)
                            logging.info(f"Found ETH: {asset.balance} ETH at {address}")
                    
                    else:  # Bitcoin path
                        wallet = HDWallet.create(
                            wallet_name, 
                            keys=mnemonic, 
                            network=self.btc_network,
                            account_id=0,
                            witness_type='segwit' if '84' in path else 'p2sh-segwit' if '49' in path else 'legacy'
                        )
                        
                        # Get address for this path
                        key = wallet.get_key(path)
                        address = key.address
                        
                        # Scan for assets
                        scan_result = self.scanner.scan_bitcoin_address(address)
                        
                        if 'error' not in scan_result and scan_result['balance'] > 0:
                            asset = RecoveredAsset(
                                asset_type='BTC',
                                address=address,
                                balance=scan_result['balance'] / 100000000,  # Convert to BTC
                                private_key=key.wif(),
                                derivation_path=path
                            )
                            assets.append(asset)
                            logging.info(f"Found BTC: {asset.balance} BTC at {address}")
                        
                        wallet_delete_if_exists(wallet_name, force=True)
                
                except Exception as e:
                    logging.error(f"Error processing path {path}: {e}")
                    continue
        
        except Exception as e:
            logging.error(f"Mnemonic recovery error: {e}")
        finally:
            if wallet_name:
                try:
                    wallet_delete_if_exists(wallet_name, force=True)
                except Exception:
                    pass
        
        self.recovered_assets.extend(assets)
        return assets
    
    def recover_from_private_key(self, private_key: str, key_type: str = "auto") -> List[RecoveredAsset]:
        """Recover assets from a single private key"""
        assets = []
        
        # Auto-detect key type if not specified
        if key_type == "auto":
            if len(private_key) == 64 or (len(private_key) == 66 and private_key.startswith('0x')):
                key_type = "ethereum"
            elif len(private_key) in [51, 52] or len(private_key) == 64:
                key_type = "bitcoin"
            else:
                logging.error("Cannot auto-detect private key type")
                return []
        
        try:
            if key_type.lower() == "bitcoin":
                if not SecurityValidator.validate_private_key(private_key, "bitcoin"):
                    logging.error("Invalid Bitcoin private key")
                    return []
                
                # Create temporary wallet
                wallet_name = SecurityValidator.generate_secure_wallet_name()
                wallet = HDWallet.create(wallet_name, keys=private_key, network=self.btc_network)
                
                key = wallet.get_key()
                address = key.address
                
                # Scan for assets
                scan_result = self.scanner.scan_bitcoin_address(address)
                
                if 'error' not in scan_result and scan_result['balance'] > 0:
                    asset = RecoveredAsset(
                        asset_type='BTC',
                        address=address,
                        balance=scan_result['balance'] / 100000000,
                        private_key=private_key
                    )
                    assets.append(asset)
                    logging.info(f"Found BTC: {asset.balance} BTC at {address}")
                
                wallet_delete_if_exists(wallet_name, force=True)
            
            elif key_type.lower() == "ethereum":
                if not SecurityValidator.validate_private_key(private_key, "ethereum"):
                    logging.error("Invalid Ethereum private key")
                    return []
                
                # Prepare key format
                if not private_key.startswith('0x'):
                    private_key = '0x' + private_key
                
                account = Account.from_key(private_key)
                address = account.address
                
                # Scan for assets
                scan_result = self.scanner.scan_ethereum_address(address)
                
                if 'error' not in scan_result and scan_result['balance_eth'] > 0:
                    asset = RecoveredAsset(
                        asset_type='ETH',
                        address=address,
                        balance=scan_result['balance_eth'],
                        balance_wei=scan_result['balance_wei'],
                        private_key=private_key,
                        is_staked=scan_result.get('is_staked', False)
                    )
                    assets.append(asset)
                    logging.info(f"Found ETH: {asset.balance} ETH at {address}")
        
        except Exception as e:
            logging.error(f"Private key recovery error: {e}")
        
        self.recovered_assets.extend(assets)
        return assets
    
    def consolidate_funds(self, destination_btc: str = None, destination_eth: str = None) -> Dict[str, List[TransactionResult]]:
        """Consolidate all recovered funds to new addresses"""
        if not self.recovered_assets:
            logging.warning("No assets to consolidate")
            return {'btc': [], 'eth': []}
        
        results = {'btc': [], 'eth': []}
        
        # Create new destination addresses if not provided
        if not destination_btc or not destination_eth:
            new_address, new_private_key, new_mnemonic = self.executor.create_new_wallet()
            if not destination_btc:
                destination_btc = new_address
            logging.info(f"Created new BTC address: {destination_btc}")
            logging.info(f"New wallet mnemonic: {new_mnemonic}")
        
        # Process Bitcoin assets
        btc_assets = [asset for asset in self.recovered_assets if asset.asset_type == 'BTC']
        for asset in btc_assets:
            logging.info(f"Transferring {asset.balance} BTC from {asset.address}")
            result = self.executor.execute_bitcoin_transfer(
                asset.private_key, 
                destination_btc
            )
            results['btc'].append(result)
            
            if result.success:
                logging.info(f"BTC transfer successful: {result.txid}")
            else:
                logging.error(f"BTC transfer failed: {result.error_message}")
        
        # Process Ethereum assets
        if destination_eth:
            eth_assets = [asset for asset in self.recovered_assets if asset.asset_type == 'ETH']
            for asset in eth_assets:
                if asset.is_staked:
                    logging.warning(f"ETH at {asset.address} is staked - manual unstaking required")
                    continue
                
                logging.info(f"Transferring {asset.balance} ETH from {asset.address}")
                result = self.executor.execute_ethereum_transfer(
                    asset.private_key,
                    destination_eth
                )
                results['eth'].append(result)
                
                if result.success:
                    logging.info(f"ETH transfer successful: {result.txid}")
                else:
                    logging.error(f"ETH transfer failed: {result.error_message}")
        
        return results
    
    def generate_recovery_report(self) -> Dict[str, Any]:
        """Generate comprehensive recovery report"""
        total_btc = sum(asset.balance for asset in self.recovered_assets if asset.asset_type == 'BTC')
        total_eth = sum(asset.balance for asset in self.recovered_assets if asset.asset_type == 'ETH')
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_assets_found': len(self.recovered_assets),
            'total_btc_recovered': total_btc,
            'total_eth_recovered': total_eth,
            'assets_by_type': {
                'BTC': [
                    {
                        'address': asset.address,
                        'balance': asset.balance,
                        'derivation_path': asset.derivation_path
                    }
                    for asset in self.recovered_assets if asset.asset_type == 'BTC'
                ],
                'ETH': [
                    {
                        'address': asset.address,
                        'balance': asset.balance,
                        'is_staked': asset.is_staked,
                        'derivation_path': asset.derivation_path
                    }
                    for asset in self.recovered_assets if asset.asset_type == 'ETH'
                ]
            }
        }
        
        return report

def main():
    """Main execution function with CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Blockchain Asset Recovery System")
    parser.add_argument("--mnemonic", help="BIP39 mnemonic phrase for recovery")
    parser.add_argument("--private-key", help="Single private key for recovery")
    parser.add_argument("--key-type", choices=["bitcoin", "ethereum", "auto"], default="auto",
                       help="Type of private key (auto-detect by default)")
    parser.add_argument("--btc-destination", help="Bitcoin destination address")
    parser.add_argument("--eth-destination", help="Ethereum destination address")
    parser.add_argument("--eth-rpc", help="Ethereum RPC URL")
    parser.add_argument("--btc-network", default="bitcoin", help="Bitcoin network (bitcoin/testnet)")
    parser.add_argument("--consolidate", action="store_true", help="Automatically consolidate funds")
    parser.add_argument("--report-only", action="store_true", help="Generate report without transferring")
    
    args = parser.parse_args()
    
    if not args.mnemonic and not args.private_key:
        print("Error: Must provide either --mnemonic or --private-key")
        sys.exit(1)
    
    # Initialize recovery system
    recovery_system = BlockchainRecoverySystem(
        btc_network=args.btc_network,
        eth_rpc_url=args.eth_rpc
    )
    
    try:
        # Perform recovery
        if args.mnemonic:
            logging.info("Starting mnemonic-based recovery")
            assets = recovery_system.recover_from_mnemonic(args.mnemonic)
        else:
            logging.info("Starting private key recovery")
            assets = recovery_system.recover_from_private_key(args.private_key, args.key_type)
        
        if not assets:
            logging.info("No assets found for recovery")
            return
        
        # Generate report
        report = recovery_system.generate_recovery_report()
        print(f"\n=== RECOVERY REPORT ===")
        print(f"Total BTC found: {report['total_btc_recovered']}")
        print(f"Total ETH found: {report['total_eth_recovered']}")
        print(f"Total addresses: {report['total_assets_found']}")
        
        # Save detailed report
        report_file = f"recovery_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        logging.info(f"Detailed report saved to: {report_file}")
        
        # Consolidate funds if requested
        if args.consolidate and not args.report_only:
            logging.info("Starting fund consolidation")
            results = recovery_system.consolidate_funds(
                destination_btc=args.btc_destination,
                destination_eth=args.eth_destination
            )
            
            # Summary of transfers
            successful_btc = sum(1 for r in results['btc'] if r.success)
            successful_eth = sum(1 for r in results['eth'] if r.success)
            
            print(f"\n=== CONSOLIDATION RESULTS ===")
            print(f"BTC transfers: {successful_btc}/{len(results['btc'])} successful")
            print(f"ETH transfers: {successful_eth}/{len(results['eth'])} successful")
            
            # Log transaction IDs
            for result in results['btc'] + results['eth']:
                if result.success:
                    logging.info(f"Transaction ID: {result.txid}")
    
    except Exception as e:
        logging.error(f"Recovery system error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()