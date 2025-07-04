# Blockchain Recovery System

A comprehensive, secure blockchain transaction system for recovering and consolidating cryptocurrency assets from various sources including private keys, mnemonic phrases, and wallet files.

## Features

### 🔐 Security First
- **Industry-standard cryptographic validation**
- **Secure memory handling** for sensitive data
- **Comprehensive audit logging**
- **Private key strength validation**
- **Encrypted storage** for sensitive information

### 🔍 Asset Discovery
- **Multi-blockchain support** (Bitcoin, Ethereum)
- **Multiple derivation path scanning** (BIP44, BIP49, BIP84)
- **Staked asset detection**
- **Locked fund identification**
- **RBF transaction analysis**
- **Historical transaction scanning**

### 💰 Fund Management
- **Secure transaction creation**
- **Gas optimization** for Ethereum
- **Fee calculation** and validation
- **Batch consolidation**
- **Error handling** and retry mechanisms

### 🖥️ User Interface
- **Graphical interface** for easy operation
- **Command-line interface** for automation
- **Real-time progress tracking**
- **Detailed reporting**

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Environment Setup
Create a `.env` file with your configuration:
```bash
# Ethereum RPC endpoints
ETH_RPC_MAINNET=https://mainnet.infura.io/v3/YOUR_PROJECT_ID
ETH_RPC_GOERLI=https://goerli.infura.io/v3/YOUR_PROJECT_ID

# API Keys (optional)
ETHERSCAN_API_KEY=your_etherscan_api_key
INFURA_API_KEY=your_infura_project_id
```

## Usage

### Graphical Interface
```bash
python gui_interface.py
```

### Command Line Interface

#### Recover from Mnemonic
```bash
python blockchain_recovery.py --mnemonic "your twelve word mnemonic phrase here" --consolidate
```

#### Recover from Private Key
```bash
python blockchain_recovery.py --private-key "your_private_key_here" --key-type bitcoin --consolidate
```

#### Specify Destination Addresses
```bash
python blockchain_recovery.py \
  --mnemonic "your mnemonic phrase" \
  --btc-destination "1YourBitcoinAddressHere" \
  --eth-destination "0xYourEthereumAddressHere" \
  --consolidate
```

#### Report Only (No Transfers)
```bash
python blockchain_recovery.py --mnemonic "your mnemonic phrase" --report-only
```

### Advanced Options

#### Custom Ethereum RPC
```bash
python blockchain_recovery.py \
  --mnemonic "your mnemonic phrase" \
  --eth-rpc "https://your-custom-rpc-endpoint.com" \
  --consolidate
```

#### Testnet Recovery
```bash
python blockchain_recovery.py \
  --mnemonic "your mnemonic phrase" \
  --btc-network testnet \
  --consolidate
```

## Security Features

### Private Key Validation
The system performs comprehensive validation of private keys:
- **Format validation** (WIF, hex, etc.)
- **Cryptographic strength analysis**
- **Weak pattern detection**
- **Entropy calculation**

### Secure Storage
- **AES encryption** for sensitive data
- **PBKDF2 key derivation**
- **Secure memory handling**
- **Automatic data clearing**

### Audit Logging
All operations are logged with:
- **Timestamp and operation details**
- **Security events**
- **Transaction attempts**
- **Error conditions**

## Supported Assets

### Bitcoin
- **Legacy addresses** (P2PKH)
- **SegWit addresses** (P2WPKH)
- **P2SH-SegWit addresses** (P2SH-P2WPKH)
- **Multi-signature wallets**

### Ethereum
- **ETH transfers**
- **ERC-20 tokens** (planned)
- **Staked ETH detection**
- **Smart contract interactions**

## Recovery Methods

### 1. BIP39 Mnemonic Phrases
- **12, 15, 18, 21, or 24-word phrases**
- **Multiple derivation paths**
- **Automatic address generation**
- **Balance checking across paths**

### 2. Private Keys
- **Bitcoin WIF format**
- **Raw hex format**
- **Ethereum private keys**
- **Auto-detection of key type**

### 3. Wallet Files
- **Electrum wallet files**
- **Bitcoin Core wallet.dat**
- **JSON wallet files**
- **Encrypted wallet support**

## Error Handling

The system includes comprehensive error handling:

### Network Errors
- **Automatic retry mechanisms**
- **Fallback RPC endpoints**
- **Connection timeout handling**

### Transaction Errors
- **Insufficient balance detection**
- **Gas estimation failures**
- **Network congestion handling**
- **Invalid address validation**

### Security Errors
- **Invalid key detection**
- **Weak key warnings**
- **Encryption failures**
- **Access control violations**

## Configuration

### Network Settings
```python
# Bitcoin networks
BITCOIN_NETWORKS = {
    'mainnet': 'bitcoin',
    'testnet': 'testnet'
}

# Ethereum networks
ETH_NETWORKS = {
    'mainnet': 'https://mainnet.infura.io/v3/YOUR_PROJECT_ID',
    'goerli': 'https://goerli.infura.io/v3/YOUR_PROJECT_ID'
}
```

### Derivation Paths
```python
DERIVATION_PATHS = [
    "m/44'/0'/0'/0/0",    # BIP44 Bitcoin
    "m/49'/0'/0'/0/0",    # BIP49 Bitcoin (P2SH-P2WPKH)
    "m/84'/0'/0'/0/0",    # BIP84 Bitcoin (P2WPKH)
    "m/44'/60'/0'/0/0",   # BIP44 Ethereum
]
```

### Security Settings
```python
SECURITY_CONFIG = {
    'min_password_length': 12,
    'max_login_attempts': 3,
    'session_timeout': 3600,
    'require_2fa': False,
}
```

## API Reference

### BlockchainRecoverySystem Class

#### Methods

##### `recover_from_mnemonic(mnemonic: str, derivation_paths: List[str] = None) -> List[RecoveredAsset]`
Recover assets from BIP39 mnemonic phrase.

##### `recover_from_private_key(private_key: str, key_type: str = "auto") -> List[RecoveredAsset]`
Recover assets from a single private key.

##### `consolidate_funds(destination_btc: str = None, destination_eth: str = None) -> Dict[str, List[TransactionResult]]`
Consolidate all recovered funds to specified addresses.

##### `generate_recovery_report() -> Dict[str, Any]`
Generate comprehensive recovery report.

### SecurityValidator Class

#### Methods

##### `validate_private_key(key: str, key_type: str = "bitcoin") -> bool`
Validate private key format and cryptographic properties.

##### `validate_mnemonic(phrase: str) -> bool`
Validate BIP39 mnemonic phrase.

##### `generate_secure_wallet_name() -> str`
Generate cryptographically secure wallet name.

## Troubleshooting

### Common Issues

#### "Invalid mnemonic phrase"
- Ensure the phrase contains 12, 15, 18, 21, or 24 words
- Check for typos in the words
- Verify words are from the BIP39 wordlist

#### "Cannot connect to Ethereum RPC"
- Check your internet connection
- Verify the RPC URL is correct
- Ensure your API key is valid (for Infura/Alchemy)

#### "Insufficient balance for gas fees"
- The account balance is too low to cover transaction fees
- Try consolidating larger amounts first
- Check current network gas prices

#### "Transaction failed"
- Network congestion may cause failures
- Try increasing gas price
- Check if the destination address is valid

### Debug Mode
Enable debug logging:
```bash
export PYTHONPATH=$PYTHONPATH:.
python -c "import logging; logging.basicConfig(level=logging.DEBUG)"
python blockchain_recovery.py --mnemonic "your phrase" --report-only
```

## Security Considerations

### Best Practices
1. **Never share private keys** or mnemonic phrases
2. **Use hardware wallets** for long-term storage
3. **Verify destination addresses** before consolidation
4. **Test with small amounts** first
5. **Keep backups** of recovery phrases

### Risk Mitigation
- **Air-gapped systems** for maximum security
- **Multi-signature wallets** for shared control
- **Time-locked transactions** for delayed execution
- **Regular security audits**

### Privacy Protection
- **No data collection** or transmission to third parties
- **Local processing** of all sensitive data
- **Secure deletion** of temporary files
- **Encrypted storage** of configuration

## Contributing

### Development Setup
```bash
git clone https://github.com/your-repo/blockchain-recovery
cd blockchain-recovery
pip install -r requirements-dev.txt
```

### Running Tests
```bash
python -m pytest tests/
```

### Code Style
```bash
black blockchain_recovery.py
flake8 blockchain_recovery.py
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

**⚠️ IMPORTANT SECURITY NOTICE ⚠️**

This software is provided for educational and recovery purposes only. Users are responsible for:

- **Securing their private keys** and mnemonic phrases
- **Verifying destination addresses** before transfers
- **Understanding the risks** of cryptocurrency transactions
- **Complying with local laws** and regulations

The developers are not responsible for:
- **Lost funds** due to user error
- **Network failures** or congestion
- **Third-party service** outages
- **Regulatory compliance** issues

**Always test with small amounts first and ensure you have proper backups.**

## Support

