"""
Configuration file for Blockchain Recovery System
Contains network settings, API endpoints, and security parameters
"""

import os
from typing import Dict, List

class Config:
    """Main configuration class"""
    
    # Network Configuration
    BITCOIN_NETWORKS = {
        'mainnet': 'bitcoin',
        'testnet': 'testnet'
    }
    
    # Default RPC Endpoints
    DEFAULT_ETH_RPC = {
        'mainnet': 'https://mainnet.infura.io/v3/YOUR_PROJECT_ID',
        'goerli': 'https://goerli.infura.io/v3/YOUR_PROJECT_ID',
        'sepolia': 'https://sepolia.infura.io/v3/YOUR_PROJECT_ID'
    }
    
    # Derivation Paths for Recovery
    STANDARD_DERIVATION_PATHS = [
        # Bitcoin paths
        "m/44'/0'/0'/0/0",    # BIP44 Bitcoin Legacy
        "m/49'/0'/0'/0/0",    # BIP49 Bitcoin P2SH-P2WPKH
        "m/84'/0'/0'/0/0",    # BIP84 Bitcoin P2WPKH (Native SegWit)
        
        # Ethereum paths
        "m/44'/60'/0'/0/0",   # BIP44 Ethereum
        "m/44'/60'/0'/0/1",   # BIP44 Ethereum (second address)
        
        # Extended search paths
        "m/44'/0'/0'/0/1",    # Bitcoin second address
        "m/44'/0'/0'/0/2",    # Bitcoin third address
        "m/44'/60'/0'/0/2",   # Ethereum third address
    ]
    
    # Security Settings
    SECURITY_CONFIG = {
        'min_password_length': 12,
        'require_uppercase': True,
        'require_lowercase': True,
        'require_numbers': True,
        'require_symbols': True,
        'max_login_attempts': 3,
        'session_timeout': 3600,  # 1 hour
    }
    
    # Transaction Settings
    TRANSACTION_CONFIG = {
        'bitcoin': {
            'min_confirmations': 1,
            'fee_rate': 'normal',  # slow, normal, fast
            'rbf_enabled': True,
            'dust_threshold': 546,  # satoshis
        },
        'ethereum': {
            'gas_limit': 21000,
            'gas_price_multiplier': 1.1,
            'max_fee_per_gas': None,  # Use network default
            'max_priority_fee_per_gas': None,
        }
    }
    
    # Logging Configuration
    LOGGING_CONFIG = {
        'level': 'INFO',
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'file_rotation': True,
        'max_file_size': '10MB',
        'backup_count': 5,
    }
    
    # API Rate Limits
    RATE_LIMITS = {
        'blockchain_info': 1,  # requests per second
        'etherscan': 5,
        'infura': 10,
        'alchemy': 25,
    }
    
    @classmethod
    def get_eth_rpc_url(cls, network: str = 'mainnet') -> str:
        """Get Ethereum RPC URL for specified network"""
        return os.getenv(f'ETH_RPC_{network.upper()}', cls.DEFAULT_ETH_RPC.get(network, ''))
    
    @classmethod
    def get_api_key(cls, service: str) -> str:
        """Get API key for specified service"""
        return os.getenv(f'{service.upper()}_API_KEY', '')
    
    @classmethod
    def validate_config(cls) -> bool:
        """Validate configuration settings"""
        required_vars = ['ETH_RPC_MAINNET']
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        
        if missing_vars:
            print(f"Warning: Missing environment variables: {missing_vars}")
            return False
        return True

# Environment-specific configurations
class DevelopmentConfig(Config):
    """Development environment configuration"""
    DEBUG = True
    BITCOIN_NETWORK = 'testnet'
    ETH_NETWORK = 'goerli'

class ProductionConfig(Config):
    """Production environment configuration"""
    DEBUG = False
    BITCOIN_NETWORK = 'bitcoin'
    ETH_NETWORK = 'mainnet'

class TestingConfig(Config):
    """Testing environment configuration"""
    TESTING = True
    BITCOIN_NETWORK = 'testnet'
    ETH_NETWORK = 'sepolia'

# Configuration factory
def get_config(env: str = None) -> Config:
    """Get configuration based on environment"""
    env = env or os.getenv('ENVIRONMENT', 'development')
    
    configs = {
        'development': DevelopmentConfig,
        'production': ProductionConfig,
        'testing': TestingConfig,
    }
    
    return configs.get(env, DevelopmentConfig)()