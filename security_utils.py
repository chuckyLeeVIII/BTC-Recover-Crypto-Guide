"""
Security utilities for the Blockchain Recovery System
Provides encryption, key validation, and secure storage functions
"""

import os
import hashlib
import secrets
import base64
from typing import Optional, Tuple, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json
import logging

class SecureStorage:
    """Handles secure storage of sensitive data"""
    
    def __init__(self, password: str):
        self.password = password.encode()
        self._derive_key()
    
    def _derive_key(self):
        """Derive encryption key from password"""
        salt = b'blockchain_recovery_salt_2024'  # In production, use random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        self.fernet = Fernet(key)
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        try:
            encrypted = self.fernet.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logging.error(f"Encryption error: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            raise
    
    def store_secure_data(self, data: Dict[str, Any], filename: str):
        """Store encrypted data to file"""
        try:
            json_data = json.dumps(data)
            encrypted_data = self.encrypt_data(json_data)
            
            with open(filename, 'w') as f:
                f.write(encrypted_data)
            
            # Set restrictive file permissions
            os.chmod(filename, 0o600)
            logging.info(f"Secure data stored to {filename}")
        except Exception as e:
            logging.error(f"Error storing secure data: {e}")
            raise
    
    def load_secure_data(self, filename: str) -> Dict[str, Any]:
        """Load and decrypt data from file"""
        try:
            with open(filename, 'r') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.decrypt_data(encrypted_data)
            return json.loads(decrypted_data)
        except Exception as e:
            logging.error(f"Error loading secure data: {e}")
            raise

class KeyValidator:
    """Advanced key validation and security checks"""
    
    @staticmethod
    def validate_private_key_strength(key: str, key_type: str = "bitcoin") -> Dict[str, Any]:
        """Comprehensive private key validation"""
        result = {
            'is_valid': False,
            'strength_score': 0,
            'warnings': [],
            'recommendations': []
        }
        
        try:
            if key_type.lower() == "bitcoin":
                # Bitcoin key validation
                if len(key) == 51 or len(key) == 52:  # WIF format
                    from bitcoinlib.keys import HDKey
                    hd_key = HDKey(key)
                    if hd_key.is_private:
                        result['is_valid'] = True
                        result['strength_score'] = 85
                elif len(key) == 64:  # Hex format
                    int(key, 16)  # Validate hex
                    result['is_valid'] = True
                    result['strength_score'] = 80
                    result['warnings'].append("Raw hex format - consider using WIF")
                
            elif key_type.lower() == "ethereum":
                # Ethereum key validation
                if key.startswith('0x'):
                    key = key[2:]
                if len(key) == 64:
                    int(key, 16)  # Validate hex
                    result['is_valid'] = True
                    result['strength_score'] = 80
            
            # Additional security checks
            if result['is_valid']:
                # Check for weak patterns
                if KeyValidator._has_weak_patterns(key):
                    result['strength_score'] -= 20
                    result['warnings'].append("Key contains weak patterns")
                
                # Check entropy
                entropy_score = KeyValidator._calculate_entropy(key)
                if entropy_score < 0.7:
                    result['strength_score'] -= 15
                    result['warnings'].append("Low entropy detected")
                
                # Security recommendations
                if result['strength_score'] < 70:
                    result['recommendations'].append("Consider generating a new key")
                
                result['recommendations'].append("Store key in secure hardware wallet")
                result['recommendations'].append("Never share key over insecure channels")
        
        except Exception as e:
            result['warnings'].append(f"Validation error: {str(e)}")
        
        return result
    
    @staticmethod
    def _has_weak_patterns(key: str) -> bool:
        """Check for weak patterns in private key"""
        # Remove common prefixes
        clean_key = key.replace('0x', '').lower()
        
        # Check for repeated characters
        if len(set(clean_key)) < len(clean_key) * 0.5:
            return True
        
        # Check for sequential patterns
        for i in range(len(clean_key) - 3):
            if clean_key[i:i+4] in ['0123', '1234', '2345', '3456', '4567', '5678', '6789', 'abcd', 'bcde', 'cdef']:
                return True
        
        # Check for common weak keys (simplified)
        weak_patterns = ['0000', '1111', '2222', '3333', '4444', '5555', '6666', '7777', '8888', '9999', 'aaaa', 'bbbb', 'cccc', 'dddd', 'eeee', 'ffff']
        for pattern in weak_patterns:
            if pattern * 4 in clean_key:
                return True
        
        return False
    
    @staticmethod
    def _calculate_entropy(key: str) -> float:
        """Calculate entropy of the key"""
        # Simple entropy calculation
        char_counts = {}
        for char in key:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0
        key_length = len(key)
        for count in char_counts.values():
            probability = count / key_length
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        # Normalize to 0-1 range
        max_entropy = (key_length.bit_length() - 1) if key_length > 0 else 1
        return entropy / max_entropy if max_entropy > 0 else 0

class SecureRandom:
    """Cryptographically secure random number generation"""
    
    @staticmethod
    def generate_secure_bytes(length: int) -> bytes:
        """Generate cryptographically secure random bytes"""
        return secrets.token_bytes(length)
    
    @staticmethod
    def generate_secure_hex(length: int) -> str:
        """Generate cryptographically secure hex string"""
        return secrets.token_hex(length)
    
    @staticmethod
    def generate_secure_password(length: int = 16, include_symbols: bool = True) -> str:
        """Generate cryptographically secure password"""
        import string
        
        characters = string.ascii_letters + string.digits
        if include_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        password = ''.join(secrets.choice(characters) for _ in range(length))
        
        # Ensure password meets complexity requirements
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password) if include_symbols else True
        
        if not all([has_upper, has_lower, has_digit, has_symbol]):
            # Regenerate if requirements not met
            return SecureRandom.generate_secure_password(length, include_symbols)
        
        return password

class AuditLogger:
    """Security audit logging"""
    
    def __init__(self, log_file: str = "security_audit.log"):
        self.log_file = log_file
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup security audit logging"""
        self.logger = logging.getLogger('security_audit')
        self.logger.setLevel(logging.INFO)
        
        # Create file handler
        handler = logging.FileHandler(self.log_file)
        handler.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
    
    def log_key_access(self, key_type: str, address: str, action: str):
        """Log private key access"""
        self.logger.info(f"KEY_ACCESS: {key_type} key for {address} - {action}")
    
    def log_transaction(self, tx_type: str, from_addr: str, to_addr: str, amount: float, txid: str = ""):
        """Log transaction attempt"""
        self.logger.info(f"TRANSACTION: {tx_type} - {amount} from {from_addr} to {to_addr} - TXID: {txid}")
    
    def log_security_event(self, event_type: str, details: str):
        """Log security-related events"""
        self.logger.warning(f"SECURITY_EVENT: {event_type} - {details}")
    
    def log_error(self, error_type: str, details: str):
        """Log security errors"""
        self.logger.error(f"SECURITY_ERROR: {error_type} - {details}")

class SecureMemory:
    """Secure memory handling for sensitive data"""
    
    def __init__(self):
        self._sensitive_data = {}
        self._access_count = {}
    
    def store_sensitive(self, key: str, value: str, max_access: int = 1):
        """Store sensitive data with access limits"""
        # Hash the key for additional security
        hashed_key = hashlib.sha256(key.encode()).hexdigest()
        
        # Encrypt the value
        storage = SecureStorage("temp_memory_key")
        encrypted_value = storage.encrypt_data(value)
        
        self._sensitive_data[hashed_key] = encrypted_value
        self._access_count[hashed_key] = max_access
    
    def retrieve_sensitive(self, key: str) -> Optional[str]:
        """Retrieve sensitive data (decrements access count)"""
        hashed_key = hashlib.sha256(key.encode()).hexdigest()
        
        if hashed_key not in self._sensitive_data:
            return None
        
        # Check access count
        if self._access_count[hashed_key] <= 0:
            self._clear_sensitive(hashed_key)
            return None
        
        # Decrypt and return
        storage = SecureStorage("temp_memory_key")
        try:
            decrypted_value = storage.decrypt_data(self._sensitive_data[hashed_key])
            
            # Decrement access count
            self._access_count[hashed_key] -= 1
            
            # Clear if no more access allowed
            if self._access_count[hashed_key] <= 0:
                self._clear_sensitive(hashed_key)
            
            return decrypted_value
        except Exception:
            self._clear_sensitive(hashed_key)
            return None
    
    def _clear_sensitive(self, hashed_key: str):
        """Securely clear sensitive data"""
        if hashed_key in self._sensitive_data:
            # Overwrite with random data before deletion
            self._sensitive_data[hashed_key] = secrets.token_hex(64)
            del self._sensitive_data[hashed_key]
        
        if hashed_key in self._access_count:
            del self._access_count[hashed_key]
    
    def clear_all(self):
        """Clear all sensitive data"""
        for key in list(self._sensitive_data.keys()):
            self._clear_sensitive(key)

# Global secure memory instance
secure_memory = SecureMemory()