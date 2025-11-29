import hashlib
import hmac
import base64
import secrets
import bcrypt
from typing import Dict, List, Optional

class HashGenerator:
    """Cryptographic hash generator and verifier"""
    
    def __init__(self):
        self.supported_algorithms = ['sha256']
    
    def generate_hash(self, data: str, algorithm: str = 'sha256', 
                     encoding: str = 'utf-8') -> Dict:
        """Generate hash for given data"""
        try:
            if algorithm.lower() not in self.supported_algorithms:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            # Convert string to bytes
            data_bytes = data.encode(encoding)
            
            # Generate hash
            hash_obj = hashlib.new(algorithm.lower())
            hash_obj.update(data_bytes)
            
            # Get different representations
            hex_hash = hash_obj.hexdigest()
            b64_hash = base64.b64encode(hash_obj.digest()).decode('ascii')
            
            return {
                'algorithm': algorithm.upper(),
                'original_data': data,
                'hex_hash': hex_hash,
                'base64_hash': b64_hash,
                'hash_length': len(hex_hash),
                'byte_length': len(hash_obj.digest())
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'algorithm': algorithm,
                'original_data': data
            }
    
    def generate_multiple_hashes(self, data: str, 
                               algorithms: Optional[List[str]] = None) -> Dict:
        """Generate multiple hashes for the same data"""
        if algorithms is None:
            algorithms = ['sha256']
        
        results = {}
        for algo in algorithms:
            if algo.lower() in self.supported_algorithms:
                results[algo] = self.generate_hash(data, algo)
        
        return {
            'original_data': data,
            'hashes': results
        }
    
    def verify_hash(self, data: str, expected_hash: str, 
                   algorithm: str = 'sha256') -> Dict:
        """Verify if data matches the expected hash"""
        try:
            generated = self.generate_hash(data, algorithm)
            
            if 'error' in generated:
                return generated
            
            # Check both hex and base64 representations
            hex_match = generated['hex_hash'].lower() == expected_hash.lower()
            b64_match = generated['base64_hash'] == expected_hash
            
            return {
                'algorithm': algorithm.upper(),
                'original_data': data,
                'expected_hash': expected_hash,
                'generated_hash': generated['hex_hash'],
                'matches': hex_match or b64_match,
                'match_type': 'hex' if hex_match else 'base64' if b64_match else 'none'
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'algorithm': algorithm,
                'expected_hash': expected_hash
            }
    
    def generate_hmac(self, data: str, key: str, 
                     algorithm: str = 'sha256') -> Dict:
        """Generate HMAC (Hash-based Message Authentication Code)"""
        try:
            data_bytes = data.encode('utf-8')
            key_bytes = key.encode('utf-8')
            
            # Generate HMAC
            hmac_obj = hmac.new(key_bytes, data_bytes, 
                               getattr(hashlib, algorithm.lower()))
            
            hex_hmac = hmac_obj.hexdigest()
            b64_hmac = base64.b64encode(hmac_obj.digest()).decode('ascii')
            
            return {
                'algorithm': f"HMAC-{algorithm.upper()}",
                'original_data': data,
                'key_used': '***' + key[-4:] if len(key) > 4 else '***',
                'hex_hmac': hex_hmac,
                'base64_hmac': b64_hmac,
                'hmac_length': len(hex_hmac)
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'algorithm': f"HMAC-{algorithm}"
            }
    
    def verify_hmac(self, data: str, key: str, expected_hmac: str,
                   algorithm: str = 'sha256') -> Dict:
        """Verify HMAC"""
        try:
            generated = self.generate_hmac(data, key, algorithm)
            
            if 'error' in generated:
                return generated
            
            # Check both representations
            hex_match = generated['hex_hmac'].lower() == expected_hmac.lower()
            b64_match = generated['base64_hmac'] == expected_hmac
            
            return {
                'algorithm': f"HMAC-{algorithm.upper()}",
                'original_data': data,
                'expected_hmac': expected_hmac,
                'generated_hmac': generated['hex_hmac'],
                'matches': hex_match or b64_match,
                'match_type': 'hex' if hex_match else 'base64' if b64_match else 'none'
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'algorithm': f"HMAC-{algorithm}"
            }
    
    def hash_password(self, password: str, rounds: int = 12) -> Dict:
        """Generate bcrypt hash for password (secure password hashing)"""
        try:
            # Generate salt and hash
            salt = bcrypt.gensalt(rounds=rounds)
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
            
            return {
                'algorithm': 'bcrypt',
                'rounds': rounds,
                'salt': salt.decode('utf-8'),
                'hashed_password': hashed.decode('utf-8'),
                'hash_length': len(hashed),
                'security_note': 'This hash is suitable for password storage'
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'algorithm': 'bcrypt'
            }
    
    def verify_password(self, password: str, hashed_password: str) -> Dict:
        """Verify password against bcrypt hash"""
        try:
            # Verify password
            matches = bcrypt.checkpw(password.encode('utf-8'), 
                                   hashed_password.encode('utf-8'))
            
            return {
                'algorithm': 'bcrypt',
                'password_matches': matches,
                'verification_time': 'Variable (by design for security)'
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'algorithm': 'bcrypt'
            }
    
    def generate_random_salt(self, length: int = 32) -> Dict:
        """Generate cryptographically secure random salt"""
        try:
            salt_bytes = secrets.token_bytes(length)
            
            return {
                'salt_hex': salt_bytes.hex(),
                'salt_base64': base64.b64encode(salt_bytes).decode('ascii'),
                'salt_length': length,
                'entropy_bits': length * 8
            }
            
        except Exception as e:
            return {
                'error': str(e)
            }
    
    def file_hash(self, file_path: str, algorithm: str = 'sha256', 
                 chunk_size: int = 8192) -> Dict:
        """Generate hash for a file (for large files)"""
        try:
            hash_obj = hashlib.new(algorithm.lower())
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hash_obj.update(chunk)
            
            hex_hash = hash_obj.hexdigest()
            
            return {
                'algorithm': algorithm.upper(),
                'file_path': file_path,
                'hex_hash': hex_hash,
                'hash_length': len(hex_hash),
                'note': 'File hashed in chunks for memory efficiency'
            }
            
        except FileNotFoundError:
            return {
                'error': f'File not found: {file_path}',
                'algorithm': algorithm
            }
        except Exception as e:
            return {
                'error': str(e),
                'algorithm': algorithm,
                'file_path': file_path
            }
    
    def get_algorithm_info(self, algorithm: str) -> Dict:
        """Get information about SHA-256 hash algorithm"""
        info = {
            'sha256': {
                'description': 'Secure Hash Algorithm 256-bit',
                'output_size': '256 bits (64 hex chars)', 
                'security': 'Secure - widely recommended',
                'speed': 'Fast and efficient'
            }
        }
        
        return info.get(algorithm.lower(), {
            'description': 'Only SHA-256 is supported',
            'note': 'This implementation focuses on SHA-256 for simplicity and security'
        })