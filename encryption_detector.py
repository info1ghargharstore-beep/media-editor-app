"""
Advanced encryption and obfuscation detection
"""

import numpy as np
from typing import Dict, List, Tuple
import hashlib
import struct

class EncryptionDetector:
    """Detect encrypted content and analyze encryption strength"""
    
    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        Range: 0-8 (bits per byte)
        
        Values:
        - 0-3: Likely plaintext
        - 3-5: Possible compression or weak encryption
        - 5-7: Likely encrypted
        - 7-8: Strong encryption or random data
        """
        if not data:
            return 0.0
        
        entropy = 0.0
        byte_counts = {}
        
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        data_len = len(data)
        for count in byte_counts.values():
            p = count / data_len
            entropy -= p * np.log2(p)
        
        return entropy
    
    @staticmethod
    def calculate_chi_squared(data: bytes) -> float:
        """
        Calculate chi-squared statistic
        High values indicate non-random (encrypted) data
        """
        byte_counts = np.zeros(256)
        for byte in data:
            byte_counts[byte] += 1
        
        expected = len(data) / 256.0
        chi_squared = np.sum((byte_counts - expected) ** 2 / expected)
        
        return float(chi_squared)
    
    @staticmethod
    def detect_aes_encryption(data: bytes) -> Dict:
        """
        Detect AES encryption patterns
        AES uses 128-bit (16-byte) blocks
        """
        results = {
            'likely_aes': False,
            'evidence': []
        }
        
        # Check for block alignment
        if len(data) % 16 == 0:
            results['evidence'].append('Data is multiple of 16 bytes (AES block size)')
        
        # High entropy is typical of AES
        entropy = EncryptionDetector.calculate_shannon_entropy(data)
        if entropy > 7.5:
            results['evidence'].append(f'High entropy ({entropy:.2f}) typical of AES')
        
        if len(results['evidence']) >= 2:
            results['likely_aes'] = True
        
        return results
    
    @staticmethod
    def detect_rsa_encryption(data: bytes) -> Dict:
        """
        Detect RSA encryption patterns
        RSA typically produces output of specific lengths (1024, 2048, 4096 bits)
        """
        results = {
            'likely_rsa': False,
            'key_size': None,
            'evidence': []
        }
        
        possible_key_sizes = {
            128: '1024-bit',
            256: '2048-bit',
            512: '4096-bit'
        }
        
        for byte_size, key_size in possible_key_sizes.items():
            if len(data) == byte_size:
                results['key_size'] = key_size
                results['evidence'].append(f'Data length matches RSA {key_size} key')
        
        entropy = EncryptionDetector.calculate_shannon_entropy(data)
        if entropy > 7.5:
            results['evidence'].append('High entropy typical of RSA')
        
        if results['key_size']:
            results['likely_rsa'] = True
        
        return results
    
    @staticmethod
    def detect_compression(data: bytes) -> Dict:
        """
        Detect compression algorithms
        """
        signatures = {
            b'\x1f\x8b\x08': 'GZIP',
            b'BZ': 'BZIP2',
            b'PK\x03\x04': 'ZIP',
            b'7z\xbc\xaf\x27\x1c': '7ZIP',
            b'\x28\xb5/\xfd': 'ZSTANDARD'
        }
        
        detected = []
        for signature, name in signatures.items():
            if data.startswith(signature):
                detected.append(name)
        
        return {
            'compressed': len(detected) > 0,
            'algorithm': detected[0] if detected else None,
            'all_detected': detected
        }
    
    @staticmethod
    def analyze_byte_distribution(data: bytes) -> Dict:
        """
        Analyze byte distribution for encryption signatures
        """
        byte_counts = np.zeros(256)
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate statistics
        non_zero_bytes = np.count_nonzero(byte_counts)
        avg_frequency = len(data) / 256.0
        max_frequency = np.max(byte_counts)
        min_frequency = np.min(byte_counts[byte_counts > 0]) if np.any(byte_counts > 0) else 0
        
        return {
            'unique_bytes': int(non_zero_bytes),
            'avg_frequency': float(avg_frequency),
            'max_frequency': int(max_frequency),
            'min_frequency': int(min_frequency),
            'frequency_variance': float(np.var(byte_counts[byte_counts > 0])) if np.any(byte_counts > 0) else 0,
            'likely_encrypted': non_zero_bytes > 250  # Most byte values used
        }
    
    @staticmethod
    def analyze_entropy_per_block(data: bytes, block_size: int = 256) -> Dict:
        """
        Analyze entropy in different blocks of data
        """
        blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
        
        entropies = []
        for block in blocks:
            if block:
                entropy = EncryptionDetector.calculate_shannon_entropy(block)
                entropies.append(entropy)
        
        return {
            'num_blocks': len(blocks),
            'block_size': block_size,
            'entropies': [float(e) for e in entropies],
            'mean_entropy': float(np.mean(entropies)) if entropies else 0,
            'entropy_variance': float(np.var(entropies)) if len(entropies) > 1 else 0,
            'entropy_consistency': 'High' if np.var(entropies) < 0.5 else 'Variable'
        }
    
    @staticmethod
    def comprehensive_encryption_analysis(file_path: str) -> Dict:
        """
        Comprehensive encryption detection analysis
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Get file signature
            signature = data[:16].hex() if len(data) >= 16 else data.hex()
            
            analysis = {
                'file': file_path,
                'file_size': len(data),
                'signature': signature,
                'entropy': EncryptionDetector.calculate_shannon_entropy(data),
                'chi_squared': EncryptionDetector.calculate_chi_squared(data),
                'compression': EncryptionDetector.detect_compression(data),
                'aes_patterns': EncryptionDetector.detect_aes_encryption(data),
                'rsa_patterns': EncryptionDetector.detect_rsa_encryption(data),
                'byte_distribution': EncryptionDetector.analyze_byte_distribution(data),
                'entropy_per_block': EncryptionDetector.analyze_entropy_per_block(data),
                'verdict': EncryptionDetector._generate_verdict(data)
            }
            
            return analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def _generate_verdict(data: bytes) -> str:
        """Generate encryption verdict based on analysis"""
        entropy = EncryptionDetector.calculate_shannon_entropy(data)
        
        # Check for compression first
        compression = EncryptionDetector.detect_compression(data)
        if compression['compressed']:
            return f"Compressed data ({compression['algorithm']})"
        
        # Check entropy
        if entropy > 7.95:
            return "Strong encryption likely (AES, RSA, or similar)"
        elif entropy > 7.5:
            return "Encryption detected (likely high-strength)"
        elif entropy > 7.0:
            return "Possible encryption or random data"
        elif entropy > 5.0:
            return "Possible weak encryption or significant compression"
        else:
            return "Likely plaintext or low-entropy content"


class EncryptionKeyAnalyzer:
    """Analyze patterns related to encryption keys"""
    
    @staticmethod
    def detect_key_material(data: bytes) -> Dict:
        """
        Detect likely cryptographic key material
        """
        results = {
            'possible_key_material': False,
            'indicators': [],
            'size_analysis': {}
        }
        
        # High entropy is typical of keys
        entropy = EncryptionDetector.calculate_shannon_entropy(data)
        if entropy > 7.5:
            results['indicators'].append('High entropy (typical of keys)')
        
        # Check common key sizes
        common_key_sizes = {
            16: 'AES-128',
            24: 'AES-192',
            32: 'AES-256 / SHA-256',
            64: 'SHA-512 / HMAC',
            128: 'RSA-1024',
            256: 'RSA-2048',
            512: 'RSA-4096'
        }
        
        if len(data) in common_key_sizes:
            key_type = common_key_sizes[len(data)]
            results['indicators'].append(f'Size matches {key_type} key')
            results['size_analysis']['matches'] = key_type
        
        # Check for key derivation function markers
        if data.startswith(b'\x00'):
            results['indicators'].append('Begins with null byte (possible KDF output)')
        
        if len(results['indicators']) >= 2:
            results['possible_key_material'] = True
        
        return results