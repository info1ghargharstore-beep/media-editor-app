"""
Comprehensive hidden data recovery and steganography detection
"""

import numpy as np
import cv2
from PIL import Image
import struct
from typing import List, Dict, Tuple, Optional
import hashlib

class SteganographyDetector:
    """Detect and extract steganographic data"""
    
    @staticmethod
    def detect_lsb_steganography(image_path: str, threshold: float = 0.1) -> Dict:
        """
        Detect LSB (Least Significant Bit) steganography
        threshold: anomaly threshold for detection
        """
        image = cv2.imread(image_path, cv2.IMREAD_COLOR)
        if image is None:
            return {'error': 'Could not read image'}
        
        blue, green, red = cv2.split(image)
        
        results = {
            'lsb_detected': False,
            'channels_with_data': [],
            'entropy_analysis': {},
            'extracted_data': {}
        }
        
        for channel_name, channel in [('Blue', blue), ('Green', green), ('Red', red)]:
            # Extract LSB
            lsb = (channel & 1).astype(np.uint8)
            lsb_image = lsb * 255
            
            # Calculate entropy
            hist, _ = np.histogram(lsb, bins=256)
            entropy = -np.sum((hist / hist.sum()) * np.log2(hist / hist.sum() + 1e-10))
            
            results['entropy_analysis'][channel_name] = {
                'entropy': float(entropy),
                'suspicious': entropy > 7.5
            }
            
            # Check for patterns
            pattern_score = np.sum(np.abs(np.diff(lsb.flatten()))) / len(lsb.flatten())
            
            if pattern_score > threshold:
                results['channels_with_data'].append(channel_name)
                results['extracted_data'][channel_name] = lsb_image
                results['lsb_detected'] = True
        
        return results
    
    @staticmethod
    def extract_lsb_data(image_path: str) -> bytes:
        """
        Extract raw LSB data from image
        """
        image = cv2.imread(image_path, cv2.IMREAD_COLOR)
        if image is None:
            return b''
        
        blue, green, red = cv2.split(image)
        
        # Flatten channels and extract LSBs
        blue_lsb = (blue & 1).flatten()
        green_lsb = (green & 1).flatten()
        red_lsb = (red & 1).flatten()
        
        # Combine LSBs into bytes
        combined = np.concatenate([blue_lsb, green_lsb, red_lsb])
        
        # Convert bit array to bytes
        data = np.packbits(combined)
        
        return data.tobytes()
    
    @staticmethod
    def detect_dct_steganography(image_path: str) -> Dict:
        """
        Detect DCT (Discrete Cosine Transform) based steganography
        Used in JPEG compression
        """
        image = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
        if image is None:
            return {}
        
        # Perform DCT
        dct = cv2.dct(np.float32(image))
        
        # Analyze DCT coefficients for anomalies
        dct_flat = dct.flatten()
        
        # Check for non-uniform distribution (sign of steganography)
        suspicious_coefficients = np.sum(np.abs(dct_flat) < 0.1)
        
        return {
            'suspicious_dct_coefficients': int(suspicious_coefficients),
            'potential_dct_steganography': suspicious_coefficients > len(dct_flat) * 0.3
        }
    
    @staticmethod
    def detect_spread_spectrum(image_path: str) -> Dict:
        """
        Detect spread spectrum steganography
        """
        image = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
        if image is None:
            return {}
        
        # Perform FFT
        fft = np.fft.fft2(image)
        fft_shift = np.fft.fftshift(fft)
        magnitude = np.abs(fft_shift)
        
        # Analyze frequency distribution
        mean_magnitude = np.mean(magnitude)
        std_magnitude = np.std(magnitude)
        
        # Look for energy concentration (sign of steganography)
        anomalies = np.sum(magnitude > mean_magnitude + 3 * std_magnitude)
        
        return {
            'frequency_anomalies': int(anomalies),
            'mean_magnitude': float(mean_magnitude),
            'std_magnitude': float(std_magnitude),
            'potential_spread_spectrum': anomalies > 100
        }
    
    @staticmethod
    def detect_all_steganography(image_path: str) -> Dict:
        """
        Comprehensive steganography detection
        """
        results = {
            'lsb': SteganographyDetector.detect_lsb_steganography(image_path),
            'dct': SteganographyDetector.detect_dct_steganography(image_path),
            'spread_spectrum': SteganographyDetector.detect_spread_spectrum(image_path),
            'overall_verdict': 'No steganography detected'
        }
        
        # Determine overall verdict
        if results['lsb'].get('lsb_detected'):
            results['overall_verdict'] = 'LSB Steganography Likely Detected'
        elif results['dct'].get('potential_dct_steganography'):
            results['overall_verdict'] = 'DCT Steganography Possibly Detected'
        elif results['spread_spectrum'].get('potential_spread_spectrum'):
            results['overall_verdict'] = 'Spread Spectrum Steganography Possibly Detected'
        
        return results


class HiddenDataExtractor:
    """Extract hidden data from various sources"""
    
    @staticmethod
    def extract_metadata_streams(image_path: str) -> Dict:
        """
        Extract metadata and embedded streams
        """
        image = Image.open(image_path)
        metadata = {
            'basic_info': {
                'format': image.format,
                'size': image.size,
                'mode': image.mode
            },
            'all_metadata': {}
        }
        
        for key, value in image.info.items():
            metadata['all_metadata'][key] = str(value)
        
        return metadata
    
    @staticmethod
    def extract_thumbnail_data(image_path: str) -> Optional[np.ndarray]:
        """
        Extract hidden thumbnail data
        """
        try:
            image = Image.open(image_path)
            
            if hasattr(image, 'thumbnail'):
                # Some images have hidden thumbnails
                image.thumbnail((500, 500))
                return np.array(image)
        except Exception as e:
            pass
        
        return None
    
    @staticmethod
    def search_for_file_signatures(image_path: str) -> List[Dict]:
        """
        Search for embedded files using magic numbers/signatures
        """
        signatures = {
            b'\xFF\xD8\xFF': 'JPEG',
            b'\x89PNG': 'PNG',
            b'%PDF': 'PDF',
            b'PK\x03\x04': 'ZIP',
            b'\x1F\x8B\x08': 'GZIP',
            b'BM': 'BMP',
            b'GIF': 'GIF'
        }
        
        found_signatures = []
        
        try:
            with open(image_path, 'rb') as f:
                data = f.read()
            
            for signature, file_type in signatures.items():
                positions = []
                for i in range(len(data) - len(signature)):
                    if data[i:i+len(signature)] == signature:
                        positions.append(i)
                
                if positions:
                    found_signatures.append({
                        'file_type': file_type,
                        'signature': signature.hex(),
                        'positions': positions,
                        'count': len(positions)
                    })
        except Exception as e:
            pass
        
        return found_signatures
    
    @staticmethod
    def extract_embedded_files(image_path: str, output_dir: str) -> List[str]:
        """
        Extract any embedded files from image
        """
        extracted_files = []
        
        signatures = {
            b'\xFF\xD8\xFF': ('jpg', 'JPEG'),
            b'\x89PNG': ('png', 'PNG'),
            b'%PDF': ('pdf', 'PDF'),
            b'PK\x03\x04': ('zip', 'ZIP')
        }
        
        try:
            with open(image_path, 'rb') as f:
                data = f.read()
            
            for signature, (ext, name) in signatures.items():
                pos = 0
                while True:
                    pos = data.find(signature, pos)
                    if pos == -1:
                        break
                    
                    # Find end marker (simplified)
                    filename = f"{output_dir}/extracted_{len(extracted_files)}.{ext}"
                    
                    # Extract and save
                    with open(filename, 'wb') as f:
                        f.write(data[pos:pos+100000])  # Extract next 100KB
                    
                    extracted_files.append(filename)
                    pos += len(signature)
        except Exception as e:
            pass
        
        return extracted_files


class EncryptionAnalyzer:
    """Analyze for encryption and obfuscation"""
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy
        High entropy indicates encryption/compression
        """
        if not data:
            return 0.0
        
        entropy = 0.0
        for i in range(256):
            p = data.count(bytes([i])) / len(data)
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy
    
    @staticmethod
    def detect_encryption(image_path: str) -> Dict:
        """
        Detect encrypted data in image
        """
        try:
            with open(image_path, 'rb') as f:
                data = f.read()
            
            entropy = EncryptionAnalyzer.calculate_entropy(data)
            
            # Analyze different segments
            segments = {
                'header': data[:1000],
                'middle': data[len(data)//2:len(data)//2+1000],
                'tail': data[-1000:]
            }
            
            segment_entropies = {
                name: EncryptionAnalyzer.calculate_entropy(seg)
                for name, seg in segments.items()
            }
            
            return {
                'overall_entropy': float(entropy),
                'segment_entropies': {k: float(v) for k, v in segment_entropies.items()},
                'likely_encrypted': entropy > 7.5,
                'encryption_type': EncryptionAnalyzer._identify_encryption_type(entropy)
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def _identify_encryption_type(entropy: float) -> str:
        """Identify likely encryption algorithm based on entropy"""
        if entropy > 7.9:
            return 'Strong Encryption (AES, RSA, etc.)'
        elif entropy > 7.5:
            return 'Likely Encrypted Data'
        elif entropy > 6.5:
            return 'Possible Encryption or Compression'
        else:
            return 'No Encryption Detected'
    
    @staticmethod
    def detect_obfuscation(data: bytes) -> Dict:
        """
        Detect obfuscated/compressed data patterns
        """
        # Check for common compression signatures
        compression_sigs = {
            'GZIP': b'\x1f\x8b\x08',
            'ZIP': b'PK\x03\x04',
            'BZIP2': b'BZ',
            '7ZIP': b'7z\xbc\xaf\x27\x1c'
        }
        
        detected = []
        for name, sig in compression_sigs.items():
            if sig in data:
                detected.append(name)
        
        entropy = EncryptionAnalyzer.calculate_entropy(data)
        
        return {
            'compression_detected': detected,
            'entropy_score': float(entropy),
            'likely_obfuscated': entropy > 7.5 or len(detected) > 0
        }