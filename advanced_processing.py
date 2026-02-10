"""
Advanced image and PDF processing module with encryption detection
and steganography analysis
"""

import cv2
import numpy as np
import PyPDF2
from PIL import Image
import os
from pathlib import Path
from scipy import stats
from typing import List, Dict, Tuple, Optional
import hashlib
import struct
from datetime import datetime

class AdvancedImageProcessor:
    """Advanced image processing with multiple algorithms"""
    
    @staticmethod
    def detect_blocks_advanced(image_path: str) -> Tuple[np.ndarray, np.ndarray, List[Dict]]:
        """
        Advanced block detection using multiple methods
        Returns: processed image, mask, and detection info
        """
        image = cv2.imread(image_path)
        if image is None:
            return None, None, []
        
        original = image.copy()
        blocks_info = []
        
        # Method 1: Color-based detection
        hsv = cv2.cvtColor(image, cv2.COLOR_BGR2HSV)
        
        # Detect black blocks
        lower_black = np.array([0, 0, 0])
        upper_black = np.array([180, 255, 50])
        mask_black = cv2.inRange(hsv, lower_black, upper_black)
        
        # Detect white/light blocks
        lower_white = np.array([0, 0, 200])
        upper_white = np.array([180, 30, 255])
        mask_white = cv2.inRange(hsv, lower_white, upper_white)
        
        # Detect gray blocks
        lower_gray = np.array([0, 0, 50])
        upper_gray = np.array([180, 50, 200])
        mask_gray = cv2.inRange(hsv, lower_gray, upper_gray)
        
        combined_mask = cv2.bitwise_or(mask_black, mask_white)
        combined_mask = cv2.bitwise_or(combined_mask, mask_gray)
        
        # Find contours
        contours, _ = cv2.findContours(combined_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        for contour in contours:
            area = cv2.contourArea(contour)
            if area > 100:  # Minimum block size
                x, y, w, h = cv2.boundingRect(contour)
                blocks_info.append({
                    'x': int(x),
                    'y': int(y),
                    'width': int(w),
                    'height': int(h),
                    'area': int(area),
                    'type': 'block'
                })
        
        # Method 2: Edge-based detection
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        edges = cv2.Canny(gray, 100, 200)
        lines = cv2.HoughLinesP(edges, 1, np.pi/180, 50, minLineLength=100, maxLineGap=10)
        
        if lines is not None:
            for line in lines:
                x1, y1, x2, y2 = line[0]
                blocks_info.append({
                    'type': 'line',
                    'x1': int(x1), 'y1': int(y1),
                    'x2': int(x2), 'y2': int(y2)
                })
        
        # Inpaint to remove blocks
        kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (7, 7))
        dilated = cv2.dilate(combined_mask, kernel, iterations=2)
        inpainted = cv2.inpaint(original, dilated, 5, cv2.INPAINT_TELEA)
        
        return inpainted, combined_mask, blocks_info
    
    @staticmethod
    def extract_multiple_bitplanes(image_path: str) -> Dict[str, np.ndarray]:
        """
        Extract all bit planes for steganography analysis
        """
        image = cv2.imread(image_path, cv2.IMREAD_COLOR)
        if image is None:
            return {}
        
        bitplanes = {}
        blue, green, red = cv2.split(image)
        
        for channel_name, channel in [('Blue', blue), ('Green', green), ('Red', red)]:
            for bit in range(8):
                bitplane = ((channel >> bit) & 1) * 255
                key = f"{channel_name}_Bit_{bit}"
                bitplanes[key] = bitplane
        
        return bitplanes
    
    @staticmethod
    def analyze_color_channels(image_path: str) -> Dict:
        """
        Analyze color channel distribution for anomalies
        """
        image = cv2.imread(image_path, cv2.COLOR_BGR2RGB)
        if image is None:
            return {}
        
        blue, green, red = cv2.split(image)
        
        analysis = {
            'blue': {
                'mean': float(np.mean(blue)),
                'std': float(np.std(blue)),
                'min': int(np.min(blue)),
                'max': int(np.max(blue)),
                'entropy': float(stats.entropy(np.histogram(blue, 256)[0]))
            },
            'green': {
                'mean': float(np.mean(green)),
                'std': float(np.std(green)),
                'min': int(np.min(green)),
                'max': int(np.max(green)),
                'entropy': float(stats.entropy(np.histogram(green, 256)[0]))
            },
            'red': {
                'mean': float(np.mean(red)),
                'std': float(np.std(red)),
                'min': int(np.min(red)),
                'max': int(np.max(red)),
                'entropy': float(stats.entropy(np.histogram(red, 256)[0]))
            }
        }
        
        return analysis
    
    @staticmethod
    def detect_watermarks(image_path: str) -> Dict:
        """
        Detect potential watermarks or steganographic markers
        """
        image = cv2.imread(image_path)
        if image is None:
            return {}
        
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # Frequency domain analysis
        fft = np.fft.fft2(gray)
        fft_shift = np.fft.fftshift(fft)
        magnitude = 20 * np.log(np.abs(fft_shift) + 1)
        
        # Find peaks in frequency domain (potential watermarks)
        threshold = np.percentile(magnitude, 95)
        peaks = np.where(magnitude > threshold)
        
        return {
            'potential_watermarks': len(peaks[0]),
            'frequency_anomalies': int(np.sum(magnitude > threshold)),
            'max_magnitude': float(np.max(magnitude))
        }


class AdvancedPDFProcessor:
    """Advanced PDF processing with metadata and content analysis"""
    
    @staticmethod
    def extract_pdf_metadata(pdf_path: str) -> Dict:
        """
        Extract comprehensive PDF metadata
        """
        try:
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                metadata = pdf_reader.metadata if pdf_reader.metadata else {}
                
                info = {
                    'title': metadata.get('/Title', 'Unknown'),
                    'author': metadata.get('/Author', 'Unknown'),
                    'subject': metadata.get('/Subject', 'Unknown'),
                    'creator': metadata.get('/Creator', 'Unknown'),
                    'producer': metadata.get('/Producer', 'Unknown'),
                    'creation_date': str(metadata.get('/CreationDate', 'Unknown')),
                    'modification_date': str(metadata.get('/ModDate', 'Unknown')),
                    'total_pages': len(pdf_reader.pages),
                    'is_encrypted': pdf_reader.is_encrypted
                }
                
                return info
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def extract_all_pdf_objects(pdf_path: str) -> Dict:
        """
        Extract all objects from PDF including hidden streams
        """
        try:
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                
                objects = {
                    'images': [],
                    'text_streams': [],
                    'annotations': [],
                    'fonts': [],
                    'other_objects': []
                }
                
                for page_num, page in enumerate(pdf_reader.pages):
                    if "/XObject" in page["/Resources"]:
                        xobjects = page["/Resources"]["/XObject"].get_object()
                        for obj_name in xobjects:
                            obj = xobjects[obj_name].get_object()
                            if obj["/Subtype"] == "/Image":
                                objects['images'].append({
                                    'page': page_num,
                                    'name': str(obj_name),
                                    'width': obj.get("/Width", 0),
                                    'height': obj.get("/Height", 0)
                                })
                    
                    # Extract text streams
                    if "/Contents" in page:
                        objects['text_streams'].append({
                            'page': page_num,
                            'has_content': True
                        })
                    
                    # Extract annotations
                    if "/Annots" in page:
                        annots = page["/Annots"]
                        objects['annotations'].append({
                            'page': page_num,
                            'count': len(annots)
                        })
                
                return objects
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def remove_pdf_annotations_advanced(pdf_path: str, output_path: str) -> bool:
        """
        Advanced PDF cleaning - remove all annotations, hidden content
        """
        try:
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                pdf_writer = PyPDF2.PdfWriter()
                
                for page_num in range(len(pdf_reader.pages)):
                    page = pdf_reader.pages[page_num]
                    
                    # Remove annotations
                    if "/Annots" in page:
                        del page["/Annots"]
                    
                    # Remove AcroForm (form fields)
                    if "/AcroForm" in pdf_reader.trailer["/Root"]:
                        del pdf_reader.trailer["/Root"]["/AcroForm"]
                    
                    # Remove optional content
                    if "/OCProperties" in page:
                        del page["/OCProperties"]
                    
                    pdf_writer.add_page(page)
                
                with open(output_path, 'wb') as output_file:
                    pdf_writer.write(output_file)
                
                return True
        except Exception as e:
            print(f"Error: {e}")
            return False


class ImageForensics:
    """Image forensics and anomaly detection"""
    
    @staticmethod
    def analyze_jpeg_artifacts(image_path: str) -> Dict:
        """
        Analyze JPEG compression artifacts
        """
        image = cv2.imread(image_path)
        if image is None:
            return {}
        
        # Convert to YCbCr for JPEG analysis
        image_ycbcr = cv2.cvtColor(image, cv2.COLOR_BGR2YCrCb)
        
        # Analyze 8x8 block boundaries
        y_channel = image_ycbcr[:,:,0]
        
        # Detect grid pattern (8x8 blocks)
        artifact_score = 0
        for i in range(8, y_channel.shape[0], 8):
            line = y_channel[i, :]
            diff = np.abs(np.diff(line))
            artifact_score += np.sum(diff > 10)
        
        for j in range(8, y_channel.shape[1], 8):
            line = y_channel[:, j]
            diff = np.abs(np.diff(line))
            artifact_score += np.sum(diff > 10)
        
        return {
            'artifact_score': float(artifact_score),
            'possible_tampering': artifact_score > 1000
        }
    
    @staticmethod
    def detect_copy_move(image_path: str) -> Dict:
        """
        Detect copy-move forgery in images
        """
        image = cv2.imread(image_path)
        if image is None:
            return {}
        
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # SIFT feature detection
        sift = cv2.SIFT_create()
        keypoints, descriptors = sift.detectAndCompute(gray, None)
        
        if descriptors is None or len(keypoints) < 2:
            return {'keypoints_found': 0, 'potential_forgery': False}
        
        # Find matches
        bf = cv2.BFMatcher()
        matches = bf.knnMatch(descriptors, descriptors, k=2)
        
        # Apply Lowe's ratio test
        good_matches = 0
        for match_pair in matches:
            if len(match_pair) == 2:
                m, n = match_pair
                if m.distance < 0.75 * n.distance:
                    good_matches += 1
        
        return {
            'keypoints_found': len(keypoints),
            'duplicate_regions': good_matches,
            'potential_copy_move': good_matches > 10
        }
    
    @staticmethod
    def noise_analysis(image_path: str) -> Dict:
        """
        Analyze noise patterns for anomalies
        """
        image = cv2.imread(image_path)
        if image is None:
            return {}
        
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY).astype(float)
        
        # Laplacian variance (blur detection)
        laplacian = cv2.Laplacian(gray, cv2.CV_64F)
        blur_score = laplacian.var()
        
        # Noise estimation
        laplacian_kernel = np.array([[-1, -1, -1],
                                     [-1,  8, -1],
                                     [-1, -1, -1]])
        noise_map = cv2.filter2D(gray, cv2.CV_64F, laplacian_kernel)
        noise_level = np.std(noise_map)
        
        return {
            'blur_score': float(blur_score),
            'noise_level': float(noise_level),
            'likely_edited': blur_score < 100 or noise_level < 5
        }


class ExifDataExtractor:
    """Extract and analyze EXIF metadata"""
    
    @staticmethod
    def extract_exif(image_path: str) -> Dict:
        """
        Extract EXIF data from images
        """
        from PIL import Image
        from PIL.ExifTags import TAGS
        
        try:
            image = Image.open(image_path)
            exif_data = image._getexif()
            
            if not exif_data:
                return {'exif_available': False}
            
            exif_dict = {}
            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, tag_id)
                exif_dict[tag_name] = str(value)
            
            return {'exif_available': True, 'data': exif_dict}
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def check_exif_anomalies(exif_data: Dict) -> Dict:
        """
        Detect anomalies in EXIF data (potential tampering indicator)
        """
        anomalies = []
        
        if not exif_data.get('exif_available'):
            anomalies.append('No EXIF data found')
        
        # Check for suspicious modifications
        data = exif_data.get('data', {})
        
        if 'Software' in data:
            software = data['Software'].lower()
            if 'photoshop' in software or 'gimp' in software:
                anomalies.append('Image potentially edited with advanced software')
        
        if 'DateTime' in data and 'DateTimeOriginal' in data:
            if data['DateTime'] != data['DateTimeOriginal']:
                anomalies.append('Modification date differs from original date')
        
        return {
            'anomalies_detected': len(anomalies),
            'anomalies': anomalies,
            'possible_tampering': len(anomalies) > 0
        }