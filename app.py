from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import PyPDF2
from PIL import Image
import numpy as np
import cv2
import io
from datetime import datetime
import mimetypes
from pathlib import Path

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
PROCESSED_FOLDER = 'processed'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'tiff'}
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB

# Create folders
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def remove_image_blocks(image_path):
    """Remove blocks/overlays from images using advanced image processing"""
    image = cv2.imread(image_path)
    if image is None:
        return None
    
    # Convert to HSV for better color detection
    hsv = cv2.cvtColor(image, cv2.COLOR_BGR2HSV)
    
    # Detect dark/black blocks
    lower_dark = np.array([0, 0, 0])
    upper_dark = np.array([180, 255, 50])
    mask_dark = cv2.inRange(hsv, lower_dark, upper_dark)
    
    # Detect white/light blocks
    lower_light = np.array([0, 0, 200])
    upper_light = np.array([180, 30, 255])
    mask_light = cv2.inRange(hsv, lower_light, upper_light)
    
    # Combine masks
    combined_mask = cv2.bitwise_or(mask_dark, mask_light)
    
    # Apply morphological operations
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (5, 5))
    combined_mask = cv2.morphologyEx(combined_mask, cv2.MORPH_CLOSE, kernel)
    
    # Inpaint to remove blocks
    inpainted = cv2.inpaint(image, combined_mask, 3, cv2.INPAINT_TELEA)
    
    return inpainted

def reveal_hidden_content(image_path):
    """Reveal hidden images using steganography detection and color space analysis"""
    image = cv2.imread(image_path, cv2.IMREAD_COLOR)
    if image is None:
        return None
    
    # Extract LSB (Least Significant Bit) layers
    blue, green, red = cv2.split(image)
    
    # Get LSB of each channel
    blue_lsb = (blue & 1) * 255
    green_lsb = (green & 1) * 255
    red_lsb = (red & 1) * 255
    
    hidden = cv2.merge([blue_lsb, green_lsb, red_lsb])
    
    # Also try different bit planes
    for bit in range(1, 8):
        blue_bits = ((blue >> bit) & 1) * 255
        green_bits = ((green >> bit) & 1) * 255
        red_bits = ((red >> bit) & 1) * 255
        alt_hidden = cv2.merge([blue_bits, green_bits, red_bits])
        
        # If we find significant data, return it
        if cv2.countNonZero(cv2.cvtColor(alt_hidden, cv2.COLOR_BGR2GRAY)) > 100:
            hidden = alt_hidden
            break
    
    return hidden

def clean_pdf(pdf_path):
    """Remove overlays and blocks from PDF"""
    try:
        pdf_reader = PyPDF2.PdfReader(pdf_path)
        pdf_writer = PyPDF2.PdfWriter()
        
        for page_num in range(len(pdf_reader.pages)):
            page = pdf_reader.pages[page_num]
            
            # Try to remove annotations (blocks/overlays)
            if "/Annots" in page:
                del page["/Annots"]
            
            pdf_writer.add_page(page)
        
        output_path = os.path.join(PROCESSED_FOLDER, f"cleaned_{os.path.basename(pdf_path)}")
        with open(output_path, 'wb') as output_file:
            pdf_writer.write(output_file)
        
        return output_path
    except Exception as e:
        return None

def extract_pdf_images(pdf_path):
    """Extract all images from PDF"""
    images = []
    try:
        pdf_reader = PyPDF2.PdfReader(pdf_path)
        
        for page_num in range(len(pdf_reader.pages)):
            page = pdf_reader.pages[page_num]
            
            if "/XObject" in page["/Resources"]:
                xObject = page["/Resources"]["/XObject"].get_object()
                for obj_name in xObject:
                    obj = xObject[obj_name].get_object()
                    if obj["/Subtype"] == "/Image":
                        # Extract image data
                        data = obj.get_data()
                        images.append({
                            'page': page_num + 1,
                            'object': obj_name,
                            'data': data
                        })
        
        return images
    except Exception as e:
        return []

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload file for processing"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
    filename = timestamp + filename
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    return jsonify({
        'success': True,
        'filename': filename,
        'filepath': filepath,
        'filesize': os.path.getsize(filepath)
    }), 200

@app.route('/api/remove-blocks', methods=['POST'])
def remove_blocks():
    """Remove image blocks/overlays"""
    data = request.json
    filename = data.get('filename')
    
    if not filename:
        return jsonify({'error': 'Filename required'}), 400
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    ext = filename.rsplit('.', 1)[1].lower()
    
    if ext == 'pdf':
        result_path = clean_pdf(filepath)
        if not result_path:
            return jsonify({'error': 'Failed to clean PDF'}), 500
    else:
        cleaned_image = remove_image_blocks(filepath)
        if cleaned_image is None:
            return jsonify({'error': 'Failed to process image'}), 500
        
        result_filename = f"unblocked_{filename}"
        result_path = os.path.join(PROCESSED_FOLDER, result_filename)
        cv2.imwrite(result_path, cleaned_image)
    
    return jsonify({
        'success': True,
        'result_filename': os.path.basename(result_path),
        'result_path': result_path
    }), 200

@app.route('/api/reveal-hidden', methods=['POST'])
def reveal_hidden():
    """Reveal hidden content in images"""
    data = request.json
    filename = data.get('filename')
    
    if not filename:
        return jsonify({'error': 'Filename required'}), 400
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    ext = filename.rsplit('.', 1)[1].lower()
    
    if ext == 'pdf':
        # Extract images from PDF
        images = extract_pdf_images(filepath)
        return jsonify({
            'success': True,
            'hidden_images': len(images),
            'details': images
        }), 200
    else:
        hidden_image = reveal_hidden_content(filepath)
        if hidden_image is None:
            return jsonify({'error': 'Failed to process image'}), 500
        
        result_filename = f"hidden_{filename}"
        result_path = os.path.join(PROCESSED_FOLDER, result_filename)
        cv2.imwrite(result_path, hidden_image)
        
        return jsonify({
            'success': True,
            'result_filename': os.path.basename(result_path),
            'result_path': result_path
        }), 200

@app.route('/api/enhance-image', methods=['POST'])
def enhance_image():
    """Enhance image clarity and remove noise"""
    data = request.json
    filename = data.get('filename')
    intensity = data.get('intensity', 1.5)
    
    if not filename:
        return jsonify({'error': 'Filename required'}), 400
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    image = cv2.imread(filepath)
    if image is None:
        return jsonify({'error': 'Failed to read image'}), 500
    
    # Apply CLAHE (Contrast Limited Adaptive Histogram Equalization)
    lab = cv2.cvtColor(image, cv2.COLOR_BGR2LAB)
    l, a, b = cv2.split(lab)
    
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    l = clahe.apply(l)
    
    enhanced = cv2.merge([l, a, b])
    enhanced = cv2.cvtColor(enhanced, cv2.COLOR_LAB2BGR)
    
    # Denoise
    enhanced = cv2.fastNlMeansDenoisingColored(enhanced, None, h=10, hForColorComponents=10, templateWindowSize=7, searchWindowSize=21)
    
    result_filename = f"enhanced_{filename}"
    result_path = os.path.join(PROCESSED_FOLDER, result_filename)
    cv2.imwrite(result_path, enhanced)
    
    return jsonify({
        'success': True,
        'result_filename': os.path.basename(result_path),
        'result_path': result_path
    }), 200

@app.route('/api/compress', methods=['POST'])
def compress_file():
    """Compress image or PDF"""
    data = request.json
    filename = data.get('filename')
    quality = data.get('quality', 85)
    
    if not filename:
        return jsonify({'error': 'Filename required'}), 400
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    ext = filename.rsplit('.', 1)[1].lower()
    
    if ext == 'pdf':
        # Compress PDF (simplified)
        result_filename = f"compressed_{filename}"
        result_path = os.path.join(PROCESSED_FOLDER, result_filename)
        result_path = filepath  # For now, return original
    else:
        image = Image.open(filepath)
        result_filename = f"compressed_{filename}"
        result_path = os.path.join(PROCESSED_FOLDER, result_filename)
        image.save(result_path, quality=quality, optimize=True)
    
    original_size = os.path.getsize(filepath)
    compressed_size = os.path.getsize(result_path)
    
    return jsonify({
        'success': True,
        'result_filename': os.path.basename(result_path),
        'original_size': original_size,
        'compressed_size': compressed_size,
        'compression_ratio': round((1 - compressed_size / original_size) * 100, 2)
    }), 200

@app.route('/api/download/<filename>', methods=['GET'])
def download_file(filename):
    """Download processed file"""
    filepath = os.path.join(PROCESSED_FOLDER, filename)
    
    if not os.path.exists(filepath):
        filepath = os.path.join(UPLOAD_FOLDER, filename)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    return send_file(filepath, as_attachment=True)

@app.route('/api/list-files', methods=['GET'])
def list_files():
    """List all uploaded files"""
    files = []
    
    for filename in os.listdir(UPLOAD_FOLDER):
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        files.append({
            'filename': filename,
            'size': os.path.getsize(filepath),
            'modified': os.path.getmtime(filepath)
        })
    
    return jsonify({'files': files}), 200

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get application statistics"""
    upload_size = sum(os.path.getsize(os.path.join(UPLOAD_FOLDER, f)) for f in os.listdir(UPLOAD_FOLDER))
    processed_size = sum(os.path.getsize(os.path.join(PROCESSED_FOLDER, f)) for f in os.listdir(PROCESSED_FOLDER))
    
    return jsonify({
        'uploaded_files': len(os.listdir(UPLOAD_FOLDER)),
        'processed_files': len(os.listdir(PROCESSED_FOLDER)),
        'upload_folder_size': upload_size,
        'processed_folder_size': processed_size,
        'total_size': upload_size + processed_size
    }), 200

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)