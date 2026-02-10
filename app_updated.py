from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from advanced_processing import AdvancedImageProcessor, AdvancedPDFProcessor, ImageForensics, ExifDataExtractor
from hidden_data_recovery import SteganographyDetector, HiddenDataExtractor, EncryptionAnalyzer
from encryption_detector import EncryptionDetector, EncryptionKeyAnalyzer
from batch_processor import BatchProcessor, BatchJobManager
import cv2
import numpy as np

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
PROCESSED_FOLDER = 'processed'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'tiff'}
MAX_FILE_SIZE = 500 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Initialize batch processor
batch_processor = BatchProcessor(num_workers=4)
batch_processor.start()
job_manager = BatchJobManager()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ADVANCED ANALYSIS ENDPOINTS

@app.route('/api/advanced/analyze-image', methods=['POST'])
def analyze_image_advanced():
    """Comprehensive image analysis"""
    data = request.json
    filename = data.get('filename')
    
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    results = {
        'filename': filename,
        'analysis': {
            'block_detection': AdvancedImageProcessor.detect_blocks_advanced(filepath)[2],
            'color_analysis': AdvancedImageProcessor.analyze_color_channels(filepath),
            'watermark_detection': AdvancedImageProcessor.detect_watermarks(filepath),
            'jpeg_artifacts': ImageForensics.analyze_jpeg_artifacts(filepath),
            'copy_move_detection': ImageForensics.detect_copy_move(filepath),
            'noise_analysis': ImageForensics.noise_analysis(filepath),
            'steganography': SteganographyDetector.detect_all_steganography(filepath),
            'encryption': EncryptionDetector.comprehensive_encryption_analysis(filepath)
        }
    }
    
    return jsonify(results), 200

@app.route('/api/advanced/pdf-analysis', methods=['POST'])
def analyze_pdf_advanced():
    """Comprehensive PDF analysis"""
    data = request.json
    filename = data.get('filename')
    
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    results = {
        'filename': filename,
        'analysis': {
            'metadata': AdvancedPDFProcessor.extract_pdf_metadata(filepath),
            'objects': AdvancedPDFProcessor.extract_all_pdf_objects(filepath),
            'encryption': EncryptionDetector.comprehensive_encryption_analysis(filepath)
        }
    }
    
    return jsonify(results), 200

@app.route('/api/advanced/steganography-detection', methods=['POST'])
def detect_steganography():
    """Detect steganographic content"""
    data = request.json
    filename = data.get('filename')
    
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    # Extract LSB data
    lsb_data = SteganographyDetector.extract_lsb_data(filepath)
    
    # Find file signatures
    signatures = HiddenDataExtractor.search_for_file_signatures(filepath)
    
    results = {
        'steganography_analysis': SteganographyDetector.detect_all_steganography(filepath),
        'lsb_data_extracted': len(lsb_data),
        'embedded_files': signatures
    }
    
    return jsonify(results), 200

@app.route('/api/advanced/extract-hidden', methods=['POST'])
def extract_hidden_content():
    """Extract hidden embedded content"""
    data = request.json
    filename = data.get('filename')
    
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    # Create output directory for extracted files
    extract_dir = os.path.join(PROCESSED_FOLDER, f"extracted_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    os.makedirs(extract_dir, exist_ok=True)
    
    extracted_files = HiddenDataExtractor.extract_embedded_files(filepath, extract_dir)
    
    results = {
        'files_extracted': len(extracted_files),
        'files': [os.path.basename(f) for f in extracted_files],
        'extract_directory': extract_dir
    }
    
    return jsonify(results), 200

@app.route('/api/advanced/encryption-analysis', methods=['POST'])
def analyze_encryption():
    """Analyze encryption strength and type"""
    data = request.json
    filename = data.get('filename')
    
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    analysis = EncryptionDetector.comprehensive_encryption_analysis(filepath)
    
    return jsonify(analysis), 200

# BATCH PROCESSING ENDPOINTS

@app.route('/api/batch/create-job', methods=['POST'])
def create_batch_job():
    """Create new batch job"""
    data = request.json
    name = data.get('name', 'Untitled Job')
    description = data.get('description', '')
    
    job_id = job_manager.create_job(name, description)
    
    return jsonify({
        'job_id': job_id,
        'status': 'created'
    }), 201

@app.route('/api/batch/add-tasks', methods=['POST'])
def add_batch_tasks():
    """Add tasks to batch job"""
    data = request.json
    job_id = data.get('job_id')
    tasks = data.get('tasks', [])
    
    if not job_id:
        return jsonify({'error': 'job_id required'}), 400
    
    try:
        job_manager.add_tasks_to_job(job_id, tasks)
        
        # Add to processor queue
        for task in tasks:
            batch_processor.add_task(task)
        
        return jsonify({
            'job_id': job_id,
            'tasks_added': len(tasks)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/batch/status/<job_id>', methods=['GET'])
def get_batch_status(job_id):
    """Get batch job status"""
    job = job_manager.get_job(job_id)
    
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    
    processor_status = batch_processor.get_status()
    
    return jsonify({
        'job': job,
        'processor_status': processor_status
    }), 200

@app.route('/api/batch/results/<job_id>', methods=['GET'])
def get_batch_results(job_id):
    """Get batch job results"""
    job = job_manager.get_job(job_id)
    
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    
    # Get fresh results from queue
    results = batch_processor.get_all_results()
    for result in results:
        job_manager.add_result_to_job(job_id, result)
    
    return jsonify({
        'job_id': job_id,
        'results': job['results']
    }), 200

@app.route('/api/batch/list-jobs', methods=['GET'])
def list_batch_jobs():
    """List all batch jobs"""
    jobs = job_manager.list_jobs()
    
    return jsonify({
        'total_jobs': len(jobs),
        'jobs': jobs
    }), 200

# UTILITY ENDPOINTS

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload file"""
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
    
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    return jsonify({
        'success': True,
        'filename': filename,
        'filesize': os.path.getsize(filepath)
    }), 200

@app.route('/api/download/<filename>', methods=['GET'])
def download_file(filename):
    """Download file"""
    filepath = os.path.join(PROCESSED_FOLDER, filename)
    
    if not os.path.exists(filepath):
        filepath = os.path.join(UPLOAD_FOLDER, filename)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    return send_file(filepath, as_attachment=True)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'batch_processor': batch_processor.get_status()
    }), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)