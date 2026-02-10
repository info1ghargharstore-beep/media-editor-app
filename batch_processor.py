"""
Batch processing with queue management and concurrent processing
"""

import os
import json
import threading
import queue
from pathlib import Path
from typing import List, Dict, Callable, Optional
from datetime import datetime
import logging

class BatchProcessor:
    """Handle batch processing of multiple files"""
    
    def __init__(self, num_workers: int = 4, max_queue_size: int = 100):
        """
        Initialize batch processor
        
        Args:
            num_workers: Number of concurrent workers
            max_queue_size: Maximum size of processing queue
        """
        self.task_queue = queue.Queue(maxsize=max_queue_size)
        self.result_queue = queue.Queue()
        self.num_workers = num_workers
        self.workers = []
        self.active = False
        self.task_count = 0
        self.completed_count = 0
        self.failed_count = 0
        self.lock = threading.Lock()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def start(self):
        """Start batch processor workers"""
        if self.active:
            return
        
        self.active = True
        
        for i in range(self.num_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"Worker-{i}",
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
        
        self.logger.info(f"Started {self.num_workers} workers")
    
    def stop(self):
        """Stop batch processor"""
        self.active = False
        
        # Wait for queue to be empty
        self.task_queue.join()
        
        self.logger.info("Batch processor stopped")
    
    def add_task(self, task: Dict):
        """
        Add task to processing queue
        
        Args:
            task: Task dictionary with 'file', 'operation', and 'params'
        """
        with self.lock:
            self.task_count += 1
        
        self.task_queue.put(task)
    
    def add_tasks(self, tasks: List[Dict]):
        """Add multiple tasks"""
        for task in tasks:
            self.add_task(task)
    
    def _worker_loop(self):
        """Worker thread loop"""
        while self.active:
            try:
                task = self.task_queue.get(timeout=1)
                
                self.logger.info(f"Processing: {task['file']}")
                
                try:
                    result = self._process_task(task)
                    
                    with self.lock:
                        self.completed_count += 1
                    
                    self.result_queue.put({
                        'status': 'success',
                        'result': result
                    })
                    
                    self.logger.info(f"Completed: {task['file']}")
                    
                except Exception as e:
                    with self.lock:
                        self.failed_count += 1
                    
                    self.logger.error(f"Failed: {task['file']} - {str(e)}")
                    
                    self.result_queue.put({
                        'status': 'failed',
                        'file': task['file'],
                        'error': str(e)
                    })
                
                self.task_queue.task_done()
                
            except queue.Empty:
                continue
    
    def _process_task(self, task: Dict) -> Dict:
        """Process individual task"""
        from advanced_processing import AdvancedImageProcessor, AdvancedPDFProcessor
        from hidden_data_recovery import SteganographyDetector, HiddenDataExtractor
        from encryption_detector import EncryptionAnalyzer
        
        operation = task.get('operation')
        file_path = task.get('file')
        params = task.get('params', {})
        
        if operation == 'remove_blocks':
            processed, mask, info = AdvancedImageProcessor.detect_blocks_advanced(file_path)
            return {
                'operation': operation,
                'blocks_removed': len(info),
                'output_file': file_path.replace('.', '_processed.')
            }
        
        elif operation == 'extract_bitplanes':
            bitplanes = AdvancedImageProcessor.extract_multiple_bitplanes(file_path)
            return {
                'operation': operation,
                'bitplanes_extracted': len(bitplanes)
            }
        
        elif operation == 'detect_steganography':
            results = SteganographyDetector.detect_all_steganography(file_path)
            return {
                'operation': operation,
                'verdict': results['overall_verdict'],
                'details': results
            }
        
        elif operation == 'detect_encryption':
            results = EncryptionAnalyzer.detect_encryption(file_path)
            return {
                'operation': operation,
                'encrypted': results.get('likely_encrypted', False),
                'entropy': results.get('overall_entropy', 0)
            }
        
        elif operation == 'pdf_extract_metadata':
            metadata = AdvancedPDFProcessor.extract_pdf_metadata(file_path)
            return {
                'operation': operation,
                'metadata': metadata
            }
        
        else:
            raise ValueError(f"Unknown operation: {operation}")
    
    def get_results(self) -> Optional[Dict]:
        """Get next result from queue"""
        try:
            return self.result_queue.get_nowait()
        except queue.Empty:
            return None
    
    def get_all_results(self) -> List[Dict]:
        """Get all available results"""
        results = []
        while True:
            result = self.get_results()
            if result is None:
                break
            results.append(result)
        return results
    
    def get_status(self) -> Dict:
        """Get batch processor status"""
        with self.lock:
            return {
                'active': self.active,
                'total_tasks': self.task_count,
                'completed': self.completed_count,
                'failed': self.failed_count,
                'pending': self.task_count - self.completed_count - self.failed_count,
                'queue_size': self.task_queue.qsize(),
                'workers': self.num_workers
            }


class BatchJobManager:
    """Manage batch job history and persistence"""
    
    def __init__(self, jobs_dir: str = 'batch_jobs'):
        """Initialize job manager"""
        self.jobs_dir = jobs_dir
        os.makedirs(jobs_dir, exist_ok=True)
        self.jobs = {}
    
    def create_job(self, name: str, description: str = '') -> str:
        """
        Create new batch job
        
        Returns: job_id
        """
        job_id = f"job_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        job = {
            'id': job_id,
            'name': name,
            'description': description,
            'created_at': datetime.now().isoformat(),
            'tasks': [],
            'results': [],
            'status': 'pending'
        }
        
        self.jobs[job_id] = job
        
        # Save to file
        self._save_job(job_id, job)
        
        return job_id
    
    def add_tasks_to_job(self, job_id: str, tasks: List[Dict]):
        """Add tasks to job"""
        if job_id not in self.jobs:
            raise ValueError(f"Job {job_id} not found")
        
        self.jobs[job_id]['tasks'].extend(tasks)
        self._save_job(job_id, self.jobs[job_id])
    
    def add_result_to_job(self, job_id: str, result: Dict):
        """Add result to job"""
        if job_id not in self.jobs:
            raise ValueError(f"Job {job_id} not found")
        
        self.jobs[job_id]['results'].append(result)
        self._save_job(job_id, self.jobs[job_id])
    
    def get_job(self, job_id: str) -> Dict:
        """Get job details"""
        return self.jobs.get(job_id)
    
    def list_jobs(self) -> List[Dict]:
        """List all jobs"""
        return list(self.jobs.values())
    
    def _save_job(self, job_id: str, job: Dict):
        """Save job to file"""
        job_file = os.path.join(self.jobs_dir, f"{job_id}.json")
        with open(job_file, 'w') as f:
            json.dump(job, f, indent=2)
    
    def _load_job(self, job_id: str) -> Dict:
        """Load job from file"""
        job_file = os.path.join(self.jobs_dir, f"{job_id}.json")
        if os.path.exists(job_file):
            with open(job_file, 'r') as f:
                return json.load(f)
        return None