#!/usr/bin/env python3
"""
AI Chatbot Testing Suite - Web Interface
Modern Flask web application for managing and executing AI chatbot tests
"""

import os
import json
import asyncio
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
import uuid
import logging
from queue import Queue
import subprocess
import signal

# Import our testing modules
from config import ConfigManager, AIProvider, setup_environment
from ai_chatbot_test_suite import AITestSuiteRunner
from api_integration_tests import APIIntegrationTestRunner
from run_tests import generate_reports
try:
    from security_evaluation_framework import SecurityTestSuiteRunner
    from comprehensive_security_test_suite import ComprehensiveSecurityTestRunner
    from adaptive_learning_engine import AdaptiveLearningEngine
    SECURITY_FRAMEWORK_AVAILABLE = True
    COMPREHENSIVE_FRAMEWORK_AVAILABLE = True
    ADAPTIVE_LEARNING_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Some frameworks not available: {e}")
    SECURITY_FRAMEWORK_AVAILABLE = False
    COMPREHENSIVE_FRAMEWORK_AVAILABLE = False
    ADAPTIVE_LEARNING_AVAILABLE = False
    SecurityTestSuiteRunner = None
    ComprehensiveSecurityTestRunner = None
    AdaptiveLearningEngine = None

# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'ai-testing-suite-secret-key-change-in-production')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global variables for test execution
active_tests = {}
test_results_cache = {}
config_manager = ConfigManager()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TestExecutor:
    """Handles test execution in background threads"""
    
    def __init__(self, test_id: str, socketio_instance):
        self.test_id = test_id
        self.socketio = socketio_instance
        self.status = "pending"
        self.progress = 0
        self.results = {}
        self.start_time = None
        self.end_time = None
        self.thread = None
        self.cancelled = False
    
    def start_test(self, test_config):
        """Start test execution in background thread"""
        self.start_time = datetime.now()
        self.status = "running"
        self.thread = threading.Thread(target=self._run_test, args=(test_config,))
        self.thread.daemon = True
        self.thread.start()
        
        # Emit initial status
        self.socketio.emit('test_status_update', {
            'test_id': self.test_id,
            'status': self.status,
            'progress': self.progress,
            'start_time': self.start_time.isoformat()
        })
    
    def cancel_test(self):
        """Cancel running test"""
        self.cancelled = True
        self.status = "cancelled"
        self.end_time = datetime.now()
        
        self.socketio.emit('test_status_update', {
            'test_id': self.test_id,
            'status': self.status,
            'progress': self.progress,
            'end_time': self.end_time.isoformat()
        })
    
    def _run_test(self, test_config):
        """Execute test suite"""
        try:
            suite_type = test_config.get('suite_type', 'all')
            providers = test_config.get('providers', [])
            live_mode = test_config.get('live_mode', False)
            
            # Update progress
            self._update_progress(10, "Initializing test environment...")
            
            if self.cancelled:
                return
            
            # Initialize test runners
            if suite_type in ['all', 'core']:
                self._update_progress(20, "Running core LLM tests...")
                core_runner = AITestSuiteRunner()
                core_results = core_runner.run_all_tests(verbose=False)
                self.results['core'] = core_results
                
                if self.cancelled:
                    return
            
            if suite_type in ['all', 'api']:
                self._update_progress(40, "Running API integration tests...")
                api_runner = APIIntegrationTestRunner()
                api_results = api_runner.run_all_tests(verbose=False)
                self.results['api'] = api_results
                
                if self.cancelled:
                    return
            
            if suite_type in ['all', 'security'] and SECURITY_FRAMEWORK_AVAILABLE:
                self._update_progress(60, "Running advanced security tests...")
                security_runner = SecurityTestSuiteRunner()
                security_results = security_runner.run_all_security_tests(
                    target_model="test-model",
                    verbose=False
                )
                self.results['security'] = security_results
                
                if self.cancelled:
                    return
            elif suite_type in ['all', 'security'] and not SECURITY_FRAMEWORK_AVAILABLE:
                self._update_progress(60, "Advanced security framework not available...")
                self.results['security'] = {"error": "Security framework not available"}
            
            # Combine results
            self._update_progress(80, "Generating reports...")
            
            combined_results = self._combine_results()
            self.results['combined'] = combined_results
            
            # Generate reports
            output_dir = f"test_results/{self.test_id}"
            os.makedirs(output_dir, exist_ok=True)
            
            generate_reports(combined_results, output_dir, 'all')
            
            self._update_progress(100, "Test execution completed!")
            
            self.status = "completed"
            self.end_time = datetime.now()
            
            # Store results in cache
            test_results_cache[self.test_id] = {
                'results': self.results,
                'config': test_config,
                'start_time': self.start_time,
                'end_time': self.end_time,
                'status': self.status
            }
            
            # Final status update
            self.socketio.emit('test_completed', {
                'test_id': self.test_id,
                'status': self.status,
                'results': combined_results,
                'end_time': self.end_time.isoformat(),
                'duration': (self.end_time - self.start_time).total_seconds()
            })
            
        except Exception as e:
            self.status = "failed"
            self.end_time = datetime.now()
            
            self.socketio.emit('test_failed', {
                'test_id': self.test_id,
                'status': self.status,
                'error': str(e),
                'end_time': self.end_time.isoformat()
            })
            
            logger.error(f"Test {self.test_id} failed: {str(e)}")
    
    def _update_progress(self, progress, message):
        """Update test progress"""
        if self.cancelled:
            return
            
        self.progress = progress
        self.socketio.emit('test_progress_update', {
            'test_id': self.test_id,
            'progress': progress,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        
        # Small delay to make progress visible
        time.sleep(0.5)
    
    def _combine_results(self):
        """Combine results from different test suites"""
        combined = {
            'total_tests': 0,
            'passed': 0,
            'failed': 0,
            'errors': 0,
            'suite_results': {}
        }
        
        for suite_name, results in self.results.items():
            if suite_name != 'combined' and isinstance(results, dict):
                combined['total_tests'] += results.get('total_tests', 0)
                combined['passed'] += results.get('passed', 0)
                combined['failed'] += results.get('failed', 0)
                combined['errors'] += results.get('errors', 0)
                
                if 'suite_results' in results:
                    combined['suite_results'].update(results['suite_results'])
        
        combined['overall_success_rate'] = combined['passed'] / combined['total_tests'] if combined['total_tests'] > 0 else 0
        
        return combined

# Routes
@app.route('/')
def index():
    """Main dashboard"""
    # Get test history
    test_history = []
    for test_id, test_data in test_results_cache.items():
        test_history.append({
            'test_id': test_id,
            'start_time': test_data['start_time'],
            'end_time': test_data.get('end_time'),
            'status': test_data['status'],
            'results': test_data.get('results', {})
        })
    
    # Sort by start time (most recent first)
    test_history.sort(key=lambda x: x['start_time'], reverse=True)
    
    return render_template('dashboard.html', 
                         test_history=test_history[:10],  # Last 10 tests
                         config_manager=config_manager)

@app.route('/config')
def config_page():
    """Configuration management page"""
    providers = config_manager.get_available_providers()
    validation = config_manager.validate_configuration()
    
    return render_template('config.html', 
                         providers=providers,
                         validation=validation,
                         config_manager=config_manager)

@app.route('/api/config/validate', methods=['POST'])
def validate_config():
    """Validate configuration via API"""
    validation = config_manager.validate_configuration()
    return jsonify(validation)

@app.route('/api/config/save', methods=['POST'])
def save_config():
    """Save configuration"""
    try:
        config_data = request.json
        
        # Save to file
        config_file = "web_app_config.json"
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)
        
        # Reload config manager
        global config_manager
        config_manager = ConfigManager(config_file)
        
        return jsonify({'status': 'success', 'message': 'Configuration saved successfully'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/test')
def test_page():
    """Test execution page"""
    providers = [p.value for p in AIProvider]
    available_providers = [p.value for p in config_manager.get_available_providers()]
    
    return render_template('test.html', 
                         providers=providers,
                         available_providers=available_providers)

@app.route('/comprehensive')
def comprehensive_test_page():
    """Comprehensive testing page with 1000+ tests and adaptive learning"""
    return render_template('comprehensive.html', 
                         config_manager=config_manager,
                         security_available=SECURITY_FRAMEWORK_AVAILABLE,
                         comprehensive_available=COMPREHENSIVE_FRAMEWORK_AVAILABLE,
                         learning_available=ADAPTIVE_LEARNING_AVAILABLE)

@app.route('/api/comprehensive/start', methods=['POST'])
def start_comprehensive_test():
    """Start comprehensive security test with 1000+ test cases"""
    test_id = str(uuid.uuid4())
    data = request.get_json()
    
    # Test configuration
    model_name = data.get('model_name', 'comprehensive-test-model')
    test_suites = data.get('test_suites', [
        'adversarial_attacks', 'multi_modal_security', 'edge_case_boundary',
        'large_scale_stress', 'international_multilingual', 'api_integration_security'
    ])
    enable_learning = data.get('enable_learning', True)
    
    # Initialize test tracking
    active_tests[test_id] = {
        'start_time': datetime.now(),
        'status': 'running',
        'progress': 0,
        'total_tests': 0,
        'completed_tests': 0,
        'vulnerabilities_found': 0
    }
    
    test_results_cache[test_id] = {
        'test_id': test_id,
        'start_time': datetime.now().isoformat(),
        'status': 'running',
        'config': {
            'model_name': model_name,
            'test_suites': test_suites,
            'enable_learning': enable_learning
        }
    }
    
    # Start comprehensive test in background
    def run_comprehensive_test():
        try:
            from run_comprehensive_tests import run_all_security_tests
            
            # Run the comprehensive test suite
            results = run_all_security_tests(
                model_name=model_name,
                suites=test_suites,
                verbose=False,
                enable_learning=enable_learning
            )
            
            # Update results
            active_tests[test_id]['status'] = 'completed'
            active_tests[test_id]['progress'] = 100
            
            test_results_cache[test_id].update({
                'status': 'completed',
                'end_time': datetime.now().isoformat(),
                'results': results
            })
            
            # Emit completion event
            socketio.emit('test_completed', {
                'test_id': test_id,
                'results': results
            })
            
        except Exception as e:
            logger.error(f"Comprehensive test failed: {str(e)}")
            active_tests[test_id]['status'] = 'failed'
            active_tests[test_id]['error'] = str(e)
            
            test_results_cache[test_id].update({
                'status': 'failed',
                'end_time': datetime.now().isoformat(),
                'error': str(e)
            })
            
            socketio.emit('test_failed', {
                'test_id': test_id,
                'error': str(e)
            })
    
    # Start background thread
    thread = threading.Thread(target=run_comprehensive_test)
    thread.daemon = True
    thread.start()
    
    return jsonify({'test_id': test_id, 'status': 'started'})

@app.route('/api/test/start', methods=['POST'])
def start_test():
    """Start test execution"""
    try:
        test_config = request.json
        test_id = str(uuid.uuid4())
        
        # Validate config
        if not test_config.get('suite_type'):
            return jsonify({'error': 'Test suite type is required'}), 400
        
        # Create test executor
        executor = TestExecutor(test_id, socketio)
        active_tests[test_id] = executor
        
        # Start test
        executor.start_test(test_config)
        
        return jsonify({
            'test_id': test_id,
            'status': 'started',
            'message': 'Test execution started'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test/cancel/<test_id>', methods=['POST'])
def cancel_test(test_id):
    """Cancel test execution"""
    try:
        if test_id in active_tests:
            active_tests[test_id].cancel_test()
            return jsonify({'status': 'cancelled'})
        else:
            return jsonify({'error': 'Test not found'}), 404
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test/status/<test_id>')
def get_test_status(test_id):
    """Get test status"""
    if test_id in active_tests:
        executor = active_tests[test_id]
        return jsonify({
            'test_id': test_id,
            'status': executor.status,
            'progress': executor.progress,
            'start_time': executor.start_time.isoformat() if executor.start_time else None,
            'end_time': executor.end_time.isoformat() if executor.end_time else None
        })
    elif test_id in test_results_cache:
        test_data = test_results_cache[test_id]
        return jsonify({
            'test_id': test_id,
            'status': test_data['status'],
            'start_time': test_data['start_time'].isoformat(),
            'end_time': test_data.get('end_time', '').isoformat() if test_data.get('end_time') else None
        })
    else:
        return jsonify({'error': 'Test not found'}), 404

@app.route('/api/test/results/<test_id>')
def get_test_results(test_id):
    """Get test results"""
    if test_id in test_results_cache:
        return jsonify(test_results_cache[test_id]['results'])
    else:
        return jsonify({'error': 'Test results not found'}), 404

@app.route('/results')
def results_page():
    """Test results page"""
    test_history = []
    for test_id, test_data in test_results_cache.items():
        test_history.append({
            'test_id': test_id,
            'start_time': test_data['start_time'],
            'end_time': test_data.get('end_time'),
            'status': test_data['status'],
            'config': test_data.get('config', {}),
            'results': test_data.get('results', {})
        })
    
    # Sort by start time (most recent first)
    test_history.sort(key=lambda x: x['start_time'], reverse=True)
    
    return render_template('results.html', test_history=test_history)

@app.route('/results/<test_id>')
def view_test_results(test_id):
    """View detailed test results"""
    if test_id not in test_results_cache:
        return redirect(url_for('results_page'))
    
    test_data = test_results_cache[test_id]
    return render_template('test_detail.html', 
                         test_id=test_id,
                         test_data=test_data)

@app.route('/api/results/download/<test_id>/<format>')
def download_results(test_id, format):
    """Download test results in various formats"""
    if test_id not in test_results_cache:
        return jsonify({'error': 'Test results not found'}), 404
    
    try:
        results_dir = f"test_results/{test_id}"
        
        if format == 'json':
            file_path = f"{results_dir}/test_results_{test_id}.json"
            if os.path.exists(file_path):
                return send_file(file_path, as_attachment=True)
        
        elif format == 'html':
            file_path = f"{results_dir}/test_results_{test_id}.html"
            if os.path.exists(file_path):
                return send_file(file_path, as_attachment=True)
        
        elif format == 'junit':
            file_path = f"{results_dir}/test_results_{test_id}.xml"
            if os.path.exists(file_path):
                return send_file(file_path, as_attachment=True)
        
        return jsonify({'error': 'Report file not found'}), 404
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/providers')
def get_providers():
    """Get available providers"""
    available_providers = config_manager.get_available_providers()
    all_providers = list(AIProvider)
    
    provider_info = []
    for provider in all_providers:
        is_configured = provider in available_providers
        config_info = config_manager.get_api_config(provider) if is_configured else None
        
        provider_info.append({
            'name': provider.value,
            'display_name': provider.value.replace('_', ' ').title(),
            'configured': is_configured,
            'rate_limit': config_info.rate_limit_rpm if config_info else None,
            'model': config_info.model if config_info else None
        })
    
    return jsonify(provider_info)

@app.route('/docs')
def docs_page():
    """Documentation page"""
    return render_template('docs.html')

# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    emit('connected', {'message': 'Connected to AI Testing Suite'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    pass

@socketio.on('join_test')
def handle_join_test(data):
    """Join test room for updates"""
    test_id = data.get('test_id')
    if test_id:
        join_room(test_id)
        emit('joined_test', {'test_id': test_id})

@socketio.on('leave_test')
def handle_leave_test(data):
    """Leave test room"""
    test_id = data.get('test_id')
    if test_id:
        leave_room(test_id)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error="Internal server error"), 500

# Initialize app
def initialize_app():
    """Initialize the Flask application"""
    # Setup environment
    setup_environment()
    
    # Create necessary directories
    os.makedirs('test_results', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    
    # Load existing test results
    results_dir = Path('test_results')
    if results_dir.exists():
        for test_dir in results_dir.iterdir():
            if test_dir.is_dir():
                test_id = test_dir.name
                json_file = test_dir / f"test_results_{test_id}.json"
                if json_file.exists():
                    try:
                        with open(json_file, 'r') as f:
                            results = json.load(f)
                            test_results_cache[test_id] = {
                                'results': {'combined': results},
                                'config': {},
                                'start_time': datetime.now() - timedelta(days=1),  # Placeholder
                                'status': 'completed'
                            }
                    except Exception as e:
                        logger.warning(f"Failed to load cached results for {test_id}: {e}")

if __name__ == '__main__':
    initialize_app()
    
    # Run the application
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print(f"""
    🚀 AI Chatbot Testing Suite Web Interface
    ==========================================
    
    🌐 Open your browser and go to: http://localhost:{port}
    
    Features:
    ✅ Interactive Dashboard
    ✅ Real-time Test Execution
    ✅ Configuration Management
    ✅ Visual Reports & Analytics
    ✅ Multi-platform API Testing
    
    """)
    
    socketio.run(app, host='0.0.0.0', port=port, debug=debug)