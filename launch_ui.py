#!/usr/bin/env python3
"""
AI Chatbot Testing Suite - UI Launcher
Quick launcher script for the web interface with enhanced setup
"""

import os
import sys
import subprocess
import time
import webbrowser
import threading
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    print("🔍 Checking dependencies...")
    
    required_packages = [
        'flask',
        'flask-socketio',
        'requests',
        'numpy',
        'psutil'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("\n📦 Installing missing packages...")
        
        # Install missing packages
        try:
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', 
                '--upgrade', '--user'
            ] + missing_packages)
            print("✅ Dependencies installed successfully!")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            return False
    else:
        print("✅ All dependencies are installed!")
    
    return True

def setup_environment():
    """Setup environment variables and configuration"""
    print("⚙️  Setting up environment...")
    
    # Create necessary directories
    directories = [
        'test_results',
        'static/css',
        'static/js',
        'templates'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    # Set default environment variables if not present
    env_vars = {
        'FLASK_ENV': 'development',
        'FLASK_DEBUG': '1',
        'SECRET_KEY': 'ai-testing-suite-dev-key-change-in-production',
    }
    
    for key, value in env_vars.items():
        if key not in os.environ:
            os.environ[key] = value
    
    print("✅ Environment setup completed!")
    return True

def check_port_availability(port=5000):
    """Check if the specified port is available"""
    import socket
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(('localhost', port))
            return True
    except OSError:
        return False

def find_available_port(start_port=5000, max_attempts=10):
    """Find an available port starting from start_port"""
    for port in range(start_port, start_port + max_attempts):
        if check_port_availability(port):
            return port
    return None

def open_browser(url, delay=3):
    """Open browser after a delay"""
    time.sleep(delay)
    try:
        webbrowser.open(url)
        print(f"🌐 Browser opened: {url}")
    except Exception as e:
        print(f"⚠️  Could not open browser automatically: {e}")
        print(f"   Please open {url} manually in your browser")

def print_banner(port):
    """Print startup banner with information"""
    banner = f"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║    🤖 AI CHATBOT TESTING SUITE - WEB INTERFACE 🌐               ║
║                                                                  ║
║    🚀 Server running on: http://localhost:{port}                    ║
║    📚 Documentation: http://localhost:{port}/docs                   ║
║    ⚙️  Configuration: http://localhost:{port}/config               ║
║                                                                  ║
║    Features:                                                     ║
║    ✅ Interactive Dashboard                                      ║
║    ✅ Real-time Test Execution                                   ║
║    ✅ Multi-platform API Testing                                 ║
║    ✅ Security & Performance Testing                             ║
║    ✅ Visual Reports & Analytics                                 ║
║    ✅ Configuration Management                                   ║
║                                                                  ║
║    Supported AI Providers:                                      ║
║    • OpenAI (GPT-3.5, GPT-4, DALL-E)                           ║
║    • Claude (Claude 3 variants)                                 ║
║    • Google AI Studio (Gemini Pro/Vision)                       ║
║    • Hugging Face (Various models)                              ║
║    • Cohere (Command models)                                    ║
║    • Azure OpenAI                                               ║
║                                                                  ║
║    💡 Tip: Start with Mock Mode for testing without API costs!   ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

    """
    print(banner)

def show_quick_start_guide():
    """Show quick start instructions"""
    guide = """
🚀 QUICK START GUIDE:

1️⃣  FIRST TIME SETUP:
   • Go to Configuration → Set up your API keys (optional for mock testing)
   • Or start with Mock Mode to test the interface

2️⃣  RUN YOUR FIRST TEST:
   • Click "Run Tests" in the navigation
   • Select "Core LLM Tests" 
   • Choose "Mock Mode" (no API keys needed)
   • Click "Run Tests" and watch real-time progress!

3️⃣  EXPLORE FEATURES:
   • Dashboard: Overview of all test results
   • Results: Detailed analytics and visualizations
   • Configuration: API key management
   • Documentation: Comprehensive user guide

4️⃣  ADVANCED USAGE:
   • Try different test suites (Security, Performance, API Integration)
   • Switch to Live Mode for real API testing
   • Export results in multiple formats
   • Schedule automated test runs

❓ Need Help?
   • Visit the Documentation page for detailed guides
   • Check the Configuration page for setup validation
   • Use Mock Mode to explore features risk-free

    """
    print(guide)

def main():
    """Main launcher function"""
    print("🤖 AI Chatbot Testing Suite - UI Launcher")
    print("=" * 50)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required!")
        print(f"   Current version: {sys.version}")
        sys.exit(1)
    
    # Check and install dependencies
    if not check_dependencies():
        print("❌ Failed to setup dependencies!")
        sys.exit(1)
    
    # Setup environment
    if not setup_environment():
        print("❌ Failed to setup environment!")
        sys.exit(1)
    
    # Find available port
    port = find_available_port()
    if not port:
        print("❌ No available ports found! Please close other applications and try again.")
        sys.exit(1)
    
    if port != 5000:
        print(f"⚠️  Port 5000 is busy, using port {port} instead")
    
    # Print banner and guide
    print_banner(port)
    
    # Set port environment variable
    os.environ['PORT'] = str(port)
    
    # Start browser opening thread
    url = f"http://localhost:{port}"
    browser_thread = threading.Thread(target=open_browser, args=(url,))
    browser_thread.daemon = True
    browser_thread.start()
    
    # Show quick start guide
    show_quick_start_guide()
    
    print(f"🔄 Starting server on port {port}...")
    print("   Press Ctrl+C to stop the server")
    print("=" * 70)
    
    try:
        # Import and run the web application
        from web_app import app, socketio, initialize_app
        
        # Initialize the application
        initialize_app()
        
        # Run the server
        socketio.run(
            app, 
            host='0.0.0.0', 
            port=port, 
            debug=False,  # Disable debug in launcher mode
            allow_unsafe_werkzeug=True
        )
        
    except KeyboardInterrupt:
        print("\n\n🛑 Server stopped by user")
        print("   Thank you for using AI Chatbot Testing Suite!")
        
    except ImportError as e:
        print(f"\n❌ Failed to import web application: {e}")
        print("   Make sure all files are in the correct location:")
        print("   • web_app.py")
        print("   • templates/ directory")
        print("   • static/ directory") 
        sys.exit(1)
        
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        print("   Please check the error message above and try again.")
        sys.exit(1)

if __name__ == "__main__":
    main()