"""
ShadowNet Nexus - Setup and Installation Script
Automated setup for Windows/Linux/Mac
"""

import os
import sys
import subprocess
from pathlib import Path


def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║         🛡️  SHADOWNET NEXUS SETUP  🛡️                    ║
║                                                           ║
║     Gemini-Powered Anti-Forensics Detection Framework    ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """)


def check_python_version():
    """Check Python version"""
    print("🔍 Checking Python version...")
    version = sys.version_info
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"❌ Python 3.8+ required. You have {version.major}.{version.minor}")
        return False
    
    print(f"✅ Python {version.major}.{version.minor}.{version.micro}")
    return True


def install_dependencies():
    """Install required packages"""
    print("\n📦 Installing dependencies...")
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("✅ Dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        return False


def setup_environment():
    """Setup environment file"""
    print("\n🔧 Setting up environment...")
    
    env_file = Path(".env")
    env_example = Path(".env.example")
    
    if env_file.exists():
        print("⚠️ .env file already exists")
        response = input("   Overwrite? (y/N): ")
        if response.lower() != 'y':
            print("   Keeping existing .env file")
            return True
    
    # Copy example to .env
    if env_example.exists():
        with open(env_example, 'r') as f:
            content = f.read()
        
        with open(env_file, 'w') as f:
            f.write(content)
        
        print("✅ Created .env file from template")
        print("\n⚠️ IMPORTANT: Edit .env and add your GEMINI_API_KEY")
        return True
    else:
        print("❌ .env.example not found")
        return False


def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating directories...")
    
    directories = [
        'evidence/incidents',
        'evidence/artifacts',
        'evidence/reports',
        'evidence/logs',
        'cache',
        'logs'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    print("✅ Directories created")
    return True


def verify_installation():
    """Verify installation"""
    print("\n🔍 Verifying installation...")
    
    # Check core modules
    try:
        from core import (
            GeminiCommandAnalyzer,
            GeminiMultimodalAnalyzer,
            GeminiBehaviorAnalyzer,
            GeminiThreatAttributor,
            GeminiTimelineReconstructor,
            GeminiReportGenerator,
            GeminiAlertManager
        )
        print("✅ Core modules loaded successfully")
    except ImportError as e:
        print(f"❌ Failed to import core modules: {str(e)}")
        return False
    
    # Check utilities
    try:
        from utils import EvidenceVault, CacheManager
        print("✅ Utility modules loaded successfully")
    except ImportError as e:
        print(f"❌ Failed to import utility modules: {str(e)}")
        return False
    
    return True


def print_next_steps():
    """Print next steps"""
    print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║         ✅ SETUP COMPLETE!                                ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

📝 NEXT STEPS:

1. Get your FREE Gemini API key:
   👉 https://makersuite.google.com/app/apikey

2. Edit .env file and add your API key:
   GEMINI_API_KEY=your_key_here

3. Run the quick start demo:
   python quick_start.py

4. Or run the full system:
   python shadownet_nexus.py

📚 DOCUMENTATION:
   - README.md - Full documentation
   - EXAMPLES.md - Usage examples
   - config/config.yaml - Configuration options

💡 TIPS:
   - Free tier: 1500 requests/day (perfect for testing!)
   - Cost: $0-3/month for most deployments
   - Check evidence/ directory for preserved evidence
   - Check logs/ directory for system logs

🆘 SUPPORT:
   - GitHub Issues: Report bugs
   - README.md: Troubleshooting section

Happy hunting! 🛡️
    """)


def main():
    """Main setup function"""
    print_banner()
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("\n⚠️ Setup incomplete. Please install dependencies manually:")
        print("   pip install -r requirements.txt")
        sys.exit(1)
    
    # Setup environment
    if not setup_environment():
        print("\n⚠️ Please create .env file manually")
    
    # Create directories
    create_directories()
    
    # Verify installation
    if not verify_installation():
        print("\n⚠️ Installation verification failed")
        print("   Some modules may not be working correctly")
    
    # Print next steps
    print_next_steps()


if __name__ == "__main__":
    main()
