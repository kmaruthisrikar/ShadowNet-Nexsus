"""
ShadowNet Nexus - Startup Script
Starts both the core engine and API server
"""

import subprocess
import sys
import time
import os
from pathlib import Path

print("\n" + "="*80)
print("🛡️  SHADOWNET NEXUS - STARTUP")
print("="*80)

# Check if .env exists
if not Path(".env").exists():
    print("❌ ERROR: .env file not found!")
    print("   Please create .env file with your GEMINI_API_KEY")
    sys.exit(1)

# Check if API key is set
from dotenv import load_dotenv
load_dotenv()

api_key = os.getenv('GEMINI_API_KEY')
if not api_key:
    print("❌ ERROR: GEMINI_API_KEY not set in .env file")
    sys.exit(1)

print(f"✅ API Key loaded: {api_key[:20]}...{api_key[-10:]}")

print("\n" + "="*80)
print("🚀 STARTING SHADOWNET COMPONENTS")
print("="*80)

# Start ShadowNet Core Engine
print("\n[1/2] Starting ShadowNet Core Engine...")
print("      This monitors for threats in real-time")

try:
    core_process = subprocess.Popen(
        [sys.executable, "shadownet_nexus.py"]
    )
    print(f"✅ Core Engine started (PID: {core_process.pid})")
except Exception as e:
    print(f"❌ Failed to start Core Engine: {e}")
    sys.exit(1)

time.sleep(2)

# Start API Server
print("\n[2/2] Starting API Server...")
print("      This provides REST API and web interface")

try:
    api_process = subprocess.Popen(
        [sys.executable, "api_server.py"]
    )
    print(f"✅ API Server started (PID: {api_process.pid})")
except Exception as e:
    print(f"❌ Failed to start API Server: {e}")
    core_process.terminate()
    sys.exit(1)

time.sleep(3)

# Check if both are running
if core_process.poll() is not None:
    print("❌ Core Engine stopped unexpectedly")
    api_process.terminate()
    sys.exit(1)

if api_process.poll() is not None:
    print("❌ API Server stopped unexpectedly")
    core_process.terminate()
    sys.exit(1)

print("\n" + "="*80)
print("✅ SHADOWNET NEXUS IS NOW RUNNING")
print("="*80)

print("""
📊 SYSTEM STATUS:
   ├─ Core Engine: RUNNING (PID: {core_pid})
   ├─ API Server:  RUNNING (PID: {api_pid})
   └─ Status:      OPERATIONAL

🌐 ACCESS POINTS:
   ├─ API Endpoint:  http://localhost:5000
   ├─ Health Check:  http://localhost:5000/health
   ├─ API Docs:      http://localhost:5000/api/docs
   └─ Dashboard:     http://localhost:3000 (if running)

💡 WHAT'S HAPPENING:
   - ShadowNet is monitoring for threats in real-time
   - All suspicious commands will be analyzed by AI
   - Evidence will be preserved automatically
   - Alerts will be sent for critical threats
   - SIEM events will be transmitted

⚠️  TO STOP SHADOWNET:
   - Press Ctrl+C in this window
   - Or run: taskkill /F /PID {core_pid} /PID {api_pid}

📁 EVIDENCE LOCATION:
   - ./evidence/emergency_snapshots/
   - ./evidence/incidents/

🔍 MONITORING:
   - Check logs in real-time
   - View API at http://localhost:5000
   - Evidence auto-saved on threat detection
""".format(core_pid=core_process.pid, api_pid=api_process.pid))

print("="*80)
print("🛡️  SHADOWNET NEXUS - PROTECTING YOUR SYSTEM")
print("="*80)
print("\nPress Ctrl+C to stop all services...\n")

# Keep running and monitor processes
try:
    while True:
        # Check if processes are still running
        if core_process.poll() is not None:
            print("\n⚠️  Core Engine stopped!")
            api_process.terminate()
            break
        
        if api_process.poll() is not None:
            print("\n⚠️  API Server stopped!")
            core_process.terminate()
            break
        
        time.sleep(1)

except KeyboardInterrupt:
    print("\n\n" + "="*80)
    print("🛑 SHUTTING DOWN SHADOWNET NEXUS")
    print("="*80)
    
    print("\nStopping Core Engine...")
    core_process.terminate()
    core_process.wait(timeout=5)
    print("✅ Core Engine stopped")
    
    print("Stopping API Server...")
    api_process.terminate()
    api_process.wait(timeout=5)
    print("✅ API Server stopped")
    
    print("\n" + "="*80)
    print("✅ SHADOWNET NEXUS STOPPED SUCCESSFULLY")
    print("="*80 + "\n")

except Exception as e:
    print(f"\n❌ Error: {e}")
    core_process.terminate()
    api_process.terminate()
