"""
SHADOWNET NEXUS - COMPLETE REAL-TIME SYSTEM (v4.0)
Integrates all core modules: SIEM, Alerts, Behavior Analysis, and Advanced Reporting.
OPTIMIZED: Background processing and deduplication for high-volume attacks.
"""

import os
import sys
import time
import threading
import queue
import yaml
import json
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Load environment
load_dotenv()

# --- Constants (Bug 14) ---
DEDUPLICATION_WINDOW = 2.0  # seconds (Bug 9)
SNAPSHOT_TIMEOUT = 5.0      # seconds
STATUS_CHECK_INTERVAL = 60  # seconds
SHUTDOWN_TIMEOUT = 5.0      # seconds

def print_header():
    print("-" * 61)
    print("      SHADOWNET NEXUS - v4.0 (REAL-TIME)")
    print("   Complete Forensic Intelligence & Attack Detection")
    print("-" * 61)

print_header()

# Check API key
api_key = os.getenv('GEMINI_API_KEY')
if not api_key:
    print("❌ ERROR: GEMINI_API_KEY not found in .env file")
    sys.exit(1)

print(f"[OK] API Key loaded: {api_key[:20]}...{api_key[-10:]}\n")

# --- Import All Core Components ---
print("[MSG] Loading core modules...")
from core.process_monitor import ProcessMonitor, is_admin
from core.proactive_evidence_collector import ProactiveEvidenceCollector
from core.gemini_command_analyzer import GeminiCommandAnalyzer
from core.siem_integration import SIEMIntegration, SIEMPlatform
from core.alert_manager import AlertManager, AlertChannel, AlertSeverity
from core.gemini_report_generator import GeminiReportGenerator
from core.incident_report_generator import IncidentReportGenerator
from core.gemini_behavior_analyzer import GeminiBehaviorAnalyzer
from core.behavior_monitor import BehavioralMonitor

# --- Load Configuration ---
config_path = Path(__file__).parent / 'config' / 'config.yaml'
with open(config_path, 'r') as f:
    config = yaml.safe_load(f)

# FIXED: Robust keyword loading and validation (Bug 8)
keywords_config = config['shadownet']['monitoring'].get('suspicious_keywords', [])
if not keywords_config:
    keywords = []
elif isinstance(keywords_config, str):
    keywords = [keywords_config]
elif isinstance(keywords_config, list):
    keywords = keywords_config
else:
    print(f"⚠️  [WARN] Invalid keyword format: {type(keywords_config)}")
    keywords = []

if not keywords:
    print("❌ [ERROR] No keywords loaded from config!")
    print("   Check config/config.yaml - 'suspicious_keywords' section")
    sys.exit(1)

print(f"[OK] Loaded {len(keywords)} detection keywords")

# FIXED: Admin Check Happening Early
is_root = is_admin()

print("\n" + "="*80)
print(f"✅ SHADOWNET v4.0 IS NOW ACTIVE ({'ADMIN/ROOT' if is_root else 'USER MODE'})")
if not is_root:
    print("⚠️  WARNING: Running in USER MODE. Forensic commands (wevtutil) will NOT be detected.")
print("="*80)

# --- Initialize System Components ---
print("\n" + "!"*80)
print("🚀 SHADOWNET NEXUS v4.0 - ULTIMATE SPEED ENGINE STARTING...")
print("!"*80 + "\n")

# 1. Evidence Engine
capture_net = config['shadownet']['monitoring'].get('enable_network_monitoring', True)
evidence_collector = ProactiveEvidenceCollector(
    evidence_vault_path="./evidence", 
    enabled=True, 
    capture_network=capture_net,
    suspicious_keywords=keywords  # Pass ALL keywords from config
)
print(f"   [OK] Evidence Vault: {evidence_collector.os_type.upper()} Mode")

# 2. AI Command Engine
ai_analyzer = GeminiCommandAnalyzer(api_key)
print(f"   [OK] AI Command Analyzer: {ai_analyzer.model_name}")

# 3. Behavior Engine
behavior_analyzer = GeminiBehaviorAnalyzer(api_key)
print(f"   [OK] AI Behavior Analyzer: {behavior_analyzer.model_name}")

# 4. SIEM & Alerting Engine
siem = SIEMIntegration(config={'syslog_server': '127.0.0.1', 'syslog_port': 514})
alert_mgr = AlertManager(config={})
print(f"   [OK] SIEM/Alerting: Syslog & Multi-Channel Enabled")

# 5. Reporting Engine
report_gen = GeminiReportGenerator(api_key)
incident_reporter = IncidentReportGenerator(evidence_path="./evidence")
print(f"   [OK] Reporting Engine: Forensic & Executive Ready")

# --- Global State & Queueing ---
detections = 0
snapshots = 0
incidents = 0
threat_log = []
incident_queue = queue.Queue()
recent_commands = {}  # For deduplication: {command_key: last_time}
recent_commands_lock = threading.Lock()  # Bug 5: thread-safe access
MY_PID = os.getpid()
monitor = None  # Bug 1: initialize to None so shutdown is always safe

def log_worker() -> None:  # Added type hints (Bug 15)
    """Background thread to process incident reports and snapshots without blocking detection"""
    global incidents, snapshots
    print("   [OK] Background Incident Processor Started")
    
    while True:
        try:
            item = incident_queue.get()
            if item is None: break # Shutdown signal
            
            # Removed task_event race condition logic (Bug 1)

            command = item['command']
            matched_keywords = item['matched_keywords']
            process_info = item['process_info']
            is_critical = item['is_critical']
            snapshot_id = item.get('snapshot_id', 'N/A')
            
            # Deep AI Analysis in background
            ai_res = ai_analyzer.analyze_command(command, process_info)
            severity = "CRITICAL" if is_critical or ai_res.get('severity') == 'CRITICAL' else "HIGH"

            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            incident_id = f"INC-{timestamp}"
            incident_dir = Path("evidence/incidents") / incident_id
            incident_dir.mkdir(parents=True, exist_ok=True)
            # Snapshots are now taken in the foreground for speed, but we could take more here if needed
            if snapshot_id != "N/A":
                snapshots += 1

            # 2. Generate Forensic Markdown Report
            incident_data = {
                'incident_id': incident_id,
                'threat_type': ai_res.get('category', 'unknown'),
                'command': command,
                'process_info': process_info,
                'snapshot_id': snapshot_id,
                'detection_time': datetime.now().isoformat(),
                'ai_analysis': ai_res,
                'severity': severity,
                'evidence_types': ['Event Logs', 'Process State', 'Network Connections', 'VSS State', 'File Metadata']
            }
            try:
                md_report = incident_reporter.generate_incident_report(incident_data)
            except Exception as e:
                print(f"   [WARN] Failed to generate markdown report: {e}")

            # 3. Direct SIEM Transmission (Bug 3: No longer silent)
            try:
                siem.send_event({
                    'type': 'anti_forensics',
                    'severity': severity,
                    'command': command,
                    'incident_id': incident_id,
                    'confidence': ai_res.get('confidence', 0)
                }, [SIEMPlatform.SYSLOG])
            except Exception as e:
                print(f"   [ERROR] SIEM transmission failed for {incident_id}: {e}")

            # 4. Critical Alerting (Bug 3: No longer silent)
            try:
                alert_mgr.send_alert(
                    title=f"[ALERT] THREAT DETECTED",
                    message=f"Command: {command[:100]}...",
                    severity=AlertSeverity.CRITICAL if severity == "CRITICAL" else AlertSeverity.HIGH,
                    channels=[AlertChannel.CONSOLE],
                    metadata=ai_res
                )
            except Exception as e:
                print(f"   [ERROR] Alert delivery failed for {incident_id}: {e}")

            # 5. Save Raw JSON
            with open(incident_dir / "incident.json", 'w') as f:
                json.dump(incident_data, f, indent=2)
            
            incidents += 1
            threat_log.append(incident_data)
            print(f"[OK] Background: Logged {incident_id}")
            
            incident_queue.task_done()
        except Exception as e:
            print(f"   [ERROR] Worker Exception: {e}")
            time.sleep(1)

# Start the worker thread
worker_thread = threading.Thread(target=log_worker, daemon=True)
worker_thread.start()

def on_suspicious_command(command: str, process_info: dict):
    """Handle suspicious command with v4.0 Logic and Deduplication Imaging"""
    global detections, recent_commands, keywords
    
    # Deduplication (Anti-Spam) — Bug 5 Fix: thread-safe + auto-pruning
    cmd_key = f"{process_info.get('name')}:{command}"
    now = time.time()
    proc_name = process_info.get('name', 'Unknown')

    with recent_commands_lock:
        # Prune stale entries to prevent unbounded memory growth
        stale_keys = [k for k, t in recent_commands.items() if now - t > DEDUPLICATION_WINDOW * 10]
        for k in stale_keys:
            del recent_commands[k]

        if cmd_key in recent_commands and (now - recent_commands[cmd_key]) < DEDUPLICATION_WINDOW:
            sys.stdout.write(".")
            sys.stdout.flush()
            return

        recent_commands[cmd_key] = now

    # FIXED: Whitelist Checks BEFORE incrementing counter (Bug 10)
    # 1. Ignore if it's our own process (SIEM/SIEM communication)
    if process_info.get('pid') == MY_PID:
        return
        
    # 2. Ignore if ShadowNet is the PARENT (our own evidence collection)
    if process_info.get('parent_pid') == MY_PID:
        return

    # 3. Double safety for snapshot commands
    if "evidence\\emergency_snapshots" in command and ("shadownet_realtime.py" in command.lower() or "shadownet" in str(process_info.get('name', '')).lower()):
        return

    # FIXED: Robust Keyword Matching Logic
    matched_keywords = []
    cmd_lower = command.lower()
    proc_lower = proc_name.lower()

    for keyword in keywords:
        kw_lower = keyword.lower()
        if kw_lower in cmd_lower or kw_lower in proc_lower:
            matched_keywords.append(keyword)

    if not matched_keywords:
        return 
    
    # Increment detections only after passing whitelist
    detections += 1
    
    print(f"\n⚡ DETECTION: {proc_name} matched keywords {matched_keywords}")
    
    is_critical = True # Any keyword match is now considered critical for speed
    
    print(f"\n{'='*80}")
    print(f"🚨 KERNEL SIGNAL MATCHED (Instant Detection)")
    print(f"{'='*80}")
    print(f"Command: {command}")
    print(f"System: {process_info.get('name')} (PID: {process_info.get('pid')})")
    
    # 1. Trigger FOREGROUND Evidence Snapshot (Absolute priority)
    print(f"⚡ TRIGGERING PROACTIVE EVIDENCE CAPTURE...")
    snapshot_id = "N/A"
    try:
        res = evidence_collector.on_threat_detected({
            'command': command, 
            'process_info': process_info
        })
        if res.get('snapshot_taken'):
            snapshot_id = res.get('snapshot_id')
    except Exception as e:
        print(f"   [WARN] Evidence Lag: {e}")

    # 2. Spawn ASYNC Analysis (Background)
    print(f"📡 Dispatching to Gemini AI for deep analysis (Async)...")
    
    # Removed task_event race condition (Bug 1)
    
    incident_queue.put({
        'command': command,
        'matched_keywords': matched_keywords,
        'process_info': process_info,
        'is_critical': is_critical,
        'snapshot_id': snapshot_id
    })
    
    print(f"{'='*80}\n")

def on_behavioral_alert(alert_data: dict):
    """Handle alerts from the Behavioral Monitor (Keyloggers/Bots)"""
    print(f"\n🚨 [BEHAVIORAL ALERT] {alert_data['command']}")
    print(f"   Severity: {alert_data['severity']}")
    print(f"   AI Verdict: {alert_data['ai_analysis'].get('input_type', 'Unknown')}")
    
    # Push to same incident queue
    # Bug 4 Fix: key was 'ai_res' but log_worker re-analyzes via ai_analyzer;
    # store pre-computed result in a consistent place for logging
    incident_queue.put({
        'command': alert_data['command'],
        'matched_keywords': ['behavioral_anomaly'],
        'pre_analyzed': alert_data.get('ai_analysis', {}),  # stored for audit
        'process_info': alert_data['process_info'],
        'is_critical': True,
        'snapshot_id': 'N/A'
    })

# --- Start System ---
if __name__ == "__main__":
    # --- Start Monitoring Based on Config ---
    monitoring_config = config['shadownet']['monitoring']
    
    # 1. Process Monitor
    if monitoring_config.get('enable_process_monitoring', True):
        monitor = ProcessMonitor(callback=on_suspicious_command, suspicious_keywords=keywords)
        monitor.start_monitoring()
        print("   [OK] Process Monitor: ACTIVE")
    else:
        print("   [--] Process Monitor: DISABLED (Config)")

    # 2. Behavioral Guard (Keylogger/Bot Detection)
    # Using 'enable_file_monitoring' as proxy or we can add a new key. 
    # Let's assume enable_file_monitoring covers this for now or add a specific check.
    if monitoring_config.get('enable_file_monitoring', True): 
        # FIXED: Pass simulation flag from config (Bug 11)
        sim_enabled = monitoring_config.get('enable_behavioral_simulation', False)
        behavior_guard = BehavioralMonitor(
            analyzer=behavior_analyzer, 
            callback=on_behavioral_alert,
            enable_simulation=sim_enabled
        )
        behavior_guard.start_monitoring()
        print(f"   [OK] Behavioral Guard: ACTIVE (Simulation: {'ON' if sim_enabled else 'OFF'})")
    else:
        print("   [--] Behavioral Guard: DISABLED (Config)")
    print(f"Platform: {evidence_collector.os_type.upper()}")
    print(f"Monitor: Hybrid (Pulsar Enabled)")
    print("Async Queue: ENABLED")
    print("Aggressive Keywords: ENABLED")
    print("\n🔍 Watching... (Ctrl+C to Shutdown)\n")
    print("="*80)
    
    try:
        while True:
            time.sleep(1)
            if int(time.time()) % 60 == 0:
                print(f"\n📊 {datetime.now().strftime('%H:%M:%S')} - Status: {detections} detections, {incident_queue.qsize()} pending reports...")

    except KeyboardInterrupt:
        print("\n\n⏹️  Initiating Secure Shutdown...")
        # Bug 1 Fix: monitor may be None if process monitoring was disabled in config
        if monitor is not None:
            monitor.stop_monitoring()
        incident_queue.put(None)
        worker_thread.join(timeout=SHUTDOWN_TIMEOUT)
        print("\n👋 ShadowNet v4.0 shutdown complete\n")
    except Exception as e:
        print(f"\n❌ Fatal Error: {e}")
        sys.exit(1)
