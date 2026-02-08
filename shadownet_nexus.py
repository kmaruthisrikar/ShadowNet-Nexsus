"""
ShadowNet Nexus - Main Controller
Gemini-Powered Anti-Forensics Detection Framework
"""

import os
import sys
import time
import psutil
import platform
import yaml
from datetime import datetime
from typing import Dict, Any, List
from dotenv import load_dotenv

# Import core modules
from core import (
    GeminiCommandAnalyzer,
    GeminiMultimodalAnalyzer,
    GeminiBehaviorAnalyzer,
    GeminiThreatAttributor,
    GeminiTimelineReconstructor,
    GeminiReportGenerator,
    GeminiAlertManager,
    NetworkMonitor,
    FileIntegrityMonitor
)

# Import proactive modules
from core.proactive_evidence_collector import ProactiveEvidenceCollector
from core.command_interceptor import CommandInterceptor
from core.incident_report_generator import IncidentReportGenerator

# Import utilities
from utils import EvidenceVault, CacheManager
from utils.os_detector import os_detector
from core.data_manager import data_manager
from utils.model_selector import ModelSelector, model_selector


class ShadowNetNexus:
    """
    Main controller for Gemini-powered anti-forensics detection
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """
        Initialize ShadowNet Nexus
        
        Args:
            config_path: Path to configuration file
        """
        # Load environment variables
        load_dotenv()
        
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Setup Logging
        self._setup_logging()
        
        # Get API key
        self.api_key = os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not found in environment variables. Please set it in .env file.")
        
        # Initialize cache manager
        self.cache = CacheManager(
            cache_dir="./cache",
            ttl_seconds=self.config['shadownet']['rate_limiting']['cache_ttl_seconds']
        )
        
        # Initialize evidence vault
        vault_path = self.config['shadownet']['evidence_vault']['path']
        self.evidence_vault = EvidenceVault(vault_path)
        
        # Initialize Gemini-powered components
        print("🛡️ Initializing ShadowNet Nexus components...")
        
        # Display OS detection status
        os_detector.print_status()
        
        # Initialize model selector and auto-detect best models
        self.model_selector = ModelSelector(self.api_key)
        
        # Override config models with auto-detected ones if available
        fast_model = self.model_selector.get_model_for_role('fast')
        intelligent_model = self.model_selector.get_model_for_role('intelligent')
        
        print(f"🤖 AI Models: Fast={fast_model}, Intelligent={intelligent_model}")
        
        self.command_analyzer = GeminiCommandAnalyzer(self.api_key, fast_model)
        self.multimodal_analyzer = GeminiMultimodalAnalyzer(self.api_key, intelligent_model)
        self.behavior_analyzer = GeminiBehaviorAnalyzer(self.api_key, fast_model)
        self.threat_attributor = GeminiThreatAttributor(self.api_key, intelligent_model)
        self.timeline_reconstructor = GeminiTimelineReconstructor(self.api_key, intelligent_model)
        self.report_generator = GeminiReportGenerator(self.api_key, intelligent_model)
        self.alert_manager = GeminiAlertManager(self.api_key, fast_model)
        
        # Initialize proactive evidence collector
        self.proactive_collector = ProactiveEvidenceCollector(
            evidence_vault_path=vault_path,
            enabled=True  # Auto-detects if admin/root
        )
        
        # Initialize command interceptor
        self.command_interceptor = CommandInterceptor(
            callback=self._on_suspicious_command_detected
        )
        
        # Initialize incident report generator
        self.incident_reporter = IncidentReportGenerator(evidence_path=vault_path)
        
        # Active alerts and incidents
        self.active_alerts: List[Dict[str, Any]] = []
        self.active_incidents: Dict[str, Dict[str, Any]] = {}
        
        # Suspicious keywords for pre-filtering
        self.suspicious_keywords = self.config['shadownet']['monitoring']['suspicious_keywords']
        print(f"👀 Watching for {len(self.suspicious_keywords)} suspicious keywords (e.g. {self.suspicious_keywords[:3]}...)")
        if '-Enc' in self.suspicious_keywords:
            print("✅ Obfuscation detection enabled (-Enc keyword loaded)")
        else:
            print("⚠️ WARNING: Obfuscation detection keywords missing!")

        # Initialize network and file monitors
        self.network_monitor = NetworkMonitor()
        self.file_monitor = FileIntegrityMonitor()
        
        # Deduplication tracking
        self.last_alerts = {} # {threat_key: timestamp}
        self.alert_cooldown = 30 # seconds
        
        # Initialize Response Engine (Active Defense)
        from core.response_engine import ResponseEngine
        self.response_engine = ResponseEngine(
            quarantine_dir="./quarantine",
            auto_response_enabled=True,
            require_confirmation=False
        )
        print("🛡️ Response Engine: ENABLED (Quarantine Active)")
        
        # Monitor User Documents & Desktop for Ransomware Detection
        try:
            user_home = os.path.expanduser("~")
            documents_path = os.path.join(user_home, "Documents")
            desktop_path = os.path.join(user_home, "Desktop")
            
            # Add if they exist (limit to top-level/critical depth to avoid perf impact)
            if os.path.exists(documents_path):
                print(f"📂 Monitoring Documents for ransomware: {documents_path}")
                self.file_monitor.add_watch_path(documents_path)
                
            if os.path.exists(desktop_path):
                print(f"📂 Monitoring Desktop for ransomware: {desktop_path}")
                self.file_monitor.add_watch_path(desktop_path)
        except Exception as e:
            print(f"⚠️ Could not add user directories to monitor: {e}")
        
        print("✅ ShadowNet Nexus initialized successfully!")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"⚠️ Config file not found: {config_path}")
            print("Using default configuration...")
            return self._default_config()
    def _setup_logging(self):
        """Configure system logging"""
        import logging
        from logging.handlers import RotatingFileHandler
        
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "shadownet.log")
        
        # Create handlers
        file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
        console_handler = logging.StreamHandler()
        
        # Create formatters and add to handlers
        log_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(log_format)
        console_handler.setFormatter(log_format)
        
        # Configure root logger
        logging.basicConfig(level=logging.INFO, handlers=[file_handler, console_handler])
        self.logger = logging.getLogger("ShadowNet")
        self.logger.info("logging system initialized")

    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            'shadownet': {
                'models': {
                    'fast': 'gemini-2.5-flash',
                    'intelligent': 'gemini-2.5-flash'
                },
                'evidence_vault': {
                    'path': './evidence'
                },
                'monitoring': {
                    'check_interval_seconds': 1,
                    'suspicious_keywords': ['wevtutil', 'vssadmin', 'cipher', 'mimikatz']
                },
                'alerting': {
                    'min_confidence_for_alert': 0.7,
                    'enable_console': True
                },
                'rate_limiting': {
                    'cache_results': True,
                    'cache_ttl_seconds': 3600
                }
            }
        }
    
    def _auto_generate_forensic_report(self, incident_id: str):
        """Automatically generate forensic report for critical threats"""
        try:
            # We need some dummy incident info for the generator if it's not in active_incidents
            # In a real world app, we'd fetch from DataManager
            incident_data = {
                'id': incident_id,
                'timestamp': datetime.now().isoformat(),
                'status': 'HIGH_CRITICAL'
            }
            # Add to active incidents so generator finds it
            self.active_incidents[incident_id] = incident_data
            
            report_path = self.generate_incident_report(incident_id, 'technical')
            print(f"📊 Auto-Forensic Report: {report_path}")
        except Exception as e:
            print(f"⚠️ Report generation failed: {e}")

    def monitor_system(self, duration_seconds: int = None):
        """
        Main monitoring loop with proactive evidence capture
        
        Args:
            duration_seconds: How long to monitor (None = infinite)
        """
        print("\n🛡️ ShadowNet Nexus Active - Gemini AI Monitoring Enabled")
        print(f"📊 Monitoring started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🔍 Watching for anti-forensics activity...")
        
        # Display proactive status
        if self.proactive_collector.enabled:
            print(f"⚡ PROACTIVE MODE: ENABLED - Evidence captured BEFORE deletion")
        else:
            print(f"⚠️  PROACTIVE MODE: DISABLED - Run as admin/root for full protection")
        print()
        
        # Start command interceptor
        self.command_interceptor.start_monitoring(check_interval=0.1)
        
        # Start network and file monitors
        self.network_monitor.start_monitoring()
        self.file_monitor.start_monitoring()
        
        start_time = time.time()
        check_interval = self.config['shadownet']['monitoring']['check_interval_seconds']
        
        try:
            while True:
                # Check duration limit
                if duration_seconds and (time.time() - start_time) > duration_seconds:
                    print("\n⏱️ Monitoring duration reached. Stopping...")
                    break
                
                # Monitor running processes
                self._monitor_processes()
                
                # Monitor network activity for suspicious connections
                self._monitor_network()
                
                # Monitor file integrity
                self._monitor_files()
                
                # Sleep before next check
                time.sleep(check_interval)
                
        except KeyboardInterrupt:
            print("\n\n⏹️ Monitoring stopped by user")
            self.command_interceptor.stop_monitoring()
            self._print_summary()
    
    def _monitor_network(self):
        """Monitor network activity for suspicious connections"""
        try:
            stats = self.network_monitor.get_statistics()
            if stats['suspicious_connections'] > 0:
                connections = self.network_monitor.get_active_connections()
                for conn in connections:
                    if conn.get('is_suspicious'):
                        threat_key = f"NET-{conn['remote_address']}-{conn['process_name']}"
                        now = time.time()
                        
                        # Apply cooldown deduplication
                        if threat_key not in self.last_alerts or (now - self.last_alerts[threat_key]) > self.alert_cooldown:
                            print(f"🚨 NETWORK THREAT: {conn['remote_address']} ({conn['process_name']})")
                            
                            # Capture evidence context
                            evidence_id = self.proactive_collector.capture_threat_context(
                                "network_threat",
                                conn
                            )
                            
                            # Record threat
                            incident_id = f"INC-NET-{int(now)}"
                            data_manager.add_threat({
                                'id': incident_id,
                                'type': 'network_threat',
                                'title': f"Suspicious connection to {conn['remote_address']}",
                                'severity': 'high',
                                'description': f"Process {conn['process_name']} has a suspicious connection to {conn['remote_address']}. Possible C2 traffic.",
                                'timestamp': datetime.now().isoformat(),
                                'source': 'NetworkMonitor',
                                'evidence_id': evidence_id
                            })
                            
                            # Real-world auto-report
                            self._auto_generate_forensic_report(incident_id)
                            
                            self.last_alerts[threat_key] = now
        except Exception as e:
            print(f"⚠️ Network monitoring error: {str(e)}")

    def _monitor_files(self):
        """Monitor file integrity for ransomware or unauthorized changes"""
        try:
            stats = self.file_monitor.get_statistics()
            if stats['ransomware_indicators'] > 0:
                threat_key = "FILE-RANSOMWARE-INDICATOR"
                now = time.time()
                
                # Apply cooldown deduplication
                if threat_key not in self.last_alerts or (now - self.last_alerts[threat_key]) > self.alert_cooldown:
                    print(f"🚨 FILE THREAT: {stats['changes_detected']} changes detected")
                    
                    # Capture evidence context
                    evidence_id = self.proactive_collector.capture_threat_context(
                        "file_threat",
                        stats
                    )
                    
                    incident_id = f"INC-FILE-{int(now)}"
                    threat_data = {
                        'id': incident_id,
                        'type': 'mass_encryption_detected', # Triggers ISOLATE_SYSTEM action in ResponseEngine
                        'title': "Ransomware indicators detected",
                        'severity': 'CRITICAL',
                        'description': f"Rapid file changes detected ({stats['changes_detected']} changes). Possible ransomware activity.",
                        'timestamp': datetime.now().isoformat(),
                        'source': 'FileIntegrityMonitor',
                        'evidence_id': evidence_id
                    }
                    data_manager.add_threat(threat_data)
                    
                    # 🛡️ ACTIVE DEFENSE RESPONSE (Quarantine/Isolate)
                    print(f"⚡ INITIATING ACTIVE RESPONSE to Ransomware Threat...")
                    response_result = self.response_engine.respond_to_threat(threat_data)
                    print(f"   Response Action: {response_result.get('action')}")
                    print(f"   Success: {response_result.get('success')}")
                    
                    # Real-world auto-report
                    self._auto_generate_forensic_report(incident_id)
                    
                    self.last_alerts[threat_key] = now
        except Exception as e:
            print(f"⚠️ File monitoring error: {str(e)}")

    def _monitor_processes(self):
        """Monitor running processes for suspicious activity"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                try:
                    if proc.info['cmdline']:
                        command = ' '.join(proc.info['cmdline'])
                        
                        # Quick keyword pre-filter (reduce API calls)
                        if self._contains_suspicious_keywords(command):
                            # Analyze with Gemini
                            self._analyze_suspicious_command(proc, command)
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"⚠️ Process monitoring error: {str(e)}")
    
    def _on_suspicious_command_detected(self, command: str, process_info: Dict[str, Any]):
        """
        Callback for command interceptor - triggers proactive evidence capture
        
        Args:
            command: Suspicious command detected
            process_info: Process metadata
        """
        # Trigger proactive evidence capture BEFORE command executes
        snapshot_id = self.proactive_collector.capture_before_execution(
            command=command,
            process_info=process_info
        )
        
        if snapshot_id:
            print(f"   💾 Proactive snapshot: {snapshot_id}")
            
            # Use Gemini to analyze the intercepted command immediately
            try:
                print(f"   🤖 Analyzing intercepted command with Gemini...")
                analysis = self.command_analyzer.analyze_command(command, process_info)
                
                # Create Incident Data
                incident_id = f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                incident_data = {
                    'incident_id': incident_id,
                    'threat_type': analysis.get('category', 'unknown'),
                    'command': command,
                    'process_info': process_info,
                    'snapshot_id': snapshot_id,
                    'detection_time': datetime.now().isoformat(),
                    'ai_analysis': analysis,
                    'severity': analysis.get('severity', 'HIGH'),
                    'evidence_types': ['Process Snapshot', 'Event Logs', 'Memory Dump']
                }
                
                # Generate Report
                report_path = self.incident_reporter.generate_incident_report(incident_data)
                print(f"   ✅ Incident report generated: {report_path}")
                
            except Exception as e:
                print(f"   ⚠️ Failed to generate report for intercept: {e}")
    
    def _contains_suspicious_keywords(self, command: str) -> bool:
        """Quick pre-filter before sending to Gemini"""
        command_lower = command.lower()
        return any(keyword.lower() in command_lower for keyword in self.suspicious_keywords)
    
    def _analyze_suspicious_command(self, proc, command: str):
        """Analyze suspicious command with Gemini"""
        try:
            # Build process info
            process_info = {
                'name': proc.info['name'],
                'pid': proc.info['pid'],
                'parent_name': proc.parent().name() if proc.parent() else 'Unknown',
                'parent_pid': proc.ppid(),
                'user': proc.info['username'],
                'timestamp': datetime.now().isoformat()
            }
            
            # Check cache first
            cache_key = self.cache.generate_cache_key(command, process_info['name'])
            cached_analysis = self.cache.get_cached_response(cache_key)
            
            if cached_analysis:
                analysis = cached_analysis
            else:
                # Check rate limit
                self.cache.wait_for_rate_limit()

                # Analyze with Gemini
                analysis = self.command_analyzer.analyze_command(command, process_info)

                # Cache result
                if self.config['shadownet']['rate_limiting']['cache_results']:
                    self.cache.cache_response(cache_key, analysis)
            
            # Handle detection
            if analysis.get('is_anti_forensics'):
                self._handle_anti_forensics_detection(analysis, proc, command)
                
        except Exception as e:
            print(f"⚠️ Analysis error: {str(e)}")

    
    
    def _handle_anti_forensics_detection(self, analysis: Dict[str, Any], proc, command: str):
        """Respond to anti-forensics detection"""
        # Check confidence threshold
        min_confidence = self.config['shadownet']['alerting']['min_confidence_for_alert']
        if analysis.get('confidence', 0) < min_confidence:
            return
        
        print(f"\n🚨 ANTI-FORENSICS ACTIVITY DETECTED!")
        print(f"   Time: {datetime.now().strftime('%H:%M:%S')}")
        print(f"   Severity: {analysis.get('severity', 'UNKNOWN')}")
        print(f"   Command: {command}")
        print(f"   Process: {proc.info['name']} (PID: {proc.info['pid']})")
        print(f"   User: {proc.info['username']}")
        print(f"   Confidence: {analysis.get('confidence', 0):.1%}")
        print(f"   Explanation: {analysis.get('explanation', 'N/A')}")
        print(f"   Likely Actor: {analysis.get('likely_threat_actor', 'Unknown')}")
        
        # Create incident
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Create alert
        alert = {
            'id': f"ALT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'incident_id': incident_id,
            'timestamp': datetime.now().isoformat(),
            'type': 'anti_forensics',
            'severity': analysis.get('severity', 'MEDIUM'),
            'analysis': analysis,
            'process': proc.info,
            'command': command
        }
        
        # Triage alert
        system_context = self._get_system_context()
        triage = self.alert_manager.triage_alert(alert, system_context)
        
        print(f"   Priority: {triage.get('priority', 'UNKNOWN')}")
        print(f"   False Positive: {triage.get('is_false_positive', False)}")
        
        if not triage.get('is_false_positive', False):
            # Preserve evidence
            print(f"\n💾 PRESERVING EVIDENCE...")
            evidence_id = self.evidence_vault.preserve_evidence(
                incident_id=incident_id,
                evidence_data={
                    'alert': alert,
                    'analysis': analysis,
                    'triage': triage,
                    'system_context': system_context
                 },
                evidence_type='anti_forensics_detection'
            )
            print(f"   Evidence ID: {evidence_id}")
            
            # Store incident in data_manager for real-time dashboard
            data_manager.add_threat({
                'id': incident_id,
                'type': analysis.get('category', 'anti_forensics'),
                'title': analysis.get('explanation', 'Anti-forensics activity detected')[:50] + "...",
                'severity': analysis.get('severity', 'high').lower(),
                'description': analysis.get('explanation', 'N/A'),
                'timestamp': datetime.now().isoformat(),
                'source': proc.info['username'] if 'username' in proc.info else 'unknown',
                'evidence_id': evidence_id
            })
            
            # Record evidence size (mock 2MB for snapshot)
            data_manager.record_evidence(2.0)
            
            # Store incident locally
            self.active_incidents[incident_id] = {
                'id': incident_id,
                'timestamp': datetime.now().isoformat(),
                'alert': alert,
                'analysis': analysis,
                'triage': triage,
                'evidence_id': evidence_id
            }
            
            # Generate quick summary
            summary = self.report_generator.generate_incident_summary(alert)
            print(f"\n📋 INCIDENT SUMMARY:")
            print(f"   {summary}")
        
        self.active_alerts.append(alert)
        print()  # Blank line for readability
    
    def _get_system_context(self) -> Dict[str, Any]:
        """Gather system context for alert triage"""
        return {
            'hostname': platform.node(),
            'os': platform.system(),
            'time_of_day': datetime.now().strftime('%H:%M'),
            'active_users': len(psutil.users()),
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent
        }
    
    def generate_incident_report(self, incident_id: str, report_type: str = 'technical'):
        """
        Generate comprehensive incident report
        
        Args:
            incident_id: Incident identifier
            report_type: 'executive' or 'technical'
        """
        if incident_id not in self.active_incidents:
            print(f"❌ Incident not found: {incident_id}")
            return
        
        incident = self.active_incidents[incident_id]
        
        print(f"\n📄 Generating {report_type} report for {incident_id}...")
        
        if report_type == 'executive':
            report = self.report_generator.generate_executive_summary(incident)
        else:
            evidence_inventory = self.evidence_vault.get_incident_evidence(incident_id)
            report = self.report_generator.generate_technical_report(incident, evidence_inventory)
        
        # Save report
        report_path = self.evidence_vault.save_report(incident_id, report, report_type)
        print(f"✅ Report saved: {report_path}")
        
        return report_path
    
    def _print_summary(self):
        """Print monitoring summary"""
        print("\n" + "="*60)
        print("📊 SHADOWNET NEXUS MONITORING SUMMARY")
        print("="*60)
        print(f"Total Alerts: {len(self.active_alerts)}")
        print(f"Total Incidents: {len(self.active_incidents)}")
        
        # Proactive collector stats
        proactive_stats = self.proactive_collector.get_statistics()
        print(f"\n⚡ Proactive Evidence Collector:")
        print(f"   Status: {'ENABLED' if proactive_stats['enabled'] else 'DISABLED'}")
        print(f"   Snapshots Taken: {proactive_stats['snapshots_taken']}")
        print(f"   Evidence Preserved: {proactive_stats['evidence_preserved_mb']:.2f} MB")
        
        # Command interceptor stats
        interceptor_stats = self.command_interceptor.get_statistics()
        print(f"\n🔍 Command Interceptor:")
        print(f"   Commands Monitored: {interceptor_stats['commands_monitored']}")
        print(f"   Suspicious Detected: {interceptor_stats['suspicious_detected']}")
        print(f"   Detection Rate: {interceptor_stats['detection_rate']:.2f}%")
        
        # Cache stats
        cache_stats = self.cache.get_cache_stats()
        print(f"\n💾 Cache Statistics:")
        print(f"   Total Cache Entries: {cache_stats['total_cache_entries']}")
        print(f"   Cache Hits: {cache_stats['total_cache_hits']}")
        print(f"   API Calls (last minute): {cache_stats['api_calls_last_minute']}")
        
        # Evidence vault stats
        vault_stats = self.evidence_vault.get_vault_stats()
        print(f"\n🗄️ Evidence Vault:")
        print(f"   Total Incidents: {vault_stats['total_incidents']}")
        print(f"   Total Reports: {vault_stats['total_reports']}")
        print(f"   Chain of Custody Entries: {vault_stats['chain_of_custody_entries']}")
        
        print("="*60 + "\n")


def main():
    """Main entry point"""
    print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║         🛡️  SHADOWNET NEXUS  🛡️                          ║
║                                                           ║
║     Gemini-Powered Anti-Forensics Detection Framework    ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Initialize ShadowNet Nexus
        shadownet = ShadowNetNexus()
        
        # Start monitoring
        shadownet.monitor_system()
        
    except ValueError as e:
        print(f"\n❌ Configuration Error: {str(e)}")
        print("\n💡 Quick Setup:")
        print("   1. Copy .env.example to .env")
        print("   2. Get API key from: https://makersuite.google.com/app/apikey")
        print("   3. Add your key to .env file")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n👋 ShadowNet Nexus shutting down...")
    except Exception as e:
        print(f"\n❌ Fatal Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
