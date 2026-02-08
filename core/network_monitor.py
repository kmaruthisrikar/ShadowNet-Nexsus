"""
Network Traffic Monitoring Module
Detects data exfiltration, C2 communication, and suspicious connections
"""

import os
import psutil
import subprocess
import socket
import threading
import time
from typing import Dict, List, Any, Callable, Optional
from datetime import datetime
from collections import defaultdict
import json


class NetworkMonitor:
    """
    Real-time network traffic monitoring for threat detection
    """
    
    # Known malicious ports
    SUSPICIOUS_PORTS = {
        4444, 5555, 6666, 7777, 8888, 9999,  # Common backdoor ports
        31337, 12345, 54321,  # Classic trojan ports
        6667, 6668, 6669,  # IRC (often used for C2)
    }
    
    # Common safe ports to reduce noise
    SAFE_PORTS = {80, 443, 53, 123, 8080, 8443, 22}
    
    # Whitelisted processes (development tools, system processes)
    WHITELISTED_PROCESSES = {
        # IDEs and Editors
        'code.exe', 'code-insiders.exe', 'vscode.exe',
        'pycharm64.exe', 'pycharm.exe',
        'idea64.exe', 'idea.exe',
        'devenv.exe', 'msbuild.exe',
        'antigravity.exe',  # Your IDE
        
        # Language Servers and Development Tools
        'language_server_windows_x64.exe',
        'python.exe', 'pythonw.exe',
        'node.exe', 'npm.exe',
        'git.exe', 'gh.exe',
        
        # Browsers (for development)
        'chrome.exe', 'firefox.exe', 'msedge.exe',
        
        # Windows Update and Security
        'windows defender', 'mssense.exe',
        'securityhealthservice.exe',
    }
    
    # Localhost IPs (always safe for development)
    LOCALHOST_IPS = {'127.0.0.1', '::1', 'localhost'}
    
    # Known C2 indicators
    C2_INDICATORS = {
        'high_frequency_beaconing': 10,  # Connections per minute
        'unusual_data_volume': 100 * 1024 * 1024,  # 100 MB
        'encrypted_to_unknown': True,
    }
    
    def __init__(self, callback: Optional[Callable] = None, check_interval: float = 1.0):
        """
        Initialize network monitor
        
        Args:
            callback: Function to call when suspicious activity detected
            check_interval: How often to check connections (seconds)
        """
        self.callback = callback
        self.check_interval = check_interval
        self.monitoring = False
        self.monitor_thread = None

        # Enable/disable AI verification for network processes via env var
        # Set ENABLE_NETWORK_AI=false in .env or environment to disable
        self.enable_ai_verification = os.getenv('ENABLE_NETWORK_AI', 'true').lower() == 'true'
        
        
        # Statistics
        self.total_connections = 0
        self.suspicious_connections = 0
        self.blocked_connections = 0
        
        # Connection tracking
        self.connection_history: Dict[str, List[float]] = defaultdict(list)
        self.data_transferred: Dict[str, int] = defaultdict(int)
        
        # Baseline learning
        self.baseline_established = False
        self.normal_connections: set = set()
    
    def start_monitoring(self):
        """Start network monitoring in background thread"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        print("🌐 Network monitoring started")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        print("🌐 Network monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                self._check_connections()
                time.sleep(self.check_interval)
            except Exception as e:
                print(f"Network monitoring error: {e}")
    
    def _check_connections(self):
        """Check all active network connections"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    self.total_connections += 1
                    
                    # Analyze connection
                    threat_info = self._analyze_connection(conn)
                    
                    if threat_info:
                        self.suspicious_connections += 1
                        
                        if self.callback:
                            self.callback(threat_info)
        
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
    
    def _verify_legitimate_process(self, process_name: str, process_path: str, pid: int) -> bool:
        """
        Intelligently verify if a process is legitimately whitelisted using AI
        
        Uses Gemini AI to analyze:
        1. Process name vs execution path
        2. Parent process relationships
        3. Known malware masquerading techniques
        
        Args:
            process_name: Name of the process
            process_path: Full path to the executable
            pid: Process ID
        
        Returns:
            True if legitimately whitelisted, False otherwise
        """
        # If AI verification disabled by env, skip AI and use fallback heuristics
        if not self.enable_ai_verification:
            return self._fallback_verification(process_name, process_path, 'Unknown')

        # Check if name is in whitelist first
        if process_name.lower() not in {p.lower() for p in self.WHITELISTED_PROCESSES}:
            return False  # Not even in whitelist
        
        # **CACHE CHECK** - Avoid re-verifying the same process
        cache_key = f"{process_name}:{process_path}"
        if not hasattr(self, '_verification_cache'):
            self._verification_cache = {}
        
        if cache_key in self._verification_cache:
            # Return cached result (valid for this session)
            return self._verification_cache[cache_key]
        
        # Get parent process info
        parent_name = "Unknown"
        parent_path = "Unknown"
        try:
            process = psutil.Process(pid)
            parent = process.parent()
            if parent:
                parent_name = parent.name()
                try:
                    parent_path = parent.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    parent_path = "Unknown"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        

        # Use AI to verify the process path
        try:
            from .ai_process_verifier import AIProcessVerifier
            
            # Initialize AI verifier (cached)
            if not hasattr(self, '_ai_verifier'):
                self._ai_verifier = AIProcessVerifier()
            
            # Get AI verification
            result = self._ai_verifier.verify_process_path(
                process_name,
                process_path,
                parent_name,
                parent_path
            )
            
            # Log if suspicious
            if not result['is_legitimate']:
                print(f"🤖 AI DETECTED MASQUERADING:")
                print(f"   Process: {process_name}")
                print(f"   Path: {process_path}")
                print(f"   Parent: {parent_name}")
                print(f"   Threat Level: {result['threat_level']}")
                print(f"   Reason: {result['reason']}")
                if result.get('indicators'):
                    print(f"   Indicators: {', '.join(result['indicators'])}")
            
            # Return AI's decision
            # Only whitelist if AI says it's legitimate with high confidence
            is_legit = result['is_legitimate'] and result['confidence'] >= 0.7
            
            # **CACHE THE RESULT**
            self._verification_cache[cache_key] = is_legit
            
            return is_legit
            
        except Exception as e:
            # If AI fails, fall back to basic checks
            print(f"⚠️  AI verification failed, using fallback: {e}")
            result = self._fallback_verification(process_name, process_path, parent_name)
            
            # Cache fallback result too
            self._verification_cache[cache_key] = result
            
            return result


    # Signature/hash-based helpers removed — reverting to original codebase behavior
    
    def _fallback_verification(self, process_name: str, process_path: str, parent_name: str) -> bool:
        """
        Fallback verification if AI is unavailable
        Uses basic heuristics
        """
        process_path_lower = process_path.lower()
        process_name_lower = process_name.lower()
        
        # Critical system processes MUST be in System32
        critical_processes = ['svchost.exe', 'lsass.exe', 'services.exe', 'csrss.exe', 'smss.exe']
        
        if process_name_lower in critical_processes:
            if 'system32' in process_path_lower or 'syswow64' in process_path_lower:
                # Verify parent for extra security
                if process_name_lower == 'svchost.exe' and parent_name.lower() != 'services.exe':
                    print(f"⚠️  SUSPICIOUS: svchost.exe with wrong parent: {parent_name}")
                    return False
                return True  # Legitimate system process
            else:
                print(f"⚠️  MASQUERADING: {process_name} not in System32: {process_path}")
                return False  # Masquerading malware
        
        # Suspicious locations - never whitelist
        suspicious_locations = ['downloads', 'desktop', '\\temp\\', '\\tmp\\']
        if any(loc in process_path_lower for loc in suspicious_locations):
            print(f"⚠️  SUSPICIOUS LOCATION: {process_name} in {process_path}")
            return False
        
        # Development tools - allow if in reasonable locations
        dev_tools = ['python.exe', 'pythonw.exe', 'node.exe', 'code.exe', 'antigravity.exe', 'language_server_windows_x64.exe']
        if process_name_lower in dev_tools:
            reasonable_paths = ['program files', 'appdata', 'python', 'anaconda', 'users']
            if any(path in process_path_lower for path in reasonable_paths):
                return True
        
        # Default: allow with caution
        return True
    
    def _analyze_connection(self, conn) -> Optional[Dict[str, Any]]:
        """
        Analyze a network connection for threats
        
        Args:
            conn: psutil connection object
        
        Returns:
            Threat info dict if suspicious, None otherwise
        """
        remote_ip = conn.raddr.ip
        remote_port = conn.raddr.port
        local_port = conn.laddr.port
        
        # Get process info first
        try:
            process = psutil.Process(conn.pid) if conn.pid else None
            process_name = process.name() if process else "Unknown"
            process_path = process.exe() if process else "Unknown"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process_name = "Unknown"
            process_path = "Unknown"

        # Initialize threat indicators and severity early (used in checks below)
        threat_indicators = []
        severity = "LOW"

        # ============================================================
        # INTELLIGENT WHITELIST CHECKS
        # Verify process authenticity, not just name!
        # Attackers can name malware "svchost.exe" or "chrome.exe"
        # ============================================================

        # 1. Verify if process is LEGITIMATELY whitelisted
        is_whitelisted = self._verify_legitimate_process(process_name, process_path, conn.pid)
        
        if is_whitelisted:
            return None  # Verified legitimate process, ignore
        
        # 2. Check if connection is to localhost (development)
        if remote_ip in self.LOCALHOST_IPS:
            # Localhost connections are safe for development tools
            # But still check for suspicious processes (mimikatz, nc.exe, etc.)
            suspicious_names = ['nc.exe', 'netcat', 'ncat', 'socat', 'powercat', 'mimikatz', 'psexec']
            if not any(name in process_name.lower() for name in suspicious_names):
                return None  # Safe localhost connection
        
        # 3. Check if it's a browser on safe ports (web browsing)
        # But verify it's a REAL browser, not malware named "chrome.exe"
        if 'chrome' in process_name.lower() or 'firefox' in process_name.lower() or 'edge' in process_name.lower():
            if remote_port in {80, 443, 8080, 8443}:
                # Verify browser is in legitimate location
                legitimate_browser_paths = [
                    'program files', 'program files (x86)',
                    'google\\chrome', 'mozilla firefox', 'microsoft\\edge'
                ]
                if any(path in process_path.lower() for path in legitimate_browser_paths):
                    return None  # Legitimate browser
                else:
                    # Browser name but suspicious location - flag it!
                    threat_indicators.append(
                        f"Suspicious: Process named '{process_name}' but located in '{process_path}' (not standard browser location)"
                    )
                    severity = "HIGH"
        
        # ============================================================
        # THREAT ANALYSIS - Only for non-whitelisted connections
        # ============================================================
        
        threat_indicators = []
        severity = "LOW"
        
        # Check for suspicious ports
        if remote_port in self.SUSPICIOUS_PORTS:
            threat_indicators.append(f"Connection to suspicious port {remote_port}")
            severity = "HIGH"
        
        # Check for high-frequency beaconing (C2 communication)
        connection_key = f"{remote_ip}:{remote_port}"
        now = time.time()
        
        # Track connection frequency
        self.connection_history[connection_key].append(now)
        
        # Clean old entries (keep last 60 seconds)
        self.connection_history[connection_key] = [
            t for t in self.connection_history[connection_key]
            if now - t < 60
        ]
        
        # Check frequency
        connections_per_minute = len(self.connection_history[connection_key])
        if connections_per_minute > self.C2_INDICATORS['high_frequency_beaconing']:
            threat_indicators.append(
                f"High-frequency beaconing: {connections_per_minute} connections/min"
            )
            severity = "CRITICAL"
        
        # Check for unusual ports (only for external IPs)
        if remote_ip not in self.LOCALHOST_IPS:
            if remote_port > 49152:  # Dynamic/private port range
                if not self.baseline_established:
                    # Learning phase
                    self.normal_connections.add(connection_key)
                elif connection_key not in self.normal_connections:
                    threat_indicators.append(f"Connection to unusual port {remote_port}")
                    severity = max(severity, "MEDIUM")
            elif remote_port not in self.SAFE_PORTS and remote_port not in self.SUSPICIOUS_PORTS:
                 if not self.baseline_established:
                    # Learning phase
                    self.normal_connections.add(connection_key)
                 elif connection_key not in self.normal_connections:
                    threat_indicators.append(f"Unmapped port connection: {remote_port}")
                    severity = max(severity, "MEDIUM")
        
        # Check for suspicious process names (high priority)
        suspicious_names = ['nc.exe', 'netcat', 'ncat', 'socat', 'powercat', 'mimikatz', 'psexec']
        if any(name in process_name.lower() for name in suspicious_names):
            threat_indicators.append(f"Suspicious process: {process_name}")
            severity = "CRITICAL"
        
        # If threats found, return info
        if threat_indicators:
            return {
                'type': 'suspicious_network_connection',
                'timestamp': datetime.now().isoformat(),
                'severity': severity,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'local_port': local_port,
                'process_name': process_name,
                'process_path': process_path,
                'process_pid': conn.pid,
                'threat_indicators': threat_indicators,
                'connection_frequency': connections_per_minute,
                'recommended_action': 'block_connection' if severity == 'CRITICAL' else 'monitor'
            }
        
        return None
    
    def establish_baseline(self, duration_seconds: int = 300):
        """
        Establish baseline of normal network activity
        
        Args:
            duration_seconds: How long to learn (default 5 minutes)
        """
        print(f"🌐 Establishing network baseline ({duration_seconds}s)...")
        
        start_time = time.time()
        while time.time() - start_time < duration_seconds:
            try:
                connections = psutil.net_connections(kind='inet')
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        connection_key = f"{conn.raddr.ip}:{conn.raddr.port}"
                        self.normal_connections.add(connection_key)
                
                time.sleep(1)
            except Exception:
                pass
        
        self.baseline_established = True
        print(f"✅ Baseline established: {len(self.normal_connections)} normal connections")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get network monitoring statistics"""
        return {
            'total_connections': self.total_connections,
            'suspicious_connections': self.suspicious_connections,
            'blocked_connections': self.blocked_connections,
            'detection_rate': (
                f"{(self.suspicious_connections / self.total_connections * 100) if self.total_connections > 0 else 0:.2f}%"
            ),
            'baseline_established': self.baseline_established,
            'known_normal_connections': len(self.normal_connections),
            'active_tracking': len(self.connection_history)
        }
    
    def block_connection(self, remote_ip: str, remote_port: int) -> bool:
        """
        Block a network connection (requires admin/root)
        
        Args:
            remote_ip: IP address to block
            remote_port: Port to block
        
        Returns:
            True if blocked successfully
        """
        # This would require firewall integration
        # Platform-specific implementation needed
        
        print(f"🚫 Blocking connection: {remote_ip}:{remote_port}")
        self.blocked_connections += 1
        
        # TODO: Implement actual blocking via:
        # - Windows: netsh advfirewall
        # - Linux: iptables
        # - Mac: pfctl
        
        return True
    
    def _is_connection_suspicious(self, remote_ip: str, remote_port: int, process_name: str) -> bool:
        """
        Intelligently determine if a connection is suspicious
        
        Args:
            remote_ip: Remote IP address
            remote_port: Remote port number
            process_name: Name of the process making the connection
        
        Returns:
            True if suspicious, False otherwise
        """
        # Whitelist localhost connections (development tools, local services)
        if remote_ip in ['127.0.0.1', '::1', 'localhost']:
            return False
        
        # Whitelist known development tools and IDEs
        dev_tools = [
            'antigravity.exe',  # AI Assistant
            'language_server_windows_x64.exe',  # VS Code Language Server
            'code.exe',  # VS Code
            'devenv.exe',  # Visual Studio
            'python.exe',  # Python
            'node.exe',  # Node.js
            'chrome.exe',  # Chrome (for localhost dev)
            'msedge.exe',  # Edge
            'firefox.exe'  # Firefox
        ]
        
        if process_name.lower() in dev_tools:
            return False
        
        # Check if port is explicitly suspicious (C2 ports, malware ports)
        if remote_port in self.SUSPICIOUS_PORTS:
            return True
        
        # Check if connection is in learned baseline
        connection_key = f"{remote_ip}:{remote_port}"
        if connection_key in self.normal_connections:
            return False
        
        # If port is known safe, not suspicious
        if remote_port in self.SAFE_PORTS:
            return False
        
        # Unknown external connection on non-standard port = suspicious
        # But only if it's not a whitelisted process
        if process_name.lower() in {p.lower() for p in self.WHITELISTED_PROCESSES}:
            return False
        
        return True
    
    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Get list of all active connections"""
        active = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    try:
                        process = psutil.Process(conn.pid) if conn.pid else None
                        
                        active.append({
                            'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'status': conn.status,
                            'process_name': process.name() if process else 'Unknown',
                            'process_pid': conn.pid,
                            'is_suspicious': self._is_connection_suspicious(
                                conn.raddr.ip,
                                conn.raddr.port,
                                process.name() if process else 'Unknown'
                            )
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        
        except Exception as e:
            print(f"Error getting active connections: {e}")
        
        return active
