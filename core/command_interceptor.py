"""
Command Interceptor
Intercepts commands BEFORE execution to trigger proactive evidence capture
Cross-platform support with OS-specific hooks
"""

import psutil
import time
import threading
from datetime import datetime
from typing import Dict, Any, Callable, Optional
from collections import deque

from utils.os_detector import os_detector


class CommandInterceptor:
    """
    Monitors and intercepts commands before execution
    Provides early warning for proactive evidence capture
    """
    
    def __init__(self, callback: Optional[Callable] = None):
        """
        Initialize Command Interceptor
        
        Args:
            callback: Function to call when suspicious command detected
        """
        self.callback = callback
        self.os_type = os_detector.os_type
        self.is_admin = os_detector.is_admin
        self.monitoring = False
        self.monitor_thread = None
        
        # Command history for pattern detection
        self.command_history = deque(maxlen=100)
        
        # Suspicious keywords from OS detector
        self.suspicious_keywords = os_detector.get_anti_forensics_commands()
        
        # Statistics
        self.commands_monitored = 0
        self.suspicious_detected = 0
    
    def start_monitoring(self, check_interval: float = 0.1):
        """
        Start monitoring for suspicious commands
        
        Args:
            check_interval: How often to check (seconds)
        """
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(check_interval,),
            daemon=True
        )
        self.monitor_thread.start()
        
        print(f"🔍 Command Interceptor: Monitoring started ({self.os_type.upper()})")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        
        print("⏹️  Command Interceptor: Monitoring stopped")
    
    def _monitor_loop(self, check_interval: float):
        """Main monitoring loop"""
        seen_pids = set()
        
        while self.monitoring:
            try:
                # Monitor new processes
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'create_time']):
                    try:
                        pid = proc.info['pid']
                        
                        # Skip if already seen
                        if pid in seen_pids:
                            continue
                        
                        seen_pids.add(pid)
                        
                        # Check command line
                        if proc.info['cmdline']:
                            command = ' '.join(proc.info['cmdline'])
                            self.commands_monitored += 1
                            
                            # Check if suspicious
                            if self._is_suspicious(command):
                                self.suspicious_detected += 1
                                self._handle_suspicious_command(command, proc.info)
                        
                        # Cleanup old PIDs periodically
                        if len(seen_pids) > 10000:
                            seen_pids.clear()
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                time.sleep(check_interval)
                
            except Exception as e:
                print(f"⚠️ Monitor loop error: {str(e)}")
                time.sleep(1)
    
    def _is_suspicious(self, command: str) -> bool:
        """Check if command is suspicious"""
        command_lower = command.lower()
        
        for keyword in self.suspicious_keywords:
            if keyword.lower() in command_lower:
                return True
        
        return False
    
    def _handle_suspicious_command(self, command: str, process_info: Dict[str, Any]):
        """Handle detection of suspicious command"""
        # Add to history
        self.command_history.append({
            'timestamp': datetime.now().isoformat(),
            'command': command,
            'process': process_info
        })
        
        # Call callback if provided
        if self.callback:
            try:
                self.callback(command, process_info)
            except Exception as e:
                print(f"⚠️ Callback error: {str(e)}")
    
    def get_command_history(self, limit: int = 50) -> list:
        """Get recent command history"""
        return list(self.command_history)[-limit:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get interceptor statistics"""
        return {
            'monitoring': self.monitoring,
            'os_type': self.os_type,
            'is_admin': self.is_admin,
            'commands_monitored': self.commands_monitored,
            'suspicious_detected': self.suspicious_detected,
            'detection_rate': (
                self.suspicious_detected / self.commands_monitored * 100
                if self.commands_monitored > 0 else 0
            ),
            'suspicious_keywords_count': len(self.suspicious_keywords)
        }
    
    def analyze_command_sequence(self) -> Dict[str, Any]:
        """
        Analyze recent command sequence for attack patterns
        
        Returns:
            Analysis of command patterns
        """
        if len(self.command_history) < 2:
            return {'pattern_detected': False}
        
        recent = list(self.command_history)[-10:]
        
        # Check for common attack sequences
        patterns = {
            'reconnaissance': ['whoami', 'net user', 'ipconfig', 'systeminfo'],
            'credential_theft': ['mimikatz', 'procdump', 'lsass'],
            'lateral_movement': ['psexec', 'wmic', 'powershell'],
            'anti_forensics': ['wevtutil', 'vssadmin', 'cipher', 'shred']
        }
        
        detected_patterns = []
        
        for pattern_name, keywords in patterns.items():
            matches = 0
            for entry in recent:
                command = entry['command'].lower()
                if any(kw.lower() in command for kw in keywords):
                    matches += 1
            
            if matches >= 2:
                detected_patterns.append({
                    'pattern': pattern_name,
                    'matches': matches,
                    'confidence': min(matches / len(keywords), 1.0)
                })
        
        return {
            'pattern_detected': len(detected_patterns) > 0,
            'patterns': detected_patterns,
            'sequence_length': len(recent),
            'analysis_timestamp': datetime.now().isoformat()
        }
