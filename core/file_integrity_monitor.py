"""
File Integrity Monitoring Module
Detects unauthorized file modifications, ransomware encryption, and data destruction
"""

import os
import hashlib
import threading
import time
from typing import Dict, List, Any, Callable, Optional, Set
from datetime import datetime
from pathlib import Path
import json


class FileIntegrityMonitor:
    """
    Real-time file integrity monitoring for threat detection
    """
    
    # Critical system paths to monitor
    CRITICAL_PATHS_WINDOWS = [
        r"C:\Windows\System32\drivers\etc\hosts",
        r"C:\Windows\System32\config",
        r"C:\Windows\System32\drivers",
    ]
    
    CRITICAL_PATHS_LINUX = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/ssh/sshd_config",
        "/var/log",
    ]
    
    CRITICAL_PATHS_MAC = [
        "/etc/hosts",
        "/etc/passwd",
        "/Library/LaunchDaemons",
        "/System/Library/Extensions",
    ]
    
    # Ransomware indicators
    RANSOMWARE_EXTENSIONS = {
        '.locked', '.encrypted', '.crypto', '.crypt', '.enc',
        '.lockbit', '.blackcat', '.alphv', '.royal', '.play',
        '.akira', '.blackbasta', '.conti', '.revil'
    }
    
    def __init__(
        self, 
        watch_paths: Optional[List[str]] = None,
        callback: Optional[Callable] = None,
        check_interval: float = 5.0
    ):
        """
        Initialize file integrity monitor
        
        Args:
            watch_paths: Paths to monitor (auto-detect if None)
            callback: Function to call when changes detected
            check_interval: How often to check files (seconds)
        """
        self.callback = callback
        self.check_interval = check_interval
        self.monitoring = False
        self.monitor_thread = None
        
        # Auto-detect critical paths
        if watch_paths is None:
            self.watch_paths = self._get_default_paths()
        else:
            self.watch_paths = watch_paths
        
        # File state tracking
        self.file_hashes: Dict[str, str] = {}
        self.file_metadata: Dict[str, Dict[str, Any]] = {}
        
        # Statistics
        self.total_files_monitored = 0
        self.changes_detected = 0
        self.ransomware_indicators = 0
        
        # Rapid encryption detection
        self.recent_modifications: List[tuple] = []  # (path, timestamp)
    
    def _get_default_paths(self) -> List[str]:
        """Get default critical paths based on OS"""
        import platform
        
        os_type = platform.system()
        
        if os_type == "Windows":
            return self.CRITICAL_PATHS_WINDOWS
        elif os_type == "Linux":
            return self.CRITICAL_PATHS_LINUX
        elif os_type == "Darwin":
            return self.CRITICAL_PATHS_MAC
        else:
            return []
    
    def start_monitoring(self):
        """Start file integrity monitoring"""
        if self.monitoring:
            return
        
        # Build initial baseline
        print("📁 Building file integrity baseline...")
        self._build_baseline()
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        print(f"📁 File integrity monitoring started ({self.total_files_monitored} files)")
    
    def stop_monitoring(self):
        """Stop file integrity monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        print("📁 File integrity monitoring stopped")
    
    def _build_baseline(self):
        """Build initial baseline of file hashes"""
        for watch_path in self.watch_paths:
            if os.path.exists(watch_path):
                if os.path.isfile(watch_path):
                    self._hash_file(watch_path)
                elif os.path.isdir(watch_path):
                    self._hash_directory(watch_path)
    
    def _hash_file(self, file_path: str) -> Optional[str]:
        """
        Calculate SHA-256 hash of file
        
        Args:
            file_path: Path to file
        
        Returns:
            SHA-256 hash or None if error
        """
        try:
            hasher = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                # Read in chunks for large files
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            
            file_hash = hasher.hexdigest()
            
            # Store hash and metadata
            self.file_hashes[file_path] = file_hash
            self.file_metadata[file_path] = {
                'size': os.path.getsize(file_path),
                'modified': os.path.getmtime(file_path),
                'hash': file_hash
            }
            
            self.total_files_monitored += 1
            
            return file_hash
        
        except (IOError, PermissionError):
            return None
    
    def _hash_directory(self, dir_path: str, max_depth: int = 3):
        """
        Recursively hash all files in directory
        
        Args:
            dir_path: Directory path
            max_depth: Maximum recursion depth
        """
        if max_depth <= 0:
            return
        
        try:
            for entry in os.scandir(dir_path):
                try:
                    if entry.is_file(follow_symlinks=False):
                        self._hash_file(entry.path)
                    elif entry.is_dir(follow_symlinks=False):
                        self._hash_directory(entry.path, max_depth - 1)
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            pass
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                self._check_integrity()
                time.sleep(self.check_interval)
            except Exception as e:
                print(f"File integrity monitoring error: {e}")
    
    def _check_integrity(self):
        """Check file integrity against baseline"""
        for file_path, baseline_hash in list(self.file_hashes.items()):
            if not os.path.exists(file_path):
                # File deleted
                threat_info = {
                    'type': 'file_deleted',
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'HIGH',
                    'file_path': file_path,
                    'baseline_hash': baseline_hash,
                    'threat_indicators': ['Critical file deleted'],
                    'recommended_action': 'investigate'
                }
                
                self.changes_detected += 1
                
                if self.callback:
                    self.callback(threat_info)
                
                # Remove from tracking
                del self.file_hashes[file_path]
                del self.file_metadata[file_path]
                
                continue
            
            # Check if file modified
            current_mtime = os.path.getmtime(file_path)
            baseline_mtime = self.file_metadata[file_path]['modified']
            
            if current_mtime > baseline_mtime:
                # File modified - recalculate hash
                current_hash = self._calculate_hash(file_path)
                
                if current_hash and current_hash != baseline_hash:
                    # Hash changed - file modified
                    threat_info = self._analyze_modification(
                        file_path,
                        baseline_hash,
                        current_hash
                    )
                    
                    self.changes_detected += 1
                    
                    if self.callback:
                        self.callback(threat_info)
                    
                    # Update baseline
                    self.file_hashes[file_path] = current_hash
                    self.file_metadata[file_path]['hash'] = current_hash
                    self.file_metadata[file_path]['modified'] = current_mtime
        
        # Detect new files in watched directories
        for watch_path in self.watch_paths:
            if os.path.isdir(watch_path):
                self._scan_new_files(watch_path)
        
        # Check for ransomware mass encryption
        self._detect_mass_encryption()
    
    def _scan_new_files(self, dir_path: str):
        """Scan for new files not in baseline"""
        try:
            for entry in os.scandir(dir_path):
                if entry.is_file() and entry.path not in self.file_hashes:
                    # New file detected!
                    self.changes_detected += 1
                    
                    # Analyze as new file (could be ransomware)
                    threat_info = self._analyze_modification(
                        entry.path,
                        "NEW_FILE",
                        self._calculate_hash(entry.path)
                    )
                    
                    if self.callback:
                        self.callback(threat_info)
                        
                    # Add to baseline so we don't alert again
                    self._hash_file(entry.path)
        except Exception:
            pass
    
    def _calculate_hash(self, file_path: str) -> Optional[str]:
        """Calculate hash without updating baseline"""
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (IOError, PermissionError):
            return None
    
    def _analyze_modification(
        self, 
        file_path: str, 
        old_hash: str, 
        new_hash: str
    ) -> Dict[str, Any]:
        """
        Analyze file modification for threats
        
        Args:
            file_path: Path to modified file
            old_hash: Original hash
            new_hash: New hash
        
        Returns:
            Threat information dictionary
        """
        threat_indicators = []
        severity = "MEDIUM"
        
        # Check for ransomware extension
        file_ext = Path(file_path).suffix.lower()
        if file_ext in self.RANSOMWARE_EXTENSIONS:
            threat_indicators.append(f"Ransomware extension detected: {file_ext}")
            severity = "CRITICAL"
            self.ransomware_indicators += 1
        
        # Check if critical system file
        is_critical = any(
            critical in file_path 
            for critical in (
                self.CRITICAL_PATHS_WINDOWS + 
                self.CRITICAL_PATHS_LINUX + 
                self.CRITICAL_PATHS_MAC
            )
        )
        
        if is_critical:
            threat_indicators.append("Critical system file modified")
            severity = "CRITICAL"
        
        # Track for mass encryption detection
        self.recent_modifications.append((file_path, time.time()))
        
        return {
            'type': 'file_modified',
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'file_path': file_path,
            'old_hash': old_hash,
            'new_hash': new_hash,
            'file_extension': file_ext,
            'is_critical': is_critical,
            'threat_indicators': threat_indicators,
            'recommended_action': 'preserve_evidence' if severity == 'CRITICAL' else 'monitor'
        }
    
    def _detect_mass_encryption(self):
        """Detect ransomware mass encryption"""
        now = time.time()
        
        # Clean old modifications (keep last 60 seconds)
        self.recent_modifications = [
            (path, ts) for path, ts in self.recent_modifications
            if now - ts < 60
        ]
        
        # Check for rapid file modifications (ransomware indicator)
        if len(self.recent_modifications) > 50:  # >50 files in 60 seconds
            threat_info = {
                'type': 'mass_encryption_detected',
                'timestamp': datetime.now().isoformat(),
                'severity': 'CRITICAL',
                'files_modified': len(self.recent_modifications),
                'time_window': '60 seconds',
                'threat_indicators': [
                    f'Rapid file modification: {len(self.recent_modifications)} files in 60s',
                    'Likely ransomware encryption in progress'
                ],
                'affected_files': [path for path, _ in self.recent_modifications[-10:]],
                'recommended_action': 'isolate_system'
            }
            
            if self.callback:
                self.callback(threat_info)
            
            # Clear to avoid repeated alerts
            self.recent_modifications.clear()
    
    def add_watch_path(self, path: str):
        """Add a new path to monitor"""
        if path not in self.watch_paths:
            self.watch_paths.append(path)
            
            if os.path.exists(path):
                if os.path.isfile(path):
                    self._hash_file(path)
                elif os.path.isdir(path):
                    self._hash_directory(path)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get file integrity monitoring statistics"""
        return {
            'total_files_monitored': self.total_files_monitored,
            'changes_detected': self.changes_detected,
            'ransomware_indicators': self.ransomware_indicators,
            'watch_paths': len(self.watch_paths),
            'recent_modifications': len(self.recent_modifications)
        }
    
    def get_file_status(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific file"""
        if file_path in self.file_metadata:
            return self.file_metadata[file_path]
        return None
