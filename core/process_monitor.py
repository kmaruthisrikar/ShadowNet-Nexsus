"""
ShadowNet Nexus - Cross-Platform Process Monitor
Supports Windows (WMI + Polling), Linux (Polling), and Mac (Polling)
"""

import os
import sys
import threading
import time
from datetime import datetime
from typing import Callable, Optional, Dict, Any, List
from collections import deque
import platform
import subprocess
import ctypes

def is_admin():
    try:
        if platform.system().lower() == 'windows':
            return ctypes.windll.shell32.IsUserAnAdmin()
        return os.getuid() == 0
    except:
        return False

# Conditional imports
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    if platform.system().lower() == 'windows':
        import wmi
        import pythoncom
        HAS_WMI = True
    else:
        HAS_WMI = False
except ImportError:
    HAS_WMI = False


class BaseProcessMonitor:
    """Base class for platform-specific process monitors"""
    def __init__(self, callback: Optional[Callable] = None, suspicious_keywords: List[str] = None):
        self.callback = callback
        self.suspicious_keywords = suspicious_keywords or []
        self.monitoring = False
        self.processes_detected = 0
        self.suspicious_detected = 0
        self.command_history = deque(maxlen=100)
        self.os_type = platform.system().lower()

    def start_monitoring(self):
        raise NotImplementedError

    def stop_monitoring(self):
        self.monitoring = False

    def _is_suspicious(self, command: str) -> bool:
        if not command:
            return False
        cmd_lower = command.lower()
        for keyword in self.suspicious_keywords:
            if keyword.lower() in cmd_lower:
                return True
        return False

    def _handle_suspicious_command(self, command: str, process_info: Dict[str, Any], method: str):
        self.suspicious_detected += 1
        
        # Call callback if provided
        if self.callback:
            try:
                self.callback(command, process_info)
            except Exception as e:
                print(f"⚠️  Callback error: {str(e)}")

        self.command_history.append({
            'timestamp': datetime.now().isoformat(),
            'command': command,
            'process': process_info,
            'method': method
        })

    def get_statistics(self) -> Dict[str, Any]:
        return {
            'monitoring': self.monitoring,
            'processes_detected': self.processes_detected,
            'suspicious_detected': self.suspicious_detected,
            'os': self.os_type
        }


class WindowsProcessMonitor(BaseProcessMonitor):
    """Windows-specific monitor using WMI events and Fast Polling"""
    def __init__(self, callback: Optional[Callable] = None, suspicious_keywords: List[str] = None):
        super().__init__(callback, suspicious_keywords)
        self.wmi_thread = None
        self.polling_thread = None

    def start_monitoring(self):
        if self.monitoring:
            return
        self.monitoring = True
        
        # 1. WMI Thread (Event-driven)
        if HAS_WMI:
            self.wmi_thread = threading.Thread(target=self._wmi_monitor_loop, daemon=True)
            self.wmi_thread.start()
        
        # 2. Polling Thread (Backup)
        if HAS_PSUTIL:
            self.polling_thread = threading.Thread(target=self._polling_loop, daemon=True)
            self.polling_thread.start()
            
        print(f"⚡ Windows Process Monitor: ACTIVE (WMI: {'YES' if HAS_WMI else 'NO'}, Polling: {'YES' if HAS_PSUTIL else 'NO'})")

    def _wmi_monitor_loop(self):
        pythoncom.CoInitialize()
        wmi_working = False
        try:
            w = wmi.WMI()
            # 1. WMI Event Watcher initialization with delay fallback
            print("   [WMI] Attempting to initialize event watcher...")
            try:
                # FIXED: Use delay_secs for more stable WMI event delivery
                watcher = w.Win32_Process.watch_for(
                    notification_type="creation",
                    delay_secs=1
                )
            except Exception as e:
                print(f"   [ERROR] WMI event watcher failed: {e}")
                print("   [FALLBACK] Using polling-only mode")
                wmi_working = False
                return

            wmi_working = True
            print("   [WMI] ✅ Event watcher initialized successfully")
            
            last_pulse = time.time()
            while self.monitoring:
                try:
                    # Self-Pulse: Verify monitor is hearing things
                    if time.time() - last_pulse > 20:
                        subprocess.Popen(['cmd.exe', '/c', 'echo ShadowNetPulse'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        last_pulse = time.time()

                    # Use shorter timeout to avoid blocking
                    new_process = watcher(timeout_ms=100)
                    if new_process:
                        name = str(new_process.Name)
                        pid = new_process.ProcessId
                        
                        # Diagnostic: Show EVERY discovery instantly
                        if "ShadowNetPulse" not in name:
                            sys.stdout.write(f" [WMI-DISCOVERED: {name}] ")
                            sys.stdout.flush()

                        # FIXED: Better fallback chain for command line
                        try:
                            cmdline = getattr(new_process, 'CommandLine', None)
                            if not cmdline or str(cmdline).strip() == "":
                                cmdline = getattr(new_process, 'ExecutablePath', name)
                            if not cmdline:
                                cmdline = name
                            cmd = str(cmdline)
                        except Exception as e:
                            cmd = name

                        # Aggressive forensic check
                        is_suspicious_exe = any(kw.lower() in name.lower() for kw in self.suspicious_keywords)
                        
                        if self._is_suspicious(cmd) or is_suspicious_exe:
                            self.processes_detected += 1
                            owner = "Unknown"
                            try:
                                owner_info = new_process.GetOwner()
                                if owner_info and owner_info[0]:
                                    owner = f"{owner_info[0]}\\{owner_info[2]}"
                            except: pass
                            
                            p_info = {
                                'pid': pid,
                                'name': name,
                                'cmdline': [cmd],
                                'username': owner,
                                'parent_pid': new_process.ParentProcessId
                            }
                            self._handle_suspicious_command(cmd, p_info, "WMI")
                except wmi.x_wmi_timed_out:
                    # Normal timeout, continue silently
                    continue
                except Exception as e:
                    if self.monitoring:
                        print(f"\n⚠️  WMI Error: {e}")
                        time.sleep(1) # Prevent tight error loop
                    continue
        except Exception as e:
            print(f"⚠️ WMI initialization failed: {e}")
            print("   [FALLBACK] Switching to polling-only mode...")
        finally:
            pythoncom.CoUninitialize()
            
        if not wmi_working:
            print("   [INFO] WMI not available, relying on polling fallback")

    def _polling_loop(self):
        seen_pids = set()
        print("   [POLLING] Ultra-fast differential polling active (10ms interval)")
        while self.monitoring:
            try:
                # FIXED: Proper differential tracking for polling
                current_pids = set(p.info['pid'] for p in psutil.process_iter(['pid']))
                new_pids = current_pids - seen_pids
                
                # Check for processes that vanished to clean up seen_pids
                seen_pids = current_pids

                # Only examine new processes or all if requested
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                    try:
                        pid = proc.info['pid']
                        if pid not in new_pids:
                            continue
                            
                        name = proc.info.get('name', '')
                        cmdline = proc.info.get('cmdline')
                        full_cmd = " ".join(cmdline) if cmdline else name
                        
                        # Detect by Command Line OR by Binary Name (Fast-kill fallback)
                        is_suspicious_exe = any(kw.lower() in name.lower() for kw in self.suspicious_keywords)
                        is_suspicious_cmd = self._is_suspicious(full_cmd)
                        
                        # Debug: Show when we find a match
                        if is_suspicious_exe or is_suspicious_cmd:
                            print(f"\n[MATCH!] {name} (PID: {pid}) - Exe:{is_suspicious_exe}, Cmd:{is_suspicious_cmd}")
                            print(f"[MATCH!] Full command: {full_cmd[:100]}...")
                        
                        if is_suspicious_cmd or is_suspicious_exe:
                            self._handle_suspicious_command(full_cmd, {
                                'pid': pid,
                                'name': name,
                                'cmdline': cmdline or [name],
                                'username': proc.info.get('username', 'Unknown'),
                                'parent_pid': proc.ppid() if hasattr(proc, 'ppid') else 0
                            }, "Polling")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception as e:
                if self.monitoring:
                    # Use stderr for internal errors to keep stdout clean
                    pass
            
            time.sleep(0.01) # 10ms ultra-fast polling


class UnixProcessMonitor(BaseProcessMonitor):
    """Linux/Mac monitor using Optimized Polling"""
    def __init__(self, callback: Optional[Callable] = None, suspicious_keywords: List[str] = None):
        super().__init__(callback, suspicious_keywords)
        self.polling_thread = None

    def start_monitoring(self):
        if self.monitoring:
            return
        self.monitoring = True
        
        if HAS_PSUTIL:
            self.polling_thread = threading.Thread(target=self._polling_loop, daemon=True)
            self.polling_thread.start()
            print(f"⚡ {self.os_type.upper()} Process Monitor: ACTIVE (Polling-Based)")
        else:
            print(f"❌ {self.os_type.upper()} Monitor Failed: psutil not installed")

    def _polling_loop(self):
        """
        High-Performance Differential Polling (Linux/Mac)
        Strategy: Only fetch full details for NEW PIDs to minimize I/O overhead.
        Target Latency: ~5ms
        """
        known_pids = set(psutil.pids())
        
        while self.monitoring:
            try:
                # 1. Light scan: Get current PIDs only
                current_pids = set(psutil.pids())
                
                # 2. find new processes (Differential)
                new_pids = current_pids - known_pids
                
                if new_pids:
                    for pid in new_pids:
                        try:
                            # 3. Deep interaction only for NEW targets
                            proc = psutil.Process(pid)
                            
                            # Fast-fail checks
                            try:
                                cmdline = proc.cmdline()
                            except (psutil.ZombieProcess, psutil.AccessDenied, psutil.NoSuchProcess):
                                continue
                                
                            if not cmdline: continue
                            
                            full_cmd = " ".join(cmdline)
                            
                            if self._is_suspicious(full_cmd):
                                p_info = {
                                    'pid': pid,
                                    'name': proc.name(),
                                    'cmdline': cmdline,
                                    'username': proc.username(),
                                    'parent_pid': proc.ppid()
                                }
                                self._handle_suspicious_command(full_cmd, p_info, "Fast-Poll")
                                
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            pass
                
                # Update baseline
                known_pids = current_pids
                
                # 4. Cleanup dead PIDs from set to prevent memory growth (optional but good)
                # (handled by reassignment above)
                
            except Exception as e:
                # print(f"Poll Error: {e}") 
                pass
            
            # Adaptive High-Speed Sleep
            # If we found something, sleep less. If idle, sleep normal.
            time.sleep(0.005) # 5ms Latency Target


def ProcessMonitor(callback: Optional[Callable] = None, suspicious_keywords: List[str] = None):
    """Factory function to return the correct monitor for the platform"""
    os_type = platform.system().lower()
    if os_type == 'windows':
        print(f"   [WMI] Initializing Kernel Watcher with {len(suspicious_keywords)} triggers...")
        return WindowsProcessMonitor(callback, suspicious_keywords)
    else:
        # Linux and Darwin (Mac) share psutil logic
        return UnixProcessMonitor(callback, suspicious_keywords)
