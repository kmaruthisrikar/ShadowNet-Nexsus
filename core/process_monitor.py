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
        # 🛡️ Admin Check
        if platform.system().lower() == 'windows' and not is_admin():
            print("\n⚠️  PRIVILEGE ALERT: ShadowNet is NOT Admin. System processes (wevtutil) might be hidden.\n")

        pythoncom.CoInitialize()
        try:
            w = wmi.WMI()
            # 1.0s is much more stable than 0.1s for some WMI providers
            query = "SELECT * FROM __InstanceCreationEvent WITHIN 1.0 WHERE TargetInstance ISA 'Win32_Process'"
            watcher = w.watch_for(raw_wql=query)
            
            last_pulse = time.time()
            while self.monitoring:
                try:
                    # Self-Pulse: Verify monitor is hearing things
                    if time.time() - last_pulse > 20:
                        subprocess.Popen(['cmd.exe', '/c', 'echo ShadowNetPulse'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        last_pulse = time.time()

                    event = watcher(timeout_ms=500)
                    if event:
                        proc = event.TargetInstance
                        name = str(proc.Name)
                        pid = proc.ProcessId
                        
                        # Diagnostic: Show EVERY discovery instantly
                        if "ShadowNetPulse" not in name:
                            sys.stdout.write(f" [DISCOVERED: {name}] ")
                            sys.stdout.flush()

                        try:
                            cmd = str(proc.CommandLine or proc.ExecutablePath or name)
                        except:
                            cmd = name

                        # Aggressive forensic check
                        is_suspicious_exe = any(kw.lower() in name.lower() for kw in self.suspicious_keywords)
                        
                        if self._is_suspicious(cmd) or is_suspicious_exe:
                            self.processes_detected += 1
                            owner = "Unknown"
                            try:
                                owner_info = proc.GetOwner()
                                if owner_info and owner_info[0]:
                                    owner = f"{owner_info[0]}\\{owner_info[2]}"
                            except: pass
                            
                            p_info = {
                                'pid': pid,
                                'name': name,
                                'cmdline': [cmd],
                                'username': owner,
                                'parent_pid': proc.ParentProcessId
                            }
                            self._handle_suspicious_command(cmd, p_info, "WMI")
                except wmi.x_wmi_timed_out:
                    continue
                except Exception:
                    pass 
        except Exception as e:
            print(f"⚠️ WMI Critical failure: {e}")
        finally:
            pythoncom.CoUninitialize()

    def _polling_loop(self):
        seen_pids = set()
        while self.monitoring:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                    pid = proc.info['pid']
                    if pid in seen_pids: continue
                    seen_pids.add(pid)
                    
                    name = proc.info.get('name', '')
                    cmdline = proc.info.get('cmdline')
                    full_cmd = " ".join(cmdline) if cmdline else name
                    
                    # Detect by Command Line OR by Binary Name (Fast-kill fallback)
                    is_suspicious_exe = any(kw.lower() in name.lower() for kw in self.suspicious_keywords)
                    
                    if self._is_suspicious(full_cmd) or is_suspicious_exe:
                        self._handle_suspicious_command(full_cmd, {
                            'pid': pid,
                            'name': name,
                            'cmdline': cmdline or [name],
                            'username': proc.info.get('username', 'Unknown'),
                            'parent_pid': proc.ppid() if hasattr(proc, 'ppid') else 0
                        }, "Polling")
            except: pass
            
            if len(seen_pids) > 2000: seen_pids.clear()
            time.sleep(0.05) # Balanced frequency


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
