"""
ShadowNet Nexus - Real-Time Behavioral Monitor
Monitors input patterns (Keystrokes/Mouse) for bot-like behavior
"""

import time
import threading
import random
import statistics
from datetime import datetime
from typing import Callable, List, Dict, Any, Optional

# --- Constants (Bug 14) ---
BEHAVIOR_CHECK_INTERVAL = 1.0  # seconds
STDEV_THRESHOLD = 20           # ms
SIMULATION_PROBABILITY = 0.01  # 1%
JOIN_TIMEOUT = 1.0             # seconds

class BehavioralMonitor:
    """
    Real-time Input Behavior Monitor
    Analyzes keystroke dynamics to distinguish Humans from Bots/Keyloggers.
    """
    
    def __init__(self, analyzer, callback: Callable, enable_simulation: bool = False):
        self.analyzer = analyzer
        self.callback = callback
        self.enable_simulation = enable_simulation # Bug 11
        self.monitoring = False
        self.monitor_thread = None
        self.sample_window = []
        self.last_keystroke_time = time.time()
        
    def start_monitoring(self):
        """Start the behavioral analysis thread"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        print("   [OK] Behavioral Guard: Active (Pattern Analysis)")

    def stop_monitoring(self):
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=JOIN_TIMEOUT)

    def _monitor_loop(self):
        """
        Simulation Loop:
        In a real deployment, this would hook into 'keyboard' or 'pywin32' events.
        For this v4.0 Demo, we simulate capturing an input buffer 'check' every 30 seconds.
        """
        print("   ⚡ Behavioral Guard: watching input streams...")
        
        while self.monitoring:
            time.sleep(BEHAVIOR_CHECK_INTERVAL)
            
            # FIXED: Only run simulation if explicitly enabled (Bug 11)
            if self.enable_simulation and random.random() < SIMULATION_PROBABILITY:
                self._run_analysis_simulation()
    
    def _run_analysis_simulation(self):
        """Simulate capturing a burst of data and analyzing it"""
        
        # 1. Generate synthesized data
        # We only generate "attacks" in this demo to show capability
        is_attack = True 
        
        # Mechanical pattern (Low StDev) = BOT/KEYLOGGER
        timings = [10, 10, 11, 10, 10, 12, 10, 10, 10, 10] 
        description = "[SIMULATED] Mechanical Input (Bot-like Pattern)"

        # 2. Analyze
        try:
            stdev = statistics.stdev(timings)
        except Exception as e:
            stdev = 100
        
        if stdev < STDEV_THRESHOLD: # Suspiciously regular
            # Only print if it's a confirmed "threat" in our simulation
            # AI verification (Mocked for speed or called for real)
            result = self.analyzer.analyze_keystroke_pattern(timings)
            
            if 'error' not in result and not result.get('is_human'):
                # THREAT CONFIRMED
                self.callback({
                    'type': 'behavioral_anomaly',
                    'command': f'Input Injection Activity {description}',
                    'process_info': {
                        'name': 'behavioral_engine',
                        'pid': 'N/A',
                        'details': description
                    },
                    'ai_analysis': result,
                    'severity': 'HIGH'
                })
