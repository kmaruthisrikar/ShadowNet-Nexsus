"""
ShadowNet Nexus - Real-Time Behavioral Monitor
Monitors input patterns (Keystrokes/Mouse) for bot-like behavior
"""

import time
import threading
import random
import statistics
from datetime import datetime
from typing import Callable, List, Dict, Any

class BehavioralMonitor:
    """
    Real-time Input Behavior Monitor
    Analyzes keystroke dynamics to distinguish Humans from Bots/Keyloggers.
    """
    
    def __init__(self, analyzer, callback: Callable):
        self.analyzer = analyzer
        self.callback = callback
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
            self.monitor_thread.join(timeout=1)

    def _monitor_loop(self):
        """
        Simulation Loop:
        In a real deployment, this would hook into 'keyboard' or 'pywin32' events.
        For this v4.0 Demo, we simulate capturing an input buffer 'check' every 30 seconds.
        """
        print("   ⚡ Behavioral Guard: watching input streams...")
        
        while self.monitoring:
            time.sleep(1) # Check interval
            
            # ------------------------------------------------------------------
            # DEMO LOGIC: Randomly simulate a "suspicious" input burst
            # In production, replace this with actual keyboard hook
            # ------------------------------------------------------------------
            if random.random() < 0.05: # 5% chance per second to "spot" something
                self._run_analysis_simulation()
    
    def _run_analysis_simulation(self):
        """Simulate capturing a burst of data and analyzing it"""
        
        # 1. Generate synthesized data (Simulating a potential attack or human typing)
        is_attack = random.choice([True, False])
        
        if is_attack:
            # Mechanical pattern (Low StDev) = BOT/KEYLOGGER
            timings = [10, 10, 11, 10, 10, 12, 10, 10, 10, 10] 
            description = "Simulated Mechanical Input (Bot-like)"
        else:
            # Organic pattern (High StDev) = HUMAN
            timings = [120, 240, 85, 110, 300, 150, 90, 210]
            description = "Simulated Human Input"

        # 2. Analyze
        # print(f"\n   [Behavior] Analyzing input burst ({len(timings)} events)...")
        # Local pre-check (Optimization)
        try:
            stdev = statistics.stdev(timings)
        except:
            stdev = 100
        
        if stdev < 20: # Suspiciously regular
            print(f"\n   👀 [Behavior] Suspicious regularity detected (Jitter: {stdev:.2f}ms)")
            print(f"   [AI] Verifying input pattern...")
            
            # Call Gemini
            result = self.analyzer.analyze_keystroke_pattern(timings)
            
            if 'error' not in result and not result.get('is_human'):
                # THREAT CONFIRMED
                self.callback({
                    'type': 'behavioral_anomaly',
                    'command': 'Input Injection / Keylogging Activity',
                    'process_info': {
                        'name': 'input_stream',
                        'pid': 'N/A',
                        'details': description
                    },
                    'ai_analysis': result,
                    'severity': 'HIGH'
                })
