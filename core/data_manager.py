"""
ShadowNet Nexus - Data Manager
Shares state between the monitoring engine and the API server
Ensures real-time data persistence
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import threading

class DataManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DataManager, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, data_file: str = "data/shadow_state.json"):
        if self._initialized:
            return
            
        self.data_file = Path(data_file)
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.lock = threading.Lock()
        self.state = self._load_state()
        self._initialized = True

    def _load_state(self) -> Dict[str, Any]:
        """Loads state from disk or initializes defaults"""
        if self.data_file.exists():
            try:
                with open(self.data_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
                
        return {
            'stats': {
                'threats_detected': 0,
                'evidence_preserved': 0,
                'systems_monitored': 1,
                'active_alerts': 0,
                'start_time': datetime.now().isoformat()
            },
            'threats': [],
            'network_baseline': {},
            'alert_history': [],
            'action_logs': []
        }

    def _save_state(self):
        """Saves current state to disk"""
        with self.lock:
            try:
                with open(self.data_file, 'w') as f:
                    json.dump(self.state, f, indent=4)
            except Exception as e:
                print(f"Error saving state: {e}")

    def add_threat(self, threat: Dict[str, Any]):
        """Adds a real detected threat to the state"""
        # Always reload first to get latest state from other processes
        self.state = self._load_state()
        
        with self.lock:
            # Ensure timestamp
            if 'timestamp' not in threat:
                threat['timestamp'] = datetime.now().isoformat()
            
            # Avoid duplicates if possible
            if not any(t.get('id') == threat.get('id') for t in self.state['threats']):
                self.state['threats'].insert(0, threat)
                # Keep only last 100 threats
                self.state['threats'] = self.state['threats'][:100]
                
                # Update stats
                self.state['stats']['threats_detected'] += 1
                self.state['stats']['active_alerts'] += 1
            
        self._save_state()

    def record_evidence(self, size_mb: float = 0):
        """Updates evidence preservation stats"""
        self.state = self._load_state()
        with self.lock:
            self.state['stats']['evidence_preserved'] += size_mb
        self._save_state()

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Returns the full state for the dashboard"""
        # Force reload from disk to see changes from other processes (e.g. keylogger test)
        self.state = self._load_state()
        with self.lock:
            return self.state

    def reset_alerts(self):
        """Clears active alerts counter"""
        self.state = self._load_state()
        with self.lock:
            self.state['stats']['active_alerts'] = 0
        self._save_state()

# Global instance
data_manager = DataManager()
