"""
Automated Response Engine
Automatically responds to threats: kill processes, quarantine files, block connections
"""

import os
import psutil
import shutil
import subprocess
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
from enum import Enum


class ResponseAction(str, Enum):
    """Available automated response actions"""
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    BLOCK_CONNECTION = "block_connection"
    ISOLATE_SYSTEM = "isolate_system"
    SNAPSHOT_EVIDENCE = "snapshot_evidence"
    ALERT_ONLY = "alert_only"


class ResponseEngine:
    """
    Automated threat response system
    """
    
    def __init__(
        self, 
        quarantine_dir: str = "./quarantine",
        auto_response_enabled: bool = True,
        require_confirmation: bool = False
    ):
        """
        Initialize response engine
        
        Args:
            quarantine_dir: Directory for quarantined files
            auto_response_enabled: Enable automatic responses
            require_confirmation: Require human confirmation for actions
        """
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        self.auto_response_enabled = auto_response_enabled
        self.require_confirmation = require_confirmation
        
        # Statistics
        self.total_responses = 0
        self.responses_by_action: Dict[str, int] = {
            action.value: 0 for action in ResponseAction
        }
        self.successful_responses = 0
        self.failed_responses = 0
        
        # Response log
        self.response_log: List[Dict[str, Any]] = []
    
    def respond_to_threat(
        self, 
        threat_info: Dict[str, Any],
        override_confirmation: bool = False
    ) -> Dict[str, Any]:
        """
        Automatically respond to detected threat
        
        Args:
            threat_info: Threat information dictionary
            override_confirmation: Skip confirmation if True
        
        Returns:
            Response result dictionary
        """
        if not self.auto_response_enabled:
            return {
                'success': False,
                'reason': 'Automated response disabled',
                'action_taken': ResponseAction.ALERT_ONLY
            }
        
        # Determine appropriate response action
        action = self._determine_response_action(threat_info)
        
        # Check if confirmation required
        if self.require_confirmation and not override_confirmation:
            return {
                'success': False,
                'reason': 'Human confirmation required',
                'recommended_action': action.value,
                'threat_info': threat_info
            }
        
        # Execute response
        result = self._execute_response(action, threat_info)
        
        # Log response
        self._log_response(action, threat_info, result)
        
        return result
    
    def _determine_response_action(self, threat_info: Dict[str, Any]) -> ResponseAction:
        """
        Determine appropriate response action based on threat
        
        Args:
            threat_info: Threat information
        
        Returns:
            Recommended response action
        """
        threat_type = threat_info.get('type', '')
        severity = threat_info.get('severity', 'LOW')
        
        # Critical severity - aggressive response
        if severity == 'CRITICAL':
            if threat_type == 'suspicious_process':
                return ResponseAction.KILL_PROCESS
            elif threat_type == 'suspicious_network_connection':
                return ResponseAction.BLOCK_CONNECTION
            elif threat_type == 'mass_encryption_detected':
                return ResponseAction.ISOLATE_SYSTEM
            elif threat_type == 'file_modified':
                return ResponseAction.QUARANTINE_FILE
        
        # High severity - moderate response
        elif severity == 'HIGH':
            if threat_type == 'suspicious_process':
                return ResponseAction.KILL_PROCESS
            elif threat_type in ['file_modified', 'file_deleted']:
                return ResponseAction.SNAPSHOT_EVIDENCE
        
        # Default - alert only
        return ResponseAction.ALERT_ONLY
    
    def _execute_response(
        self, 
        action: ResponseAction, 
        threat_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute response action
        
        Args:
            action: Response action to execute
            threat_info: Threat information
        
        Returns:
            Execution result
        """
        self.total_responses += 1
        self.responses_by_action[action.value] += 1
        
        start_time = datetime.now()
        
        try:
            if action == ResponseAction.KILL_PROCESS:
                result = self._kill_process(threat_info)
            elif action == ResponseAction.QUARANTINE_FILE:
                result = self._quarantine_file(threat_info)
            elif action == ResponseAction.BLOCK_CONNECTION:
                result = self._block_connection(threat_info)
            elif action == ResponseAction.ISOLATE_SYSTEM:
                result = self._isolate_system(threat_info)
            elif action == ResponseAction.SNAPSHOT_EVIDENCE:
                result = self._snapshot_evidence(threat_info)
            else:
                result = {'success': True, 'action': 'alert_only'}
            
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            result['response_time_ms'] = response_time
            result['action'] = action.value
            
            if result.get('success'):
                self.successful_responses += 1
            else:
                self.failed_responses += 1
            
            return result
        
        except Exception as e:
            self.failed_responses += 1
            return {
                'success': False,
                'action': action.value,
                'error': str(e),
                'response_time_ms': (datetime.now() - start_time).total_seconds() * 1000
            }
    
    def _kill_process(self, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        """Kill malicious process"""
        pid = threat_info.get('process_pid') or threat_info.get('pid')
        
        if not pid:
            return {'success': False, 'reason': 'No PID provided'}
        
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            process_path = process.exe()
            
            # Terminate process
            process.terminate()
            
            # Wait for termination
            try:
                process.wait(timeout=3)
            except psutil.TimeoutExpired:
                # Force kill if terminate didn't work
                process.kill()
            
            return {
                'success': True,
                'pid': pid,
                'process_name': process_name,
                'process_path': process_path,
                'message': f'Process {process_name} (PID: {pid}) terminated'
            }
        
        except psutil.NoSuchProcess:
            return {
                'success': False,
                'reason': f'Process {pid} no longer exists'
            }
        except psutil.AccessDenied:
            return {
                'success': False,
                'reason': f'Access denied - requires admin/root privileges'
            }
    
    def _quarantine_file(self, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        """Quarantine malicious file"""
        file_path = threat_info.get('file_path') or threat_info.get('path')
        
        if not file_path or not os.path.exists(file_path):
            return {'success': False, 'reason': 'File not found'}
        
        try:
            # Generate quarantine filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_name = Path(file_path).name
            quarantine_path = self.quarantine_dir / f"{timestamp}_{file_name}"
            
            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            
            # Create metadata file
            metadata_path = quarantine_path.with_suffix('.metadata.json')
            import json
            with open(metadata_path, 'w') as f:
                json.dump({
                    'original_path': file_path,
                    'quarantined_at': datetime.now().isoformat(),
                    'threat_info': threat_info
                }, f, indent=2)
            
            # 🛡️ PRESERVE AS FORENSIC ARTIFACT (evidence/artifacts)
            try:
                from utils.evidence_vault import EvidenceVault
                # Initialize vault (assuming default path or ideally passed in)
                vault = EvidenceVault("./evidence")
                
                incident_id = threat_info.get('id', 'UNKNOWN_INCIDENT')
                artifact_id = vault.preserve_file_artifact(
                    incident_id=incident_id,
                    source_file=str(quarantine_path), # Use the SAFE quarantined copy
                    artifact_type="malware_sample"
                )
                print(f"   📦 Artifact preserved in vault: {artifact_id}")
            except Exception as e:
                print(f"   ⚠️ Failed to preserve artifact: {e}")
            
            return {
                'success': True,
                'original_path': file_path,
                'quarantine_path': str(quarantine_path),
                'artifact_id': locals().get('artifact_id', 'failed'),
                'message': f'File quarantined and preserved: {file_path}'
            }
        
        except Exception as e:
            return {
                'success': False,
                'reason': f'Quarantine failed: {str(e)}'
            }
    
    def _block_connection(self, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        """Block network connection"""
        remote_ip = threat_info.get('remote_ip')
        remote_port = threat_info.get('remote_port')
        
        if not remote_ip:
            return {'success': False, 'reason': 'No IP address provided'}
        
        try:
            # Platform-specific firewall commands
            import platform
            os_type = platform.system()
            
            if os_type == "Windows":
                # Windows Firewall
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=ShadowNet_Block_{remote_ip}',
                    'dir=out',
                    'action=block',
                    f'remoteip={remote_ip}'
                ]
            elif os_type == "Linux":
                # iptables
                cmd = [
                    'iptables', '-A', 'OUTPUT',
                    '-d', remote_ip,
                    '-j', 'DROP'
                ]
            elif os_type == "Darwin":
                # pfctl (Mac)
                cmd = [
                    'pfctl', '-t', 'shadownet_blocklist',
                    '-T', 'add', remote_ip
                ]
            else:
                return {'success': False, 'reason': 'Unsupported OS'}
            
            # Execute firewall command (requires admin/root)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'message': f'Connection to {remote_ip} blocked'
                }
            else:
                return {
                    'success': False,
                    'reason': f'Firewall command failed: {result.stderr}'
                }
        
        except subprocess.TimeoutExpired:
            return {'success': False, 'reason': 'Firewall command timed out'}
        except PermissionError:
            return {'success': False, 'reason': 'Requires admin/root privileges'}
        except Exception as e:
            return {'success': False, 'reason': str(e)}
    
    def _isolate_system(self, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        """Isolate system from network (emergency response)"""
        try:
            import platform
            os_type = platform.system()
            
            if os_type == "Windows":
                # Disable all network adapters
                cmd = ['netsh', 'interface', 'set', 'interface', 'name="Ethernet"', 'admin=disabled']
            elif os_type == "Linux":
                # Bring down all interfaces except loopback
                cmd = ['ip', 'link', 'set', 'down', 'dev', 'eth0']
            elif os_type == "Darwin":
                # Disable network interfaces
                cmd = ['networksetup', '-setnetworkserviceenabled', 'Wi-Fi', 'off']
            else:
                return {'success': False, 'reason': 'Unsupported OS'}
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'message': '⚠️ SYSTEM ISOLATED FROM NETWORK',
                    'warning': 'Manual intervention required to restore connectivity'
                }
            else:
                return {
                    'success': False,
                    'reason': f'Network isolation failed: {result.stderr}'
                }
        
        except Exception as e:
            return {'success': False, 'reason': str(e)}
    
    def _snapshot_evidence(self, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        """Create emergency evidence snapshot"""
        try:
            from core.emergency_snapshot import EmergencySnapshotEngine
            
            snapshot_engine = EmergencySnapshotEngine()
            snapshot_id = snapshot_engine.capture_snapshot(
                trigger_reason=f"Automated response to {threat_info.get('type')}"
            )
            
            return {
                'success': True,
                'snapshot_id': snapshot_id,
                'message': f'Evidence snapshot created: {snapshot_id}'
            }
        
        except Exception as e:
            return {
                'success': False,
                'reason': f'Snapshot failed: {str(e)}'
            }
    
    def _log_response(
        self, 
        action: ResponseAction, 
        threat_info: Dict[str, Any],
        result: Dict[str, Any]
    ):
        """Log response action"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action.value,
            'threat_info': threat_info,
            'result': result,
            'success': result.get('success', False)
        }
        
        self.response_log.append(log_entry)
        
        # Keep only last 1000 entries
        if len(self.response_log) > 1000:
            self.response_log = self.response_log[-1000:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get response engine statistics"""
        return {
            'total_responses': self.total_responses,
            'successful_responses': self.successful_responses,
            'failed_responses': self.failed_responses,
            'success_rate': (
                f"{(self.successful_responses / self.total_responses * 100) if self.total_responses > 0 else 0:.1f}%"
            ),
            'responses_by_action': self.responses_by_action,
            'auto_response_enabled': self.auto_response_enabled,
            'require_confirmation': self.require_confirmation
        }
    
    def get_recent_responses(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent response actions"""
        return self.response_log[-limit:]
    
    def restore_quarantined_file(self, quarantine_filename: str) -> Dict[str, Any]:
        """Restore a file from quarantine"""
        try:
            quarantine_path = self.quarantine_dir / quarantine_filename
            metadata_path = quarantine_path.with_suffix('.metadata.json')
            
            if not quarantine_path.exists():
                return {'success': False, 'reason': 'File not found in quarantine'}
            
            # Read metadata
            import json
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            original_path = metadata['original_path']
            
            # Restore file
            shutil.move(str(quarantine_path), original_path)
            metadata_path.unlink()
            
            return {
                'success': True,
                'restored_to': original_path,
                'message': f'File restored to {original_path}'
            }
        
        except Exception as e:
            return {'success': False, 'reason': str(e)}
