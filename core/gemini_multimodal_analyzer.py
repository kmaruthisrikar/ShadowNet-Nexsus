"""
Gemini Multimodal Analyzer
Analyze screenshots, memory dumps, network traffic visualizations
"""

import google.generativeai as genai
import json
from datetime import datetime
from typing import Dict, Any, Optional
import PIL.Image

from utils.model_selector import model_selector


class GeminiMultimodalAnalyzer:
    """
    Gemini's Superpower: Analyze visual evidence (screenshots, graphs, images)
    """
    
    def __init__(self, api_key: str, model_name: str = 'gemini-2.5-flash'):
        """
        Initialize Multimodal Analyzer (use Pro for complex visual analysis)
        """
        genai.configure(api_key=api_key)
        # Validate model or pick best intelligent one
        self.model_name = model_selector.validate_model(model_name)
        self.model = genai.GenerativeModel(self.model_name)
    
    def analyze_screenshot(self, screenshot_path: str) -> Dict[str, Any]:
        """
        Analyze screenshot of attacker's desktop/terminal
        
        Args:
            screenshot_path: Path to screenshot image
        
        Returns:
            Analysis of visible threats and activities
        """
        try:
            img = PIL.Image.open(screenshot_path)
            
            prompt = """
Analyze this screenshot for evidence of anti-forensics or malicious activity.

Look for:
1. Command prompts or terminals running suspicious commands
2. Anti-forensics tools visible in taskbar or windows
3. File deletion/wiping utilities
4. Evidence of credential theft tools (mimikatz, procdump, etc.)
5. Ransomware payment screens or encryption tools
6. Any visible indicators of compromise
7. Suspicious PowerShell commands
8. Evidence tampering tools

Respond in JSON format:
{
  "threats_detected": true/false,
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW|NONE",
  "visible_tools": ["list of tools/applications seen"],
  "suspicious_commands": ["any visible commands"],
  "indicators_of_compromise": ["specific IOCs visible"],
  "analysis_summary": "What you see and why it's concerning",
  "recommended_actions": ["immediate steps to take"],
  "confidence": 0.0-1.0
}

IMPORTANT: Respond ONLY with valid JSON.
"""
            
            response = self.model.generate_content([prompt, img])
            result = self._parse_json_response(response.text)
            result['screenshot_path'] = screenshot_path
            result['analysis_timestamp'] = datetime.now().isoformat()
            
            return result
            
        except Exception as e:
            return self._error_response(f"Screenshot analysis failed: {str(e)}")
    
    def analyze_memory_dump_text(self, memory_strings: str, process_list: str) -> Dict[str, Any]:
        """
        Analyze text extracted from memory dump
        
        Args:
            memory_strings: Extracted strings from memory
            process_list: List of running processes
        
        Returns:
            Analysis of memory artifacts
        """
        prompt = f"""
You are analyzing a Windows memory dump for anti-forensics activity.

RUNNING PROCESSES:
{process_list}

EXTRACTED STRINGS (partial):
{memory_strings[:5000]}

TASK: Identify evidence of anti-forensics tools or techniques.

Look for:
1. Anti-forensics tool names (BleachBit, CCleaner, Eraser, timestomp, etc.)
2. Suspicious PowerShell commands in memory
3. Evidence of log clearing utilities
4. Credential dumping tools (mimikatz, procdump, dumpert)
5. Signs of memory manipulation or hiding
6. Ransomware indicators
7. Lateral movement tools (PsExec, WMI)

Respond in JSON:
{{
  "anti_forensics_detected": true/false,
  "tools_found": ["list of tools"],
  "suspicious_processes": ["list with PIDs"],
  "memory_artifacts": ["specific findings"],
  "confidence": 0.0-1.0,
  "analysis_summary": "What you found",
  "threat_assessment": "CRITICAL|HIGH|MEDIUM|LOW",
  "next_steps": ["recommended investigation actions"],
  "mitre_attack_ttps": ["T1003", "T1070"]
}}

IMPORTANT: Respond ONLY with valid JSON.
"""
        
        try:
            response = self.model.generate_content(prompt)
            result = self._parse_json_response(response.text)
            result['analysis_timestamp'] = datetime.now().isoformat()
            return result
        except Exception as e:
            return self._error_response(f"Memory analysis failed: {str(e)}")
    
    def analyze_network_traffic_graph(self, traffic_graph_path: str) -> Dict[str, Any]:
        """
        Analyze visualization of network traffic patterns
        
        Args:
            traffic_graph_path: Path to network traffic graph image
        
        Returns:
            Analysis of network patterns
        """
        try:
            img = PIL.Image.open(traffic_graph_path)
            
            prompt = """
This is a network traffic visualization graph.

Identify suspicious patterns that might indicate:
1. Data exfiltration (large outbound transfers)
2. Command and Control (C2) beaconing (regular intervals)
3. Lateral movement (unusual internal connections)
4. Anti-forensics: attempts to clear network logs or hide traffic
5. Port scanning or reconnaissance
6. Unusual protocols or destinations

Respond in JSON:
{
  "suspicious_patterns": true/false,
  "pattern_types": ["exfiltration", "c2_beaconing", "lateral_movement"],
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "analysis": "Detailed description of patterns",
  "suspicious_connections": [
    {
      "source": "IP or host",
      "destination": "IP or host",
      "pattern": "description",
      "risk_level": "HIGH|MEDIUM|LOW"
    }
  ],
  "recommended_actions": ["investigation steps"],
  "confidence": 0.0-1.0
}

IMPORTANT: Respond ONLY with valid JSON.
"""
            
            response = self.model.generate_content([prompt, img])
            result = self._parse_json_response(response.text)
            result['graph_path'] = traffic_graph_path
            result['analysis_timestamp'] = datetime.now().isoformat()
            
            return result
            
        except Exception as e:
            return self._error_response(f"Network graph analysis failed: {str(e)}")
    
    def _parse_json_response(self, response_text: str) -> Dict[str, Any]:
        """Parse JSON from Gemini response, handling markdown code blocks"""
        response_text = response_text.strip()
        
        # Remove markdown code blocks
        if response_text.startswith('```json'):
            response_text = response_text[7:]
        if response_text.startswith('```'):
            response_text = response_text[3:]
        if response_text.endswith('```'):
            response_text = response_text[:-3]
        
        response_text = response_text.strip()
        
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            # Return structured error
            return {
                'error': 'JSON parsing failed',
                'raw_response': response_text[:500],
                'threats_detected': False,
                'confidence': 0.0
            }
    
    def _error_response(self, error_message: str) -> Dict[str, Any]:
        """Generate standardized error response"""
        return {
            'error': error_message,
            'threats_detected': False,
            'confidence': 0.0,
            'analysis_timestamp': datetime.now().isoformat(),
            'model_used': self.model_name
        }
