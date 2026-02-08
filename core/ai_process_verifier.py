"""
AI-Powered Process Path Verification
Uses Gemini AI to intelligently verify if a process path is legitimate
"""

import os
from typing import Dict, Any, Optional
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

class AIProcessVerifier:
    """
    AI-powered process verification using Gemini
    Verifies if a process path is legitimate based on:
    - Process name
    - Execution path
    - Parent process
    - System context
    """
    
    VERIFICATION_PROMPT = """You are a cybersecurity expert analyzing process execution paths for legitimacy.

TASK: Determine if this process execution is LEGITIMATE or SUSPICIOUS.

PROCESS INFORMATION:
- Process Name: {process_name}
- Execution Path: {process_path}
- Parent Process: {parent_name}
- Parent Path: {parent_path}

ANALYSIS CRITERIA:

1. LEGITIMATE SYSTEM PROCESSES:
   - Windows system processes (svchost.exe, services.exe, lsass.exe, etc.) MUST be in:
     * C:\\Windows\\System32\\
     * C:\\Windows\\SysWOW64\\
   - If a system process is ANYWHERE else, it's MASQUERADING MALWARE

2. LEGITIMATE APPLICATION PATHS:
   - Browsers (chrome.exe, firefox.exe, msedge.exe) should be in:
     * C:\\Program Files\\
     * C:\\Program Files (x86)\\
     * C:\\Users\\[user]\\AppData\\Local\\[vendor]\\
   
   - Development tools (python.exe, node.exe, code.exe) can be in:
     * C:\\Program Files\\
     * C:\\Users\\[user]\\AppData\\
     * C:\\Python\\
     * C:\\[tool-name]\\
   
   - User applications should be in:
     * C:\\Program Files\\
     * C:\\Program Files (x86)\\
     * C:\\Users\\[user]\\AppData\\

3. SUSPICIOUS LOCATIONS (ALWAYS FLAG):
   - C:\\Users\\[user]\\Downloads\\
   - C:\\Users\\[user]\\Desktop\\
   - C:\\Temp\\
   - C:\\Windows\\Temp\\
   - C:\\ProgramData\\ (unless specific known apps)
   - Removable drives (D:\\, E:\\, etc.) for system processes

4. PARENT PROCESS VERIFICATION:
   - svchost.exe parent MUST be services.exe
   - services.exe parent MUST be wininit.exe
   - User applications typically have explorer.exe as parent
   - Suspicious if system process has cmd.exe or powershell.exe as parent

5. MASQUERADING DETECTION:
   - Process name matches system process BUT path is wrong → MASQUERADING
   - Process name matches browser BUT path is wrong → MASQUERADING
   - Example: "svchost.exe" in C:\\Users\\Downloads\\ → DEFINITELY MALWARE

RESPONSE FORMAT (JSON):
{{
    "is_legitimate": true/false,
    "confidence": 0.0-1.0,
    "reason": "Brief explanation",
    "threat_level": "SAFE/LOW/MEDIUM/HIGH/CRITICAL",
    "indicators": ["list", "of", "suspicious", "indicators"]
}}

IMPORTANT:
- Be STRICT with system processes (svchost.exe, lsass.exe, etc.)
- Be FLEXIBLE with development tools (python.exe, node.exe, etc.)
- ALWAYS flag if process name suggests system process but path is wrong
- Consider parent process relationships
- Flag unusual parent-child relationships

Analyze this process and respond ONLY with valid JSON:
"""

    def __init__(self, api_key: Optional[str] = None):
        """Initialize AI Process Verifier"""
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not found")
        
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-2.5-flash')
    
    def verify_process_path(
        self,
        process_name: str,
        process_path: str,
        parent_name: str = "Unknown",
        parent_path: str = "Unknown"
    ) -> Dict[str, Any]:
        """
        Use AI to verify if a process path is legitimate
        
        Args:
            process_name: Name of the process (e.g., "svchost.exe")
            process_path: Full path to executable (e.g., "C:\\Windows\\System32\\svchost.exe")
            parent_name: Name of parent process
            parent_path: Path of parent process
        
        Returns:
            Dictionary with verification results:
            {
                'is_legitimate': bool,
                'confidence': float,
                'reason': str,
                'threat_level': str,
                'indicators': list
            }
        """
        try:
            # Build prompt
            prompt = self.VERIFICATION_PROMPT.format(
                process_name=process_name,
                process_path=process_path,
                parent_name=parent_name,
                parent_path=parent_path
            )
            
            # Get AI analysis
            response = self.model.generate_content(prompt)
            
            # Parse JSON response
            import json
            import re
            
            # Extract JSON from response
            response_text = response.text.strip()
            
            # Remove markdown code blocks if present
            response_text = re.sub(r'```json\s*', '', response_text)
            response_text = re.sub(r'```\s*', '', response_text)
            
            # Parse JSON
            result = json.loads(response_text)
            
            # Validate required fields
            required_fields = ['is_legitimate', 'confidence', 'reason', 'threat_level']
            if not all(field in result for field in required_fields):
                raise ValueError("AI response missing required fields")
            
            return result
            
        except Exception as e:
            # Fallback to conservative approach if AI fails
            print(f"⚠️  AI verification failed: {e}")
            
            # Use basic heuristics as fallback
            return self._fallback_verification(process_name, process_path, parent_name)
    
    def _fallback_verification(
        self,
        process_name: str,
        process_path: str,
        parent_name: str
    ) -> Dict[str, Any]:
        """
        Fallback verification using basic heuristics if AI fails
        """
        process_path_lower = process_path.lower()
        process_name_lower = process_name.lower()
        
        # Critical system processes
        critical_processes = ['svchost.exe', 'lsass.exe', 'services.exe', 'csrss.exe']
        
        if process_name_lower in critical_processes:
            # System processes MUST be in System32
            if 'system32' in process_path_lower or 'syswow64' in process_path_lower:
                return {
                    'is_legitimate': True,
                    'confidence': 0.95,
                    'reason': f'System process {process_name} in correct location',
                    'threat_level': 'SAFE',
                    'indicators': []
                }
            else:
                return {
                    'is_legitimate': False,
                    'confidence': 0.99,
                    'reason': f'MASQUERADING: {process_name} not in System32',
                    'threat_level': 'CRITICAL',
                    'indicators': ['System process in wrong location', 'Likely masquerading malware']
                }
        
        # Suspicious locations
        suspicious_locations = ['downloads', 'desktop', 'temp', '\\temp\\']
        if any(loc in process_path_lower for loc in suspicious_locations):
            return {
                'is_legitimate': False,
                'confidence': 0.85,
                'reason': f'Process running from suspicious location: {process_path}',
                'threat_level': 'HIGH',
                'indicators': ['Suspicious execution path']
            }
        
        # Default: allow but with low confidence
        return {
            'is_legitimate': True,
            'confidence': 0.5,
            'reason': 'Unable to verify with AI, allowing with caution',
            'threat_level': 'LOW',
            'indicators': ['AI verification unavailable']
        }


# Example usage
if __name__ == "__main__":
    verifier = AIProcessVerifier()
    
    # Test cases
    test_cases = [
        {
            'name': 'Legitimate svchost.exe',
            'process_name': 'svchost.exe',
            'process_path': 'C:\\Windows\\System32\\svchost.exe',
            'parent_name': 'services.exe',
            'parent_path': 'C:\\Windows\\System32\\services.exe'
        },
        {
            'name': 'MALWARE masquerading as svchost.exe',
            'process_name': 'svchost.exe',
            'process_path': 'C:\\Users\\Hacker\\Downloads\\svchost.exe',
            'parent_name': 'cmd.exe',
            'parent_path': 'C:\\Windows\\System32\\cmd.exe'
        },
        {
            'name': 'Legitimate Chrome',
            'process_name': 'chrome.exe',
            'process_path': 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            'parent_name': 'explorer.exe',
            'parent_path': 'C:\\Windows\\explorer.exe'
        },
        {
            'name': 'Fake Chrome (C2 malware)',
            'process_name': 'chrome.exe',
            'process_path': 'C:\\Temp\\chrome.exe',
            'parent_name': 'powershell.exe',
            'parent_path': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
        }
    ]
    
    print("\n" + "="*80)
    print("🤖 AI-POWERED PROCESS PATH VERIFICATION TEST")
    print("="*80)
    
    for test in test_cases:
        print(f"\n📋 Test: {test['name']}")
        print(f"   Process: {test['process_name']}")
        print(f"   Path: {test['process_path']}")
        print(f"   Parent: {test['parent_name']}")
        
        result = verifier.verify_process_path(
            test['process_name'],
            test['process_path'],
            test['parent_name'],
            test['parent_path']
        )
        
        status = "✅ LEGITIMATE" if result['is_legitimate'] else "🚨 SUSPICIOUS"
        print(f"\n   {status}")
        print(f"   Confidence: {result['confidence']:.0%}")
        print(f"   Threat Level: {result['threat_level']}")
        print(f"   Reason: {result['reason']}")
        if result.get('indicators'):
            print(f"   Indicators: {', '.join(result['indicators'])}")
        print("-" * 80)
    
    print("\n✅ AI-POWERED VERIFICATION TEST COMPLETE\n")
