"""
Gemini Threat Attributor
Attribute attacks to specific threat actors using TTPs and behavior analysis
"""

import google.generativeai as genai
import json
from datetime import datetime
from typing import Dict, Any, List

from utils.model_selector import model_selector


class GeminiThreatAttributor:
    """
    Use Gemini to attribute attacks to threat actors based on TTPs and behavior
    No need for threat intelligence databases - Gemini knows them all
    """
    
    def __init__(self, api_key: str, model_name: str = 'gemini-2.5-flash'):
        """Use Pro model for complex reasoning required in attribution"""
        genai.configure(api_key=api_key)
        # Validate model or pick best intelligent one
        self.model_name = model_selector.validate_model(model_name)
        self.model = genai.GenerativeModel(self.model_name)
    
    def attribute_attack(self, attack_timeline: List[Dict], observed_ttps: List[str], 
                        artifacts: List[str]) -> Dict[str, Any]:
        """
        Attribute attack to threat actor
        
        Args:
            attack_timeline: Chronological list of attack events
            observed_ttps: List of observed TTPs (MITRE ATT&CK IDs or descriptions)
            artifacts: List of collected artifacts (tools, files, IOCs)
        
        Returns:
            Attribution analysis with confidence scores
        """
        prompt = f"""
You are a threat intelligence analyst. Attribute this cyberattack to a specific threat actor or ransomware group.

ATTACK TIMELINE:
{json.dumps(attack_timeline, indent=2)}

OBSERVED TTPs (Tactics, Techniques, Procedures):
{json.dumps(observed_ttps, indent=2)}

ARTIFACTS COLLECTED:
{json.dumps(artifacts, indent=2)}

TASK: Determine which threat actor is most likely responsible.

Consider:
1. Unique TTP combinations (some TTPs are signatures of specific groups)
2. Tool preferences (specific ransomware uses specific tools)
3. Timing patterns (some groups have characteristic dwell times)
4. Target selection (industry, geography, company size)
5. Anti-forensics techniques used
6. Command syntax and style
7. Infrastructure patterns

Known Threat Actors to Consider:
- LockBit 3.0: VSS deletion, log clearing, PsExec lateral movement, fast encryption
- BlackCat/ALPHV: Rust-based, intermittent encryption, legitimate tools
- Conti: Cobalt Strike, Mimikatz, aggressive lateral movement
- APT29 (Cozy Bear): Stealthy, long dwell time, sophisticated evasion
- APT28 (Fancy Bear): Credential theft, phishing, military targets
- Lazarus Group: Financial motivation, SWIFT attacks, destructive malware
- REvil/Sodinokibi: Double extortion, auction model
- Ryuk: Targeted, manual deployment, high ransom demands

Respond in JSON:
{{
  "primary_attribution": {{
    "threat_actor": "LockBit 3.0|BlackCat|Conti|APT29|etc.",
    "confidence": 0.0-1.0,
    "evidence": [
      "Specific TTPs that match",
      "Unique indicators",
      "Tool usage patterns"
    ],
    "matching_campaigns": ["Previous similar attacks by this actor"]
  }},
  "alternative_attributions": [
    {{
      "threat_actor": "name",
      "confidence": 0.0-1.0,
      "reasoning": "Why this is possible but less likely"
    }}
  ],
  "threat_actor_profile": {{
    "category": "ransomware|apt|cybercrime|nation_state|hacktivism",
    "sophistication": "low|medium|high|advanced",
    "typical_targets": ["industry sectors"],
    "active_since": "approximate timeframe",
    "known_aliases": ["other names"],
    "motivation": "financial|espionage|destruction|political"
  }},
  "confidence_reasoning": "Detailed explanation of attribution logic",
  "recommended_next_steps": [
    "Investigation actions based on this attribution"
  ],
  "iocs_to_search": {{
    "file_hashes": ["known hashes from this actor"],
    "ip_ranges": ["known infrastructure"],
    "domains": ["known C2 domains"],
    "tools": ["signature tools"]
  }}
}}

Be specific and cite evidence for your attribution.
IMPORTANT: Respond ONLY with valid JSON.
"""
        
        try:
            response = self.model.generate_content(prompt)
            result = self._parse_json_response(response.text)
            result['attribution_timestamp'] = datetime.now().isoformat()
            result['model_used'] = self.model_name
            return result
        except Exception as e:
            return self._error_response(f"Attribution failed: {str(e)}")
    
    def enrich_with_threat_intel(self, threat_actor: str) -> Dict[str, Any]:
        """
        Get latest threat intelligence about attributed actor
        
        Args:
            threat_actor: Name of threat actor
        
        Returns:
            Threat intelligence brief
        """
        prompt = f"""
Provide the latest threat intelligence summary for: {threat_actor}

Include:
1. Recent campaigns (last 6 months)
2. New TTPs or tool updates
3. Current infrastructure (IP ranges, domains if known)
4. Ransom demands and payment patterns (if ransomware)
5. Notable victims
6. Any changes in behavior or tactics
7. Recommended detection strategies
8. Recommended mitigation strategies

Format as a structured threat intelligence brief.
Respond in JSON:
{{
  "threat_actor": "{threat_actor}",
  "last_updated": "timeframe of intelligence",
  "recent_campaigns": ["list of recent attacks"],
  "new_ttps": ["any new techniques"],
  "current_infrastructure": {{
    "ip_ranges": ["known ranges"],
    "domains": ["known domains"],
    "tools": ["current toolset"]
  }},
  "ransom_info": {{
    "typical_demand": "amount range",
    "payment_method": "cryptocurrency type",
    "negotiation_behavior": "description"
  }},
  "notable_victims": ["recent high-profile victims"],
  "behavior_changes": "any tactical shifts",
  "detection_strategies": ["how to detect this actor"],
  "mitigation_strategies": ["how to defend against this actor"],
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "intelligence_summary": "comprehensive overview"
}}

IMPORTANT: Respond ONLY with valid JSON.
"""
        
        try:
            response = self.model.generate_content(prompt)
            result = self._parse_json_response(response.text)
            result['intel_timestamp'] = datetime.now().isoformat()
            return result
        except Exception as e:
            return self._error_response(f"Threat intel enrichment failed: {str(e)}")
    
    def compare_with_known_campaigns(self, current_attack: Dict, threat_actor: str) -> Dict[str, Any]:
        """
        Compare current attack with known campaigns from attributed actor
        
        Args:
            current_attack: Current attack details
            threat_actor: Attributed threat actor
        
        Returns:
            Comparison analysis
        """
        prompt = f"""
Compare this current attack with known campaigns from {threat_actor}.

CURRENT ATTACK:
{json.dumps(current_attack, indent=2)}

ATTRIBUTED THREAT ACTOR: {threat_actor}

TASK: Analyze similarities and differences with known campaigns.

Respond in JSON:
{{
  "similarity_score": 0.0-1.0,
  "matching_characteristics": ["what matches known campaigns"],
  "deviations": ["what's different from typical behavior"],
  "is_typical_for_actor": true/false,
  "possible_explanations": ["why there might be differences"],
  "confidence_in_attribution": 0.0-1.0,
  "analysis": "detailed comparison"
}}

IMPORTANT: Respond ONLY with valid JSON.
"""
        
        try:
            response = self.model.generate_content(prompt)
            result = self._parse_json_response(response.text)
            result['comparison_timestamp'] = datetime.now().isoformat()
            return result
        except Exception as e:
            return self._error_response(f"Campaign comparison failed: {str(e)}")
    
    def _parse_json_response(self, response_text: str) -> Dict[str, Any]:
        """Parse JSON from Gemini response"""
        response_text = response_text.strip()
        
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
            return {
                'error': 'JSON parsing failed',
                'raw_response': response_text[:500]
            }
    
    def _error_response(self, error_message: str) -> Dict[str, Any]:
        """Generate standardized error response"""
        return {
            'error': error_message,
            'confidence': 0.0,
            'attribution_timestamp': datetime.now().isoformat()
        }
