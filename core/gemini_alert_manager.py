"""
Gemini Alert Manager
Intelligent alert triage and prioritization
"""

import google.generativeai as genai
import json
from datetime import datetime
from typing import Dict, Any

from utils.model_selector import model_selector


class GeminiAlertManager:
    """
    Use Gemini to intelligently triage and prioritize alerts
    Reduce false positives and alert fatigue
    """
    
    def __init__(self, api_key: str, model_name: str = 'gemini-2.5-flash'):
        """Use Flash model for fast real-time triage"""
        genai.configure(api_key=api_key)
        # Validate model or pick best fast/intelligent one
        self.model_name = model_selector.validate_model(model_name)
        self.model = genai.GenerativeModel(self.model_name)
    
    def triage_alert(self, alert: Dict[str, Any], system_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Intelligently triage and prioritize alert
        
        Args:
            alert: Alert details
            system_context: System and environmental context
        
        Returns:
            Triage decision with priority and actions
        """
        prompt = f"""
You are a SOC analyst triaging a security alert.

ALERT:
{json.dumps(alert, indent=2)}

SYSTEM CONTEXT:
{json.dumps(system_context, indent=2)}

TASK: Determine the true priority and required response.

Consider:
1. Is this a known false positive pattern?
2. What is the business impact if this is a real attack?
3. Are there related alerts that provide context?
4. Does this match known attack patterns?
5. What is the likelihood this is malicious vs. legitimate activity?
6. Time of day and user context
7. System criticality

Respond in JSON:
{{
  "priority": "P1_CRITICAL|P2_HIGH|P3_MEDIUM|P4_LOW|P5_INFO",
  "is_false_positive": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "Why you assigned this priority",
  "context": "Additional context that influenced decision",
  "recommended_response": {{
    "immediate_actions": ["list urgent actions"],
    "investigation_steps": ["list investigation tasks"],
    "escalation_required": true/false,
    "escalate_to": "tier_2|incident_response|management|none"
  }},
  "related_alerts": ["IDs of potentially related alerts"],
  "analyst_notes": "Key information for the responding analyst",
  "estimated_time_to_resolve": "time estimate",
  "business_impact": "CRITICAL|HIGH|MEDIUM|LOW|NONE"
}}

Be practical: avoid alert fatigue by correctly identifying false positives.
IMPORTANT: Respond ONLY with valid JSON.
"""
        
        try:
            response = self.model.generate_content(prompt)
            result = self._parse_json_response(response.text)
            result['triage_timestamp'] = datetime.now().isoformat()
            result['model_used'] = self.model_name
            return result
        except Exception as e:
            return self._error_response(f"Alert triage failed: {str(e)}")
    
    def explain_alert_to_user(self, alert: Dict[str, Any], user_level: str = 'technical') -> str:
        """
        Generate user-friendly alert explanation
        
        Args:
            alert: Alert details
            user_level: 'executive', 'technical', or 'end_user'
        
        Returns:
            User-appropriate explanation
        """
        prompt = f"""
Explain this security alert to a {user_level} user.

ALERT:
{json.dumps(alert, indent=2)}

USER LEVEL: {user_level}
- 'executive': C-level, needs business impact explanation
- 'technical': IT staff, needs technical details
- 'end_user': Non-technical employee, needs simple explanation

Provide clear explanation:
1. What happened (in appropriate language for user level)
2. Why it's concerning
3. What they should do (if anything)
4. What security team is doing

Keep it concise and actionable. Avoid unnecessary alarm for low-severity issues.
Use 3-5 sentences maximum.
"""
        
        try:
            response = self.model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            return f"Alert explanation failed: {str(e)}"
    
    def correlate_alerts(self, alerts: list) -> Dict[str, Any]:
        """
        Correlate multiple alerts to identify attack campaigns
        
        Args:
            alerts: List of recent alerts
        
        Returns:
            Correlation analysis
        """
        prompt = f"""
Analyze these alerts for correlation and potential attack campaigns.

ALERTS:
{json.dumps(alerts, indent=2)}

TASK: Identify if these alerts are related and part of a coordinated attack.

Look for:
1. Temporal correlation (alerts in sequence)
2. Common indicators (same user, system, IP)
3. Attack chain patterns (reconnaissance → access → lateral movement)
4. Similar TTPs across alerts

Respond in JSON:
{{
  "are_correlated": true/false,
  "confidence": 0.0-1.0,
  "correlation_type": "attack_chain|same_actor|unrelated|uncertain",
  "attack_campaign_detected": true/false,
  "campaign_description": "description if campaign detected",
  "alert_groups": [
    {{
      "group_id": "unique ID",
      "alerts": ["alert IDs in this group"],
      "relationship": "how they're related",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW"
    }}
  ],
  "recommended_action": "treat_as_campaign|investigate_separately|monitor",
  "analysis": "detailed correlation analysis"
}}

IMPORTANT: Respond ONLY with valid JSON.
"""
        
        try:
            response = self.model.generate_content(prompt)
            result = self._parse_json_response(response.text)
            result['correlation_timestamp'] = datetime.now().isoformat()
            return result
        except Exception as e:
            return self._error_response(f"Alert correlation failed: {str(e)}")
    
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
            'triage_timestamp': datetime.now().isoformat()
        }
