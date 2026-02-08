"""
Gemini Timeline Reconstructor
Reconstruct attack timelines from fragmented evidence
"""

import google.generativeai as genai
import json
from datetime import datetime
from typing import Dict, Any, List

from utils.model_selector import model_selector


class GeminiTimelineReconstructor:
    """
    Use Gemini to fill gaps in attack timeline using logical reasoning
    Infer deleted or tampered evidence
    """
    
    def __init__(self, api_key: str, model_name: str = 'gemini-2.5-flash'):
        """Use Pro model for complex reasoning"""
        genai.configure(api_key=api_key)
        # Validate model or pick best intelligent one
        self.model_name = model_selector.validate_model(model_name)
        self.model = genai.GenerativeModel(self.model_name)
    
    def reconstruct_timeline(self, evidence_fragments: List[Dict], 
                           known_gaps: List[Dict]) -> Dict[str, Any]:
        """
        Reconstruct complete attack timeline from fragments
        
        Args:
            evidence_fragments: Available evidence pieces
            known_gaps: Known gaps in timeline (deleted evidence)
        
        Returns:
            Reconstructed timeline with inferred events
        """
        prompt = f"""
You are reconstructing a cyberattack timeline from fragmented evidence.

AVAILABLE EVIDENCE:
{json.dumps(evidence_fragments, indent=2)}

KNOWN GAPS (deleted or tampered evidence):
{json.dumps(known_gaps, indent=2)}

TASK: Reconstruct the most likely complete attack timeline.

Use logical reasoning:
1. What MUST have happened before event A for event B to occur?
2. What evidence should exist but is missing? (likely deleted by attacker)
3. What is the typical sequence for this type of attack?
4. What can be inferred from artifacts that survived deletion?
5. What are the causal dependencies between events?

Provide:
{{
  "reconstructed_timeline": [
    {{
      "timestamp": "estimated or known",
      "event": "description",
      "confidence": 0.0-1.0,
      "evidence_type": "direct_evidence|inferred|reconstructed",
      "reasoning": "Why you believe this event occurred",
      "supporting_evidence": ["what supports this inference"]
    }}
  ],
  "inferred_deleted_events": [
    {{
      "event": "What was likely deleted",
      "evidence": "What artifacts suggest this happened",
      "deletion_method": "How attacker likely removed this evidence",
      "confidence": 0.0-1.0
    }}
  ],
  "attack_narrative": "Coherent story of the complete attack sequence",
  "confidence_overall": 0.0-1.0,
  "alternative_scenarios": ["Other possible explanations if confidence is low"],
  "critical_missing_evidence": ["What evidence would confirm/refute this timeline"]
}}

Think like a forensic investigator: piece together the story from fragments.
IMPORTANT: Respond ONLY with valid JSON.
"""
        
        try:
            response = self.model.generate_content(prompt)
            result = self._parse_json_response(response.text)
            result['reconstruction_timestamp'] = datetime.now().isoformat()
            result['model_used'] = self.model_name
            return result
        except Exception as e:
            return self._error_response(f"Timeline reconstruction failed: {str(e)}")
    
    def validate_timeline_consistency(self, timeline: List[Dict]) -> Dict[str, Any]:
        """
        Check reconstructed timeline for logical inconsistencies
        
        Args:
            timeline: Reconstructed timeline to validate
        
        Returns:
            Validation results with identified issues
        """
        prompt = f"""
Review this reconstructed attack timeline for logical inconsistencies or causality violations.

TIMELINE:
{json.dumps(timeline, indent=2)}

Check for:
1. Causality violations (effect before cause)
2. Impossible time gaps (events too close/far apart)
3. Missing prerequisite events
4. Conflicting evidence from different sources
5. Physical impossibilities (file accessed before creation)
6. Logical contradictions

Respond in JSON:
{{
  "is_consistent": true/false,
  "violations": [
    {{
      "type": "causality|timing|logic|contradiction",
      "events_involved": ["event IDs or descriptions"],
      "description": "What's wrong",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW"
    }}
  ],
  "confidence_in_timeline": 0.0-1.0,
  "suggested_corrections": [
    "How to fix identified issues"
  ],
  "overall_assessment": "Is this timeline plausible?"
}}

IMPORTANT: Respond ONLY with valid JSON.
"""
        
        try:
            response = self.model.generate_content(prompt)
            result = self._parse_json_response(response.text)
            result['validation_timestamp'] = datetime.now().isoformat()
            return result
        except Exception as e:
            return self._error_response(f"Timeline validation failed: {str(e)}")
    
    def identify_anti_forensics_gaps(self, timeline: List[Dict]) -> Dict[str, Any]:
        """
        Identify gaps that indicate anti-forensics activity
        
        Args:
            timeline: Attack timeline
        
        Returns:
            Analysis of anti-forensics gaps
        """
        prompt = f"""
Analyze this timeline for gaps that indicate anti-forensics activity.

TIMELINE:
{json.dumps(timeline, indent=2)}

TASK: Identify suspicious gaps or missing evidence that suggests deliberate evidence destruction.

Look for:
1. Gaps during critical attack phases (credential theft, lateral movement)
2. Missing logs that should exist
3. Timestamp anomalies (timestomping)
4. Evidence of log clearing commands followed by gaps
5. Patterns consistent with anti-forensics tools

Respond in JSON:
{{
  "anti_forensics_detected": true/false,
  "confidence": 0.0-1.0,
  "suspicious_gaps": [
    {{
      "time_range": "when gap occurs",
      "missing_evidence": "what should be there",
      "likely_deletion_method": "how it was removed",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW"
    }}
  ],
  "anti_forensics_techniques": ["identified techniques"],
  "analysis": "Overall assessment of evidence tampering",
  "recovery_recommendations": ["how to potentially recover deleted evidence"]
}}

IMPORTANT: Respond ONLY with valid JSON.
"""
        
        try:
            response = self.model.generate_content(prompt)
            result = self._parse_json_response(response.text)
            result['analysis_timestamp'] = datetime.now().isoformat()
            return result
        except Exception as e:
            return self._error_response(f"Gap analysis failed: {str(e)}")
    
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
            'reconstruction_timestamp': datetime.now().isoformat()
        }
