"""
Pydantic Validation Schemas for ShadowNet Nexus
Ensures structured, validated outputs from Gemini API
"""

from pydantic import BaseModel, Field, validator, ValidationError
from typing import List, Optional, Literal
from enum import Enum


class SeverityLevel(str, Enum):
    """Severity levels for threats"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    BENIGN = "BENIGN"


class CategoryType(str, Enum):
    """Threat categories"""
    LOG_CLEARING = "log_clearing"
    EVIDENCE_DESTRUCTION = "evidence_destruction"
    TIMESTOMPING = "timestomping"
    SECURE_DELETION = "secure_deletion"
    VSS_DELETION = "vss_deletion"
    REGISTRY_MANIPULATION = "registry_manipulation"
    NONE = "none"


class RecommendedAction(str, Enum):
    """Recommended actions"""
    PRESERVE_EVIDENCE = "preserve_evidence"
    MONITOR = "monitor"
    IGNORE = "ignore"
    ESCALATE = "escalate"


class CommandAnalysisResponse(BaseModel):
    """Validated schema for command analysis"""
    is_anti_forensics: bool
    confidence: float = Field(ge=0.0, le=1.0, description="Must be between 0 and 1")
    category: CategoryType
    severity: SeverityLevel
    explanation: str = Field(min_length=10, max_length=500)
    threat_indicators: List[str] = Field(max_items=10)
    recommended_action: RecommendedAction
    likely_threat_actor: str = Field(max_length=100)
    mitre_attack_ttps: List[str] = Field(default_factory=list, max_items=10)
    context_notes: str = Field(default="", max_length=500)
    
    @validator('confidence')
    def validate_confidence(cls, v):
        if not 0.0 <= v <= 1.0:
            raise ValueError('Confidence must be between 0.0 and 1.0')
        return round(v, 2)  # Round to 2 decimal places
    
    @validator('explanation')
    def validate_explanation(cls, v):
        if len(v.split()) < 5:
            raise ValueError('Explanation too brief - minimum 5 words')
        return v
    
    @validator('likely_threat_actor')
    def validate_actor_name(cls, v):
        """Prevent hallucinated actor names"""
        known_actors = [
            "LockBit 3.0", "BlackCat", "ALPHV", "Conti", "REvil", 
            "DarkSide", "APT29", "APT28", "Lazarus", "APT41",
            "Royal", "BlackBasta", "Akira", "Play", "Unknown",
            "Insufficient Data"
        ]
        
        # Check if it's a known actor
        if v not in known_actors:
            # Allow but flag unknown actors
            v = f"{v} (UNVERIFIED)"
        
        return v
    
    class Config:
        use_enum_values = True


class ThreatAttribution(BaseModel):
    """Validated schema for threat actor attribution"""
    threat_actor: str = Field(max_length=100)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: List[str] = Field(min_items=1, max_items=20)
    matching_campaigns: List[str] = Field(default_factory=list, max_items=10)
    ttp_match_score: float = Field(default=0.0, ge=0.0, le=1.0)
    
    @validator('threat_actor')
    def validate_actor_name(cls, v):
        """Prevent hallucinated actor names"""
        known_actors = [
            "LockBit 3.0", "BlackCat", "ALPHV", "Conti", "REvil", 
            "DarkSide", "APT29", "APT28", "Lazarus", "APT41",
            "Royal", "BlackBasta", "Akira", "Play", "Unknown",
            "Insufficient Data"
        ]
        
        if v not in known_actors:
            v = f"{v} (UNVERIFIED)"
        
        return v
    
    @validator('confidence')
    def validate_confidence_with_evidence(cls, v, values):
        """Lower confidence if insufficient evidence"""
        evidence_count = len(values.get('evidence', []))
        
        if evidence_count < 3 and v > 0.7:
            raise ValueError(
                f'Confidence {v} too high with only {evidence_count} pieces of evidence'
            )
        
        return round(v, 2)


class AttributionResponse(BaseModel):
    """Full attribution response with uncertainty controls"""
    primary_attribution: ThreatAttribution
    alternative_attributions: List[ThreatAttribution] = Field(default_factory=list, max_items=5)
    confidence_reasoning: str = Field(min_length=50, max_length=1000)
    uncertainty_factors: List[str] = Field(default_factory=list)
    recommended_next_steps: List[str] = Field(default_factory=list, max_items=10)
    
    @validator('primary_attribution')
    def validate_primary_confidence(cls, v):
        """Require reasonable confidence for primary attribution"""
        if v.confidence < 0.5:
            raise ValueError('Primary attribution must have confidence >= 0.5')
        return v


class DecisionAuthority(str, Enum):
    """Who makes the final decision"""
    AI_AUTONOMOUS = "ai_autonomous"      # AI decides (low stakes)
    AI_ADVISORY = "ai_advisory"          # AI suggests, human decides (medium stakes)
    HUMAN_REQUIRED = "human_required"    # Human must decide (high stakes)


class ActionConfidenceLevel(str, Enum):
    """How confident are we in taking action"""
    HIGH = "high"           # >0.85 confidence
    MEDIUM = "medium"       # 0.60-0.85 confidence
    LOW = "low"             # 0.40-0.60 confidence
    UNCERTAIN = "uncertain" # <0.40 confidence
