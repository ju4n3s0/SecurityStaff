"""
Módulo de modelos de datos para Shield
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List
from enum import Enum


class RiskLevel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"


class MessageType(str, Enum):
    SMS = "sms"
    EMAIL = "email"


class ThreatCategory(str, Enum):
    NONE = "none"
    PHISHING = "phishing"
    FRAUD = "fraud"
    SPAM = "spam"
    MALWARE = "malware"
    SOCIAL_ENGINEERING = "social_engineering"
    SCAM = "scam"
    UNKNOWN = "unknown"


@dataclass
class MessageResult:
    """Resultado del análisis de un mensaje"""

    # Datos del mensaje original
    content: str
    msg_type: str
    sender: str
    subject: str = ""

    # Resultado del análisis
    risk_level: RiskLevel = RiskLevel.SAFE
    risk_score: float = 0.0          # 0.0 (seguro) a 1.0 (muy peligroso)
    threat_category: ThreatCategory = ThreatCategory.NONE
    explanation: str = ""
    indicators: List[str] = field(default_factory=list)
    recommendation: str = ""

    # Metadata
    analyzed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    model_used: str = ""
    analysis_source: str = "gemini"

    def to_dict(self) -> dict:
        return {
            "message": {
                "content": self.content[:200] + "..." if len(self.content) > 200 else self.content,
                "type": self.msg_type,
                "sender": self.sender,
                "subject": self.subject,
            },
            "analysis": {
                "risk_level": self.risk_level.value,
                "risk_score": round(self.risk_score, 2),
                "threat_category": self.threat_category.value,
                "explanation": self.explanation,
                "indicators": self.indicators,
                "recommendation": self.recommendation,
            },
            "metadata": {
                "analyzed_at": self.analyzed_at,
                "model_used": self.model_used,
                "analysis_source": self.analysis_source,
            }
        }

    @property
    def is_safe(self) -> bool:
        return self.risk_level == RiskLevel.SAFE

    @property
    def is_dangerous(self) -> bool:
        return self.risk_level == RiskLevel.DANGEROUS
