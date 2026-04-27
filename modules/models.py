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


class SenderType(str, Enum):
    LEGITIMATE = "legitimate"
    SPOOFED = "spoofed"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


@dataclass
class SenderAnalysis:
    """Resultado del análisis específico del remitente — H2"""

    sender: str
    is_suspicious: bool = False
    confidence: float = 0.0          # 0.0 (confiable) → 1.0 (muy sospechoso)
    sender_type: SenderType = SenderType.UNKNOWN
    reason: str = ""
    analyzed_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "sender": self.sender,
            "is_suspicious": self.is_suspicious,
            "confidence": round(self.confidence, 2),
            "sender_type": self.sender_type.value,
            "reason": self.reason,
            "analyzed_at": self.analyzed_at,
        }


@dataclass
class MessageResult:
    """Resultado del análisis de un mensaje"""

    # Datos del mensaje original
    content: str
    msg_type: str
    sender: str
    subject: str = ""

    # Resultado del análisis de contenido
    risk_level: RiskLevel = RiskLevel.SAFE
    risk_score: float = 0.0
    threat_category: ThreatCategory = ThreatCategory.NONE
    explanation: str = ""
    indicators: List[str] = field(default_factory=list)
    recommendation: str = ""

    # Análisis del remitente (H2)
    sender_analysis: Optional[SenderAnalysis] = None

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
                "sender_analysis": self.sender_analysis.to_dict() if self.sender_analysis else None,
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
