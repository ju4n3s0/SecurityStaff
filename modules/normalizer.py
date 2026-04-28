from modules.models import MessageResult

def normalize_result(result: MessageResult) -> dict:
    """
    Convierte el resultado interno al formato estándar requerido por las HU
    """

    mapping = {
        "safe": "bajo",
        "suspicious": "medio",
        "dangerous": "alto"
    }

    return {
        "riskLevel": mapping.get(result.risk_level.value, "medio"),
        "reason": result.explanation,
        "source": result.msg_type,
        "timestamp": result.analyzed_at,
        "score": result.risk_score,
        "category": result.threat_category.value,
        "indicators": result.indicators,
        "recommendation": result.recommendation
    }