from modules.analyzer import MessageAnalyzer
from modules.normalizer import normalize_result
from modules.rules_engine import detect_suspicious_patterns
from modules.history_service import HistoryService

class AnalysisService:

    def __init__(self, api_key: str):
        self.analyzer = MessageAnalyzer(api_key)
        self.history = HistoryService()

    def analyze_message(self, content, msg_type, sender, subject=""):
        try:
            result = self.analyzer.analyze(content, msg_type, sender, subject)

            # 🔥 aplicar reglas adicionales
            rule_matches = detect_suspicious_patterns(content)

            if rule_matches and result.risk_score < 0.6:
                result.risk_score = 0.6
                result.explanation += " | Coincidencias con reglas locales."
                result.indicators.extend(rule_matches)

            normalized = normalize_result(result)

            # 🔥 guardar en historial
            self.history.save({
                "id": len(self.history.get_all()),
                "preview": content[:80],
                "data": normalized
            })

            return normalized

        except Exception as e:
            return {
                "error": True,
                "message": "No se pudo analizar el mensaje",
                "details": str(e)
            }