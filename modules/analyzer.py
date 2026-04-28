"""
Módulo de análisis de mensajes con Gemini API (VERSIÓN ROBUSTA)
"""

import json
import logging
import re
import google.generativeai as genai
from modules.models import MessageResult, RiskLevel, ThreatCategory

logger = logging.getLogger(__name__)


ANALYSIS_PROMPT = """
Responde ÚNICAMENTE con JSON válido. NO uses markdown, NO agregues texto extra.

Formato EXACTO:
{{
  "risk_level": "safe" | "suspicious" | "dangerous",
  "risk_score": número entre 0.0 y 1.0,
  "threat_category": "phishing" | "fraud" | "spam" | "malware" | "social_engineering" | "scam" | "none",
  "explanation": "explicación corta",
  "indicators": ["indicador1", "indicador2"],
  "recommendation": "acción recomendada"
}}

Mensaje:
TIPO: {msg_type}
REMITENTE: {sender}
{subject_line}
CONTENIDO:
{content}
"""


class MessageAnalyzer:
    MODEL_NAME = "gemini-2.5-flash"

    VALID_RISK_LEVELS = {"safe", "suspicious", "dangerous"}
    VALID_CATEGORIES = {
        "none", "phishing", "fraud", "spam",
        "malware", "social_engineering", "scam"
    }

    def __init__(self, api_key: str):
        if not api_key:
            logger.warning("GEMINI_API_KEY no configurada.")
            self._configured = False
        else:
            genai.configure(api_key=api_key)
            self._model = genai.GenerativeModel(self.MODEL_NAME)
            self._configured = True
            logger.info(f"Analyzer usando {self.MODEL_NAME}")

    # =========================
    # MÉTODO PRINCIPAL
    # =========================
    def analyze(self, content: str, msg_type="sms", sender="Desconocido", subject="") -> MessageResult:

        result = MessageResult(
            content=content,
            msg_type=msg_type,
            sender=sender,
            subject=subject,
            model_used=self.MODEL_NAME if self._configured else "not_configured"
        )

        if not self._configured:
            return self._fallback_no_api(result)

        try:
            raw = self._call_gemini(content, msg_type, sender, subject)
            parsed = self._parse_response(raw)
            self._populate_result(result, parsed)

        except ConnectionError as e:
            logger.error(e)
            return self._fallback_error(result, "Error de conexión con IA")

        except json.JSONDecodeError as e:
            logger.error(f"JSON inválido: {e}")
            return self._fallback_with_rules(result)

        except Exception as e:
            logger.error(f"Error inesperado: {e}")
            return self._fallback_error(result, "Error interno del análisis")

        return result

    # =========================
    # GEMINI
    # =========================
    def _call_gemini(self, content, msg_type, sender, subject):

        subject_line = f"ASUNTO: {subject}" if subject else ""

        prompt = ANALYSIS_PROMPT.format(
            msg_type=msg_type.upper(),
            sender=sender,
            subject_line=subject_line,
            content=content
        )

        try:
            response = self._model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.1,
                    max_output_tokens=800,
                )
            )
            return response.text

        except Exception as e:
            raise ConnectionError(str(e))

    # =========================
    # PARSE ROBUSTO 🔥
    # =========================
    def _parse_response(self, raw_text: str) -> dict:

        if not raw_text:
            raise json.JSONDecodeError("Empty", raw_text, 0)

        # quitar markdown
        clean = re.sub(r'```json|```', '', raw_text, flags=re.IGNORECASE).strip()

        # extraer JSON
        match = re.search(r'\{.*\}', clean, re.DOTALL)
        if not match:
            raise json.JSONDecodeError("No JSON", raw_text, 0)

        json_text = match.group()

        return json.loads(json_text)

    # =========================
    # POPULAR RESULTADO
    # =========================
    def _populate_result(self, result: MessageResult, data: dict):

        # risk level
        rl = data.get("risk_level", "suspicious").lower()
        if rl not in self.VALID_RISK_LEVELS:
            rl = "suspicious"
        result.risk_level = RiskLevel(rl)

        # score
        result.risk_score = max(0.0, min(1.0, float(data.get("risk_score", 0.5))))

        # category con fallback inteligente 🔥
        category = data.get("threat_category", "none").lower()

        if category not in self.VALID_CATEGORIES or category == "none":
            category = self._infer_category(result.content)

        result.threat_category = ThreatCategory(category)

        # resto
        result.explanation = data.get("explanation", "")
        result.indicators = data.get("indicators", [])
        result.recommendation = data.get("recommendation", "")

    # =========================
    # FALLBACKS 🔥
    # =========================
    def _fallback_no_api(self, result):
        result.risk_level = RiskLevel.SUSPICIOUS
        result.risk_score = 0.5
        result.threat_category = ThreatCategory.UNKNOWN
        result.explanation = "API no configurada"
        return result

    def _fallback_error(self, result, message):
        result.risk_level = RiskLevel.SUSPICIOUS
        result.risk_score = 0.5
        result.threat_category = ThreatCategory.UNKNOWN
        result.explanation = message
        return result

    def _fallback_with_rules(self, result):
        category = self._infer_category(result.content)

        result.risk_level = RiskLevel.SUSPICIOUS
        result.risk_score = 0.6
        result.threat_category = ThreatCategory(category)
        result.explanation = "Clasificado por reglas locales"
        result.recommendation = "Revisar manualmente"

        return result

    # =========================
    # REGLAS INTELIGENTES 🔥
    # =========================
    def _infer_category(self, content: str) -> str:

        text = content.lower()

        if any(x in text for x in ["banco", "cuenta", "contraseña", "verifica"]):
            return "phishing"

        if any(x in text for x in ["ganaste", "premio", "gratis"]):
            return "scam"

        if "http" in text or "www" in text:
            return "malware"

        if "urgente" in text:
            return "social_engineering"

        return "spam"