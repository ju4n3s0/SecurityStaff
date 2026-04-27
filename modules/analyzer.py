"""
Módulo de análisis de mensajes con Gemini API
"""

import json
import logging
import re
import google.generativeai as genai
from modules.models import MessageResult, RiskLevel, ThreatCategory

logger = logging.getLogger(__name__)


ANALYSIS_PROMPT = """Eres un experto en ciberseguridad especializado en detección de amenazas digitales.
Analiza el siguiente mensaje y determina si es potencialmente malicioso.

TIPO DE MENSAJE: {msg_type}
REMITENTE: {sender}
{subject_line}
CONTENIDO:
---
{content}
---

Evalúa el mensaje buscando señales de:
- Phishing (suplantación de identidad, robo de credenciales)
- Fraude financiero (solicitudes de dinero, premios falsos)
- Spam agresivo con contenido engañoso
- Malware (links maliciosos, archivos adjuntos sospechosos)
- Ingeniería social (manipulación emocional, urgencia falsa)
- Estafas (scams de cualquier tipo)

Responde ÚNICAMENTE con un JSON válido con esta estructura exacta:
{{
  "risk_level": "safe" | "suspicious" | "dangerous",
  "risk_score": <número entre 0.0 y 1.0>,
  "threat_category": "none" | "phishing" | "fraud" | "spam" | "malware" | "social_engineering" | "scam" | "unknown",
  "explanation": "<explicación clara y concisa de máximo 2 oraciones>",
  "indicators": ["<indicador 1>", "<indicador 2>", ...],
  "recommendation": "<acción recomendada al usuario>"
}}

Criterios de risk_score:
- 0.0 - 0.3: Mensaje seguro
- 0.3 - 0.6: Sospechoso, requiere precaución
- 0.6 - 1.0: Peligroso, amenaza clara

No incluyas ningún texto fuera del JSON."""


class MessageAnalyzer:
    """Analizador de mensajes usando Gemini AI"""

    MODEL_NAME = "gemini-2.5-flash"
    VALID_RISK_LEVELS = {"safe", "suspicious", "dangerous"}
    VALID_CATEGORIES = {"none", "phishing", "fraud", "spam", "malware", "social_engineering", "scam", "unknown"}

    def __init__(self, api_key: str):
        if not api_key:
            logger.warning("GEMINI_API_KEY no configurada. El análisis no funcionará correctamente.")
            self._configured = False
        else:
            genai.configure(api_key=api_key)
            self._model = genai.GenerativeModel(self.MODEL_NAME)
            self._configured = True
            logger.info(f"MessageAnalyzer inicializado con modelo {self.MODEL_NAME}")

    def analyze(self, content: str, msg_type: str = "sms", sender: str = "Desconocido", subject: str = "") -> MessageResult:
        """
        Analiza un mensaje y retorna el resultado de clasificación.
        
        Args:
            content: Texto del mensaje a analizar
            msg_type: Tipo de mensaje ('sms' o 'email')
            sender: Remitente del mensaje
            subject: Asunto del mensaje (para emails)
        
        Returns:
            MessageResult con los datos del análisis
        """
        result = MessageResult(
            content=content,
            msg_type=msg_type,
            sender=sender,
            subject=subject,
            model_used=self.MODEL_NAME if self._configured else "not_configured"
        )

        if not self._configured:
            result.risk_level = RiskLevel.SUSPICIOUS
            result.risk_score = 0.5
            result.threat_category = ThreatCategory.UNKNOWN
            result.explanation = "API key de Gemini no configurada. Configura GEMINI_API_KEY para análisis real."
            result.indicators = ["Servicio de análisis no disponible"]
            result.recommendation = "Configura la variable de entorno GEMINI_API_KEY con tu clave de Gemini."
            return result

        try:
            raw_response = self._call_gemini(content, msg_type, sender, subject)
            parsed = self._parse_response(raw_response)
            self._populate_result(result, parsed)
            logger.info(f"Análisis completado: risk_level={result.risk_level}, score={result.risk_score}")

        except ConnectionError:
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Error al parsear respuesta de Gemini: {e}")
            result.risk_level = RiskLevel.SUSPICIOUS
            result.risk_score = 0.5
            result.threat_category = ThreatCategory.UNKNOWN
            result.explanation = "No se pudo procesar la respuesta del analizador. Revisa manualmente."
            result.recommendation = "Procede con precaución y verifica el mensaje manualmente."

        return result

    def _call_gemini(self, content: str, msg_type: str, sender: str, subject: str) -> str:
        """Realiza la llamada a la API de Gemini"""
        subject_line = f"ASUNTO: {subject}\n" if subject else ""
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
                    max_output_tokens=1024,
                )
            )
            return response.text
        except Exception as e:
            error_msg = str(e).lower()
            if "api key" in error_msg or "authentication" in error_msg or "permission" in error_msg:
                raise ConnectionError(f"Error de autenticación con Gemini: {e}")
            elif "quota" in error_msg or "rate limit" in error_msg:
                raise ConnectionError(f"Límite de cuota de Gemini alcanzado: {e}")
            else:
                raise ConnectionError(f"Error al contactar Gemini: {e}")

    def _parse_response(self, raw_text: str) -> dict:
        """Parsea la respuesta JSON de Gemini"""
        # Limpiar markdown si Gemini lo incluye
        clean = re.sub(r'```(?:json)?\s*|\s*```', '', raw_text).strip()
        return json.loads(clean)

    def _populate_result(self, result: MessageResult, data: dict) -> None:
        """Popula el objeto resultado con los datos parseados"""
        risk_level_str = data.get("risk_level", "suspicious").lower()
        if risk_level_str not in self.VALID_RISK_LEVELS:
            risk_level_str = "suspicious"
        result.risk_level = RiskLevel(risk_level_str)

        risk_score = data.get("risk_score", 0.5)
        result.risk_score = max(0.0, min(1.0, float(risk_score)))

        category_str = data.get("threat_category", "unknown").lower()
        if category_str not in self.VALID_CATEGORIES:
            category_str = "unknown"
        result.threat_category = ThreatCategory(category_str)

        result.explanation = data.get("explanation", "Sin explicación disponible")
        result.indicators = data.get("indicators", [])
        result.recommendation = data.get("recommendation", "Procede con precaución.")
