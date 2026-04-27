import json
import logging
import re
from google import genai
from google.genai import types
from modules.models import MessageResult, SenderAnalysis, RiskLevel, ThreatCategory, SenderType

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

SENDER_ANALYSIS_PROMPT = """Eres un experto en ciberseguridad especializado en identificación de remitentes maliciosos.

Analiza únicamente el siguiente remitente de un {msg_type} y determina si es sospechoso o confiable.

REMITENTE: {sender}
{subject_line}
CONTEXTO DEL MENSAJE (primeras 300 caracteres): {content_preview}

Evalúa buscando señales como:
- Spoofing de marcas conocidas (bancos, empresas, gobierno, operadoras)
- Dominios falsos similares a legítimos (typosquatting, homógrafos)
- Números desconocidos que se presentan como organizaciones oficiales
- Patrones típicos de phishing/scam en el identificador del remitente
- Inconsistencias entre el nombre visible y la dirección/número real

Responde ÚNICAMENTE con un JSON válido:
{{
  "is_suspicious": true | false,
  "confidence": <número entre 0.0 y 1.0>,
  "sender_type": "legitimate" | "spoofed" | "suspicious" | "unknown",
  "reason": "<explicación en máximo 1 oración>"
}}

Criterios de confidence:
- 0.0 - 0.3: Remitente probablemente legítimo
- 0.3 - 0.6: Remitente dudoso
- 0.6 - 1.0: Remitente claramente sospechoso o falso

No incluyas ningún texto fuera del JSON."""


class MessageAnalyzer:
    MODEL_NAME = "gemini-2.0-flash"
    VALID_RISK_LEVELS = {"safe", "suspicious", "dangerous"}
    VALID_CATEGORIES = {"none", "phishing", "fraud", "spam", "malware", "social_engineering", "scam", "unknown"}
    VALID_SENDER_TYPES = {"legitimate", "spoofed", "suspicious", "unknown"}

    def __init__(self, api_key: str):
        if not api_key:
            logger.warning("GEMINI_API_KEY no configurada. El análisis no funcionará correctamente.")
            self._configured = False
        else:
            self._client = genai.Client(api_key=api_key)
            self._configured = True
            logger.info(f"MessageAnalyzer inicializado con modelo {self.MODEL_NAME}")

    def analyze(self, content: str, msg_type: str = "sms", sender: str = "Desconocido", subject: str = "") -> MessageResult:
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
            result.sender_analysis = SenderAnalysis(sender=sender, reason="Servicio no disponible")
            return result

        try:
            result.sender_analysis = self.analyze_sender(
                sender=sender,
                msg_type=msg_type,
                subject=subject,
                content=content,
            )

            raw_response = self._call_gemini_content(content, msg_type, sender, subject)
            parsed = self._parse_response(raw_response)
            self._populate_result(result, parsed)

            if result.sender_analysis.is_suspicious and result.risk_level == RiskLevel.SAFE:
                result.risk_level = RiskLevel.SUSPICIOUS
                result.risk_score = max(result.risk_score, 0.35)

            logger.info(
                f"Análisis completado: risk={result.risk_level}, score={result.risk_score}, "
                f"sender_suspicious={result.sender_analysis.is_suspicious}"
            )

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

    def analyze_sender(self, sender: str, msg_type: str = "sms", subject: str = "", content: str = "") -> SenderAnalysis:
        result = SenderAnalysis(sender=sender)

        if not self._configured:
            result.reason = "Servicio no disponible — configura GEMINI_API_KEY."
            return result

        try:
            raw = self._call_gemini_sender(sender, msg_type, subject, content)
            parsed = self._parse_response(raw)

            result.is_suspicious = bool(parsed.get("is_suspicious", False))
            confidence = parsed.get("confidence", 0.0)
            result.confidence = max(0.0, min(1.0, float(confidence)))

            sender_type_str = parsed.get("sender_type", "unknown").lower()
            if sender_type_str not in self.VALID_SENDER_TYPES:
                sender_type_str = "unknown"
            result.sender_type = SenderType(sender_type_str)
            result.reason = parsed.get("reason", "Sin información adicional.")

            logger.info(
                f"Sender analysis: sender='{sender}', suspicious={result.is_suspicious}, "
                f"type={result.sender_type}, confidence={result.confidence:.2f}"
            )

        except RuntimeError:
            raise

        except (ConnectionError, json.JSONDecodeError) as e:
            logger.error(f"Error analizando remitente: {e}")
            result.reason = "No se pudo verificar el remitente. Procede con precaución."
            
        
        return result

    def _call_gemini_content(self, content: str, msg_type: str, sender: str, subject: str) -> str:
        subject_line = f"ASUNTO: {subject}\n" if subject else ""
        prompt = ANALYSIS_PROMPT.format(
            msg_type=msg_type.upper(),
            sender=sender,
            subject_line=subject_line,
            content=content
        )
        return self._generate(prompt)

    def _call_gemini_sender(self, sender: str, msg_type: str, subject: str, content: str) -> str:
        subject_line = f"ASUNTO: {subject}\n" if subject else ""
        content_preview = content[:300] if content else "Sin contenido disponible"
        prompt = SENDER_ANALYSIS_PROMPT.format(
            msg_type=msg_type.upper(),
            sender=sender,
            subject_line=subject_line,
            content_preview=content_preview,
        )
        return self._generate(prompt)

    def _generate(self, prompt: str) -> str:
        try:
            response = self._client.models.generate_content(
                model=self.MODEL_NAME,
                contents=prompt,
                config=types.GenerateContentConfig(temperature=0.1, max_output_tokens=512)
            )
            return response.text
        except Exception as e:
            error_msg = str(e).lower()
            if "api key" in error_msg or "authentication" in error_msg or "permission" in error_msg:
                raise RuntimeError("API_KEY_INVALID")
            elif "quota" in error_msg or "rate limit" in error_msg or "resource_exhausted" in error_msg:
                raise RuntimeError("TOKENS_AGOTADOS")
            else:
                raise ConnectionError(f"Error al contactar Gemini: {e}")

    def _parse_response(self, raw_text: str) -> dict:
        clean = re.sub(r'```(?:json)?\s*|\s*```', '', raw_text).strip()
        return json.loads(clean)

    def _populate_result(self, result: MessageResult, data: dict) -> None:
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