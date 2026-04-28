"""
Prefilter heurístico para reducir llamadas a Gemini.
Ahora configurable vía variables de entorno para usos académicos (activar/desactivar reglas).
Devuelve True si el correo *debe* enviarse a Gemini, False para marcarlo seguro sin enviar.
"""

import os
import re
from typing import Dict, Tuple

# Cargar configuraciones desde variables de entorno
CHECK_URLS = os.environ.get('PREFILTER_CHECK_URLS', 'true').lower() in ('1', 'true', 'yes')
CHECK_IPS = os.environ.get('PREFILTER_CHECK_IPS', 'true').lower() in ('1', 'true', 'yes')
CHECK_TLDS = os.environ.get('PREFILTER_CHECK_TLDS', 'true').lower() in ('1', 'true', 'yes')
CHECK_KEYWORDS = os.environ.get('PREFILTER_CHECK_KEYWORDS', 'true').lower() in ('1', 'true', 'yes')
MIN_URLS_TO_FLAG = int(os.environ.get('PREFILTER_MIN_URLS', '1'))

# Patterns
URL_RE = re.compile(r'https?://\S+', re.IGNORECASE)
IP_LINK_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Defaults (can be extended via PREFILTER_SUSPICIOUS_TLDS env, comma-separated)
DEFAULT_SUSPICIOUS_TLDS = ('.ru', '.xyz', '.top', '.club', '.info')
extra_tlds = os.environ.get('PREFILTER_SUSPICIOUS_TLDS', '')
SUSPICIOUS_TLDS = tuple(x.strip() for x in extra_tlds.split(',') if x.strip()) or DEFAULT_SUSPICIOUS_TLDS

FINANCIAL_KEYWORDS = tuple(x.strip() for x in os.environ.get('PREFILTER_FINANCIAL_KEYWORDS', 'transfer,pago,pagar,cuenta,banco,saldo,tarjeta,recibo,factura').split(','))
URGENT_KEYWORDS = tuple(x.strip() for x in os.environ.get('PREFILTER_URGENT_KEYWORDS', 'urgente,inmediatamente,ahora,24 horas,deuda,bloquead').split(','))
CREDENTIAL_KEYWORDS = tuple(x.strip() for x in os.environ.get('PREFILTER_CREDENTIAL_KEYWORDS', 'password,contraseña,clave,login,usuario,credencial').split(','))
PRIZE_KEYWORDS = tuple(x.strip() for x in os.environ.get('PREFILTER_PRIZE_KEYWORDS', 'ganador,premio,felicitaciones,sorteo').split(','))


def should_send_to_gemini(email_data: Dict) -> Tuple[bool, Dict]:
    """Analiza rápidamente el correo y decide si debe enviarse a Gemini.

    Retorna (send: bool, reasons: dict)
    """
    reasons = {}
    body = (email_data.get('body') or '').lower()
    subject = (email_data.get('subject') or '').lower()
    sender = (email_data.get('from') or '').lower()

    # Friendly text heuristic (simple)
    if CHECK_KEYWORDS and re.search(r"\b(dad|mom|mama|papá|papa|hello|hi|saludos|gracias)\b", body):
        reasons['friendly_text'] = True

    # URLs
    if CHECK_URLS:
        urls = URL_RE.findall(email_data.get('body') or '')
        if len(urls) >= MIN_URLS_TO_FLAG:
            reasons['urls'] = urls
    else:
        urls = []

    # IP links
    if CHECK_IPS and IP_LINK_RE.search(body):
        reasons['ip_link'] = True

    # Suspicious TLDs in links or sender domain
    if CHECK_TLDS:
        for tld in SUSPICIOUS_TLDS:
            if tld and (tld in body or tld in sender):
                reasons.setdefault('suspicious_tld', []).append(tld)

    # Keywords
    if CHECK_KEYWORDS:
        for kw in FINANCIAL_KEYWORDS:
            if kw and (kw in body or kw in subject):
                reasons.setdefault('financial', []).append(kw)
        for kw in URGENT_KEYWORDS:
            if kw and (kw in body or kw in subject):
                reasons.setdefault('urgent', []).append(kw)
        for kw in CREDENTIAL_KEYWORDS:
            if kw and (kw in body or kw in subject):
                reasons.setdefault('credentials', []).append(kw)
        for kw in PRIZE_KEYWORDS:
            if kw and (kw in body or kw in subject):
                reasons.setdefault('prize', []).append(kw)

    # Decide: if any high-confidence indicators -> send
    high_confidence = any(k in reasons for k in ('urls', 'ip_link', 'suspicious_tld'))
    keyword_flags = any(k in reasons for k in ('financial', 'credentials', 'urgent', 'prize'))

    if high_confidence:
        return True, reasons
    if keyword_flags:
        return True, reasons

    # otherwise treat as safe
    return False, reasons
