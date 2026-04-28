import re

SUSPICIOUS_WORDS = [
    "urgente", "ganaste", "premio", "haz clic", "verifica tu cuenta",
    "contraseña", "banco", "transferencia", "gratis", "oferta limitada"
]

SUSPICIOUS_DOMAINS = [
    "bit.ly", "tinyurl.com", "goo.gl", "fakebank.com", "secure-login.net"
]


def detect_suspicious_patterns(content: str):
    content_lower = content.lower()

    matches = []

    # Palabras
    for word in SUSPICIOUS_WORDS:
        if word in content_lower:
            matches.append(f"Palabra sospechosa: {word}")

    # URLs
    urls = re.findall(r'https?://[^\s]+', content_lower)
    for url in urls:
        for domain in SUSPICIOUS_DOMAINS:
            if domain in url:
                matches.append(f"Dominio sospechoso: {domain}")

    return matches