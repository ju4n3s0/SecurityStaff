# 🛡️ Shield — Detector de Mensajes Maliciosos con Gemini AI

Prototipo funcional para análisis de mensajes SMS y correos electrónicos usando Google Gemini.

## Estructura del proyecto

```
shield/
├── app.py                  # Aplicación principal Flask
├── requirements.txt        # Dependencias Python
├── .env.example            # Plantilla de variables de entorno
├── modules/
│   ├── __init__.py
│   ├── analyzer.py         # Integración con Gemini API
│   └── models.py           # Modelos de datos
└── templates/
    └── index.html          # Interfaz web
```

## Configuración e instalación

### 1. Instalar dependencias
```bash
pip install -r requirements.txt
```

### 2. Configurar API Key de Gemini
```bash
cp .env.example .env
# Edita .env y agrega tu GEMINI_API_KEY
```

Obtén tu API Key gratuita en: https://aistudio.google.com/app/apikey

### 3. Ejecutar la aplicación
```bash
# Con python-dotenv (recomendado)
python app.py

# O exportando la variable directamente
GEMINI_API_KEY=tu_clave python app.py
```

### 4. Abrir en el navegador
```
http://localhost:5000

or 

http://192.168.1.9:5000
```

## API Endpoints

### `POST /api/analyze`
Analiza un mensaje y retorna la clasificación de riesgo.

**Request:**
```json
{
  "content": "Texto del mensaje",
  "type": "sms",
  "sender": "+57 300 000 0000",
  "subject": ""
}
```

**Response:**
```json
{
  "message": { "content": "...", "type": "sms", "sender": "..." },
  "analysis": {
    "risk_level": "safe | suspicious | dangerous",
    "risk_score": 0.85,
    "threat_category": "phishing | fraud | spam | malware | social_engineering | scam | none | unknown",
    "explanation": "Explicación del análisis",
    "indicators": ["Indicador 1", "Indicador 2"],
    "recommendation": "Acción recomendada"
  },
  "metadata": {
    "analyzed_at": "2024-01-01T12:00:00",
    "model_used": "gemini-1.5-flash",
    "analysis_source": "gemini"
  }
}
```

### `GET /api/health`
Verifica el estado del servicio.

## Niveles de riesgo

| Nivel | Score | Descripción |
|-------|-------|-------------|
| `safe` | 0.0 – 0.3 | Mensaje seguro |
| `suspicious` | 0.3 – 0.6 | Requiere precaución |
| `dangerous` | 0.6 – 1.0 | Amenaza identificada |

## Categorías de amenaza

- `phishing` — Suplantación de identidad
- `fraud` — Fraude financiero
- `spam` — Correo no deseado engañoso
- `malware` — Links o archivos maliciosos
- `social_engineering` — Manipulación psicológica
- `scam` — Estafas en general
- `none` — Sin amenaza
