# 🛡️ Security Staff — Detector de Amenazas con Gemini AI

Aplicación web para análisis de mensajes SMS y correos electrónicos usando Google Gemini AI. Detecta phishing, fraudes, malware, spam e ingeniería social en tiempo real. Incluye historial persistente e integración con Gmail para monitoreo automático.

---

## Estructura del proyecto

```
SecurityStaff/
├── app.py                      # Aplicación principal Flask (API + rutas)
├── monitor_service.py          # Servicio independiente de monitoreo Gmail
├── requirements.txt            # Dependencias Python
├── .env                        # Variables de entorno (NO subir al repo)
├── credentials.json            # OAuth2 Gmail (NO subir al repo)
├── token.pickle                # Token Gmail generado (NO subir al repo)
├── threats.db                  # Base de datos SQLite (NO subir al repo)
├── modules/
│   ├── __init__.py
│   ├── analyzer.py             # Integración con Gemini AI
│   ├── models.py               # Modelos de datos (RiskLevel, MessageResult)
│   ├── email_connector.py      # Conector OAuth2 para Gmail API
│   ├── email_monitor.py        # Monitor automático de correos
│   └── threat_database.py      # Base de datos SQLite de amenazas
└── templates/
    ├── index.html              # Detector principal (SMS / Email manual)
    └── dashboard.html          # Historial de amenazas detectadas
```

---

## Instalación y configuración

### 1. Instalar dependencias
```bash
pip install -r requirements.txt
```

### 2. Configurar variables de entorno
Edita el archivo `.env` con tus valores:
```env
GEMINI_API_KEY=tu_api_key_aqui
PORT=5002
DEBUG=True
THREAT_DB_FILE=threats.db
CHECK_INTERVAL=30
```

Obtén tu API Key gratuita de Gemini en: https://aistudio.google.com/app/apikey

### 3. Ejecutar la aplicación web
```bash
python app.py
```
Luego abre: **http://localhost:5002**

---

## Integración con Gmail (opcional)

Para que la app monitoree tu Gmail automáticamente y llene el historial:

### Paso 1 — Configurar Google Cloud
1. Ve a https://console.cloud.google.com/
2. Selecciona (o crea) un proyecto
3. Activa la **Gmail API**: APIs & Services → Library → Gmail API → Enable
4. Crea credenciales OAuth 2.0: APIs & Services → Credentials → Create Credentials → OAuth client ID → Desktop App
5. Descarga el JSON → renómbralo a **`credentials.json`** → colócalo en la raíz del proyecto
6. En OAuth Consent Screen, agrega tu correo como **Test User**

### Paso 2 — Iniciar el monitor (en terminal separada)
```bash
python monitor_service.py
```
La primera vez se abrirá el navegador para autorizar el acceso a Gmail. Luego el monitor revisa correos nuevos cada 30 segundos y los guarda en el historial.

> **Nota:** `app.py` y `monitor_service.py` son procesos independientes. Ambos deben correr simultáneamente.

---

## Uso de la aplicación

### Detector manual (`/`)
- Selecciona tipo de mensaje: **SMS** o **Email**
- Ingresa remitente, asunto (si es email) y contenido
- Haz clic en **ANALIZAR MENSAJE**
- Gemini AI devuelve: nivel de riesgo, score, categoría, indicadores y recomendación

### Historial (`/dashboard`)
- Ve todos los correos analizados (automáticos via Gmail + manuales)
- Filtra por nivel de riesgo (Peligroso / Sospechoso / Seguro)
- Busca por remitente o asunto
- Haz clic en **Ver** para el detalle completo del análisis
- Haz clic en **Analizar →** para mandar el correo al detector con un clic
- Marca correos como **seguros (whitelist)** o **confirma amenazas**

---

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
    "model_used": "gemini-2.5-flash",
    "analysis_source": "gemini"
  }
}
```

### `GET /api/health`
Verifica el estado del servicio.

### `GET /api/threats?limit=50&risk_level=dangerous`
Lista los correos del historial. Parámetros opcionales: `limit`, `risk_level`.

### `GET /api/threats/<id>`
Detalle de un correo específico.

### `POST /api/threats/<id>/whitelist`
Marca un correo como seguro.

### `POST /api/threats/<id>/confirm`
Confirma un correo como amenaza real.

---

## Niveles de riesgo

| Nivel | Score | Descripción |
|-------|-------|-------------|
| `safe` | 0.0 – 0.3 | Mensaje seguro ✅ |
| `suspicious` | 0.3 – 0.6 | Requiere precaución ⚠️ |
| `dangerous` | 0.6 – 1.0 | Amenaza identificada 🚨 |

## Categorías de amenaza

| Categoría | Descripción |
|-----------|-------------|
| `phishing` | Suplantación de identidad |
| `fraud` | Fraude financiero |
| `spam` | Correo no deseado engañoso |
| `malware` | Links o archivos maliciosos |
| `social_engineering` | Manipulación psicológica |
| `scam` | Estafas en general |
| `none` | Sin amenaza detectada |

---

## Archivos excluidos del repositorio

Los siguientes archivos contienen información sensible y **no se suben a Git**:

```
.env                  # API Keys y configuración
credentials.json      # Credenciales OAuth2 de Gmail
token.pickle          # Token de acceso Gmail
threats.db            # Base de datos local de amenazas
```
