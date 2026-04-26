"""
Shield - Detector de Mensajes Maliciosos
Aplicación principal Flask
"""

from flask import Flask, render_template, request, jsonify
from modules.analyzer import MessageAnalyzer
from modules.models import MessageResult
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'shield-dev-key-2024')
app.config['GEMINI_API_KEY'] = os.environ.get('GEMINI_API_KEY', '')

analyzer = MessageAnalyzer(api_key=app.config['GEMINI_API_KEY'])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def analyze_message():
    """
    Endpoint principal para analizar mensajes.
    Recibe: { "content": "...", "type": "sms|email", "sender": "..." }
    Retorna: { "risk_level": "...", "category": "...", "explanation": "...", ... }
    """
    try:
        data = request.get_json()
        if not data or 'content' not in data:
            return jsonify({'error': 'El campo "content" es requerido'}), 400

        content = data.get('content', '').strip()
        msg_type = data.get('type', 'sms')
        sender = data.get('sender', 'Desconocido')
        subject = data.get('subject', '')

        if not content:
            return jsonify({'error': 'El mensaje no puede estar vacío'}), 400

        if len(content) > 10000:
            return jsonify({'error': 'El mensaje excede el límite de 10,000 caracteres'}), 400

        logger.info(f"Analizando mensaje de tipo '{msg_type}' del remitente '{sender}'")

        result: MessageResult = analyzer.analyze(
            content=content,
            msg_type=msg_type,
            sender=sender,
            subject=subject
        )

        return jsonify(result.to_dict()), 200

    except ValueError as e:
        logger.error(f"Error de validación: {e}")
        return jsonify({'error': str(e)}), 400
    except ConnectionError as e:
        logger.error(f"Error de conexión con Gemini: {e}")
        return jsonify({'error': 'No se pudo conectar con el servicio de análisis. Verifica tu API key.'}), 503
    except Exception as e:
        logger.error(f"Error inesperado: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Endpoint de salud para verificar el estado del servicio"""
    return jsonify({
        'status': 'ok',
        'service': 'Shield Message Analyzer',
        'gemini_configured': bool(app.config['GEMINI_API_KEY'])
    })


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint no encontrado'}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'error': 'Método no permitido'}), 405


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'True').lower() == 'true'
    
    print(f"""
    ╔══════════════════════════════════════╗
    ║     SHIELD - Detector de Mensajes    ║
    ║     Maliciosos con Gemini AI         ║
    ╚══════════════════════════════════════╝
    
    🛡️  Servidor iniciado en http://localhost:{port}
    🔑  API Key configurada: {'✓ Sí' if app.config['GEMINI_API_KEY'] else '✗ No (configura GEMINI_API_KEY)'}
    """)
    
    app.run(debug=debug, host='0.0.0.0', port=port)
