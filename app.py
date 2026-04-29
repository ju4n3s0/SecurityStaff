"""
Shield - Detector de Mensajes Maliciosos
Aplicación principal Flask
"""

from flask import Flask, render_template, request, jsonify
from modules.analyzer import MessageAnalyzer
from modules.models import MessageResult
from modules.threat_database import ThreatDatabase
from dotenv import load_dotenv
import os
import logging

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'shield-dev-key-2024')
app.config['GEMINI_API_KEY'] = os.environ.get('GEMINI_API_KEY', '')

analyzer = MessageAnalyzer(api_key=app.config['GEMINI_API_KEY'])
db_file = os.environ.get('THREAT_DB_FILE', 'threats.db')
threat_db = ThreatDatabase(db_file=db_file)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


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

        result_dict = result.to_dict()

        # Persist every manual analysis to the threat database
        threat_db.save_manual_analysis(result_dict)

        return jsonify(result_dict), 200

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
        'service': 'Security Staff Message Analyzer',
        'gemini_configured': bool(app.config['GEMINI_API_KEY'])
    })

@app.route('/api/threats', methods=['GET'])
def get_threats():
    limit = int(request.args.get('limit', 50))
    risk_level = request.args.get('risk_level')
    threats = threat_db.get_threats(limit=limit, risk_level=risk_level)
    return jsonify({'threats': threats})

@app.route('/api/threats/<int:id>', methods=['GET'])
def get_threat_detail(id):
    threat = threat_db.get_threat_by_id(id)
    if threat:
        return jsonify(threat)
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/threats/<int:id>/whitelist', methods=['POST'])
def whitelist_threat(id):
    data = request.get_json() or {}
    reason = data.get('reason', '')
    success = threat_db.mark_as_whitelisted(id, reason)
    if success:
        return jsonify({'status': 'ok'})
    return jsonify({'error': 'Error updating'}), 500

@app.route('/api/threats/<int:id>/confirm', methods=['POST'])
def confirm_threat(id):
    success = threat_db.mark_as_confirmed_threat(id)
    if success:
        return jsonify({'status': 'ok'})
    return jsonify({'error': 'Error updating'}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint no encontrado'}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'error': 'Método no permitido'}), 405


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5002))
    debug = os.environ.get('DEBUG', 'True').lower() == 'true'
    
    print(f"""
    ======================================
    SECURITY STAFF - Detector Mensajes
         Maliciosos con Gemini AI         
    ======================================
    
    > Servidor iniciado en http://localhost:{port}
    > API Key configurada: {'Si' if app.config['GEMINI_API_KEY'] else 'No (configura GEMINI_API_KEY)'}
    """)
    
    app.run(debug=debug, host='0.0.0.0', port=port)
