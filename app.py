"""
Shield - Detector de Mensajes Maliciosos
Aplicación principal Flask
"""

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
import threading
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

# Socket.IO para notificaciones en tiempo real
socketio = SocketIO(app, cors_allowed_origins="*")

analyzer = MessageAnalyzer(api_key=app.config['GEMINI_API_KEY'])

# Inicializar base de datos para amenazas
threat_db = ThreatDatabase(db_file=os.environ.get('THREAT_DB_FILE', 'threats.db'))

# Opcional: iniciar monitor integrado al levantar Flask
def _start_monitor_in_background():
    try:
        from modules.email_connector import GmailConnector
        from modules.email_monitor import EmailMonitor

        # Solo intentar si el usuario activó el monitor integrado
        if os.environ.get('ENABLE_MONITOR', 'false').lower() not in ('1', 'true', 'yes'):
            return

        # Crear componentes
        gmail_connector = GmailConnector(credentials_file='credentials.json', token_file='token.pickle')
        analyzer_local = MessageAnalyzer(api_key=app.config['GEMINI_API_KEY'])
        monitor = EmailMonitor(
            analyzer=analyzer_local,
            gmail_connector=gmail_connector,
            threat_db=threat_db,
            check_interval=int(os.environ.get('CHECK_INTERVAL', 30))
        )

        # Callback para emitir por socketio cuando se detecte una amenaza
        def _emit_threat(threat_id, risk_level, sender):
            try:
                threat = threat_db.get_threat_by_id(threat_id)
                if threat:
                    socketio.emit('new_threat', threat, broadcast=True)
            except Exception:
                pass

        monitor.set_threat_callback(_emit_threat)

        t = threading.Thread(target=monitor.start_monitoring, kwargs={'create_labels': True}, daemon=True)
        t.start()
        app.logger.info('Monitor integrado iniciado en background')
    except FileNotFoundError:
        app.logger.warning('credentials.json no encontrado; monitor integrado no iniciado')
    except Exception as e:
        app.logger.error(f'Error iniciando monitor integrado: {e}')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard')
def dashboard():
    """Panel de administración — lista de amenazas"""
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


@app.route('/api/threats', methods=['GET'])
def get_threats():
    """
    Obtiene la lista de amenazas detectadas.
    Query params: limit, risk_level (safe|suspicious|dangerous)
    """
    try:
        limit = request.args.get('limit', 50, type=int)
        risk_level = request.args.get('risk_level', type=str)
        
        threats = threat_db.get_threats(limit=limit, risk_level=risk_level)
        
        return jsonify({
            'count': len(threats),
            'threats': threats
        }), 200
    
    except Exception as e:
        logger.error(f"Error obteniendo amenazas: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/threats/<int:threat_id>', methods=['GET'])
def get_threat_detail(threat_id: int):
    """Obtiene detalles de una amenaza específica"""
    try:
        threat = threat_db.get_threat_by_id(threat_id)
        if not threat:
            return jsonify({'error': 'Amenaza no encontrada'}), 404
        
        return jsonify(threat), 200
    
    except Exception as e:
        logger.error(f"Error obteniendo amenaza: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/threats/<int:threat_id>/whitelist', methods=['POST'])
def whitelist_threat(threat_id: int):
    """Marca una amenaza como segura (whitelist)"""
    try:
        data = request.get_json() or {}
        reason = data.get('reason', '')
        
        success = threat_db.mark_as_whitelisted(threat_id, reason)
        
        if success:
            return jsonify({'status': 'ok', 'message': 'Amenaza añadida a whitelist'}), 200
        else:
            return jsonify({'error': 'No se pudo actualizar la amenaza'}), 500
    
    except Exception as e:
        logger.error(f"Error en whitelist: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/threats/<int:threat_id>/confirm', methods=['POST'])
def confirm_threat(threat_id: int):
    """Confirma una amenaza como real"""
    try:
        success = threat_db.mark_as_confirmed_threat(threat_id)
        
        if success:
            return jsonify({'status': 'ok', 'message': 'Amenaza confirmada'}), 200
        else:
            return jsonify({'error': 'No se pudo actualizar la amenaza'}), 500
    
    except Exception as e:
        logger.error(f"Error confirmando amenaza: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Obtiene estadísticas de amenazas"""
    try:
        stats = threat_db.get_statistics()
        return jsonify(stats), 200
    
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas: {e}")
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint no encontrado'}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'error': 'Método no permitido'}), 405


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5002))
    debug = os.environ.get('DEBUG', 'True').lower() == 'true'
    # Iniciar monitor integrado si está habilitado
    _start_monitor_in_background()
    
    print(f"""
    ╔══════════════════════════════════════╗
    ║     SHIELD - Detector de Mensajes    ║
    ║     Maliciosos con Gemini AI         ║
    ╚══════════════════════════════════════╝
    
    🛡️  Servidor iniciado en http://localhost:{port}
    🔑  API Key configurada: {'✓ Sí' if app.config['GEMINI_API_KEY'] else '✗ No (configura GEMINI_API_KEY)'}
    """)
    
    # Usar socketio.run para habilitar websocket
    socketio.run(app, debug=debug, host='0.0.0.0', port=port)
