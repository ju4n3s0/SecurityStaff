#!/usr/bin/env python3
"""
Servicio independiente para monitorear correos en tiempo real.
Corre en background y analiza automáticamente correos nuevos.

Uso:
    python monitor_service.py
"""

import os
import sys
import logging
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Importar módulos
from modules.email_connector import GmailConnector
from modules.email_monitor import EmailMonitor
from modules.analyzer import MessageAnalyzer
from modules.threat_database import ThreatDatabase


def print_banner():
    """Muestra el banner de bienvenida"""
    print("""
    ╔═══════════════════════════════════════════════════╗
    ║   SECURITY STAFF - Email Threat Monitor Service   ║
    ║   Monitoreo automático de amenazas en correos    ║
    ╚═══════════════════════════════════════════════════╝
    """)


def initialize_components():
    """Inicializa todos los componentes del servicio"""
    
    logger.info("🔧 Inicializando componentes...")
    
    # 1. Verificar API Key de Gemini
    gemini_api_key = os.environ.get('GEMINI_API_KEY', '')
    if not gemini_api_key:
        logger.error("❌ GEMINI_API_KEY no configurada en .env")
        sys.exit(1)
    
    # 2. Inicializar analizador de mensajes
    logger.info("  → Conectando a Gemini API...")
    analyzer = MessageAnalyzer(api_key=gemini_api_key)
    
    # 3. Inicializar conector Gmail
    logger.info("  → Conectando a Gmail...")
    try:
        gmail_connector = GmailConnector(
            credentials_file='credentials.json',
            token_file='token.pickle'
        )
    except FileNotFoundError as e:
        logger.error(f"❌ {e}")
        logger.info("""
        Pasos para configurar Gmail:
        1. Ve a: https://console.cloud.google.com/
        2. Crea un proyecto nuevo
        3. Activa Gmail API
        4. Crea credenciales OAuth 2.0 (Desktop Application)
        5. Descarga el archivo JSON y renómbralo a 'credentials.json'
        6. Colócalo en la raíz del proyecto
        """)
        sys.exit(1)
    
    # 4. Inicializar base de datos
    db_file = os.environ.get('THREAT_DB_FILE', 'threats.db')
    logger.info(f"  → Inicializando base de datos: {db_file}")
    threat_db = ThreatDatabase(db_file=db_file)
    
    # 5. Inicializar monitor
    logger.info("  → Configurando monitor de correos...")
    check_interval = int(os.environ.get('CHECK_INTERVAL', 30))
    monitor = EmailMonitor(
        analyzer=analyzer,
        gmail_connector=gmail_connector,
        threat_db=threat_db,
        check_interval=check_interval
    )
    
    logger.info("✅ Todos los componentes inicializados correctamente")
    return monitor, threat_db


def print_initial_stats(threat_db: ThreatDatabase):
    """Muestra estadísticas iniciales"""
    stats = threat_db.get_statistics()
    
    print(f"""
╔════════════════════════════════════════════════════╗
║         ESTADÍSTICAS DE AMENAZAS DETECTADAS        ║
╠════════════════════════════════════════════════════╣
║  Total de análisis:        {stats.get('total', 0):>3}                ║
║  🚨 Peligrosos:            {stats.get('dangerous', 0):>3}                ║
║  ⚠️  Sospechosos:           {stats.get('suspicious', 0):>3}                ║
║  ✅ Seguros:                {stats.get('safe', 0):>3}                ║
╠════════════════════════════════════════════════════╣
║  Por categoría:                                    ║
""")
    
    for category, count in stats.get('categories', {}).items():
        print(f"║    • {category:.<35} {count:>3}          ║")
    
    print("╚════════════════════════════════════════════════════╝\n")


def run_service():
    """Ejecuta el servicio principal"""
    
    print_banner()
    
    try:
        # Inicializar componentes
        monitor, threat_db = initialize_components()
        
        # Mostrar estadísticas iniciales
        print_initial_stats(threat_db)
        
        # Mensaje de inicio
        print(f"""
╔════════════════════════════════════════════════════╗
║         MONITOR INICIADO - EN ESCUCHA              ║
╠════════════════════════════════════════════════════╣
║                                                    ║
║  El servicio está monitoreando tu bandeja de       ║
║  entrada cada {os.environ.get('CHECK_INTERVAL', 30)} segundos.                    ║
║                                                    ║
║  Presiona CTRL+C para detener el servicio.        ║
║                                                    ║
║  📊 Dashboard disponible en:                       ║
║     http://localhost:5000/                         ║
║                                                    ║
║  🔗 API disponible en:                             ║
║     http://localhost:5000/api/threats              ║
║                                                    ║
╚════════════════════════════════════════════════════╝
        """)
        
        # Iniciar monitoreo
        monitor.start_monitoring(create_labels=True)
    
    except KeyboardInterrupt:
        logger.info("⏹ Servicio detenido por usuario")
    except Exception as e:
        logger.error(f"❌ Error fatal: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("Limpiando recursos...")
        try:
            threat_db.close()
        except:
            pass


if __name__ == '__main__':
    run_service()
