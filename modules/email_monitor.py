"""
Módulo para monitorear correos en tiempo real y analizarlos automáticamente
"""

import time
import logging
import os
from collections import deque
from typing import Callable
from modules.email_connector import GmailConnector
from modules.threat_database import ThreatDatabase
from modules.analyzer import MessageAnalyzer
logger = logging.getLogger(__name__)


class EmailMonitor:
    """Monitorea correos en Gmail y los analiza automáticamente"""
    
    def __init__(
        self,
        analyzer: MessageAnalyzer,
        gmail_connector: GmailConnector,
        threat_db: ThreatDatabase,
        check_interval: int = 30,
        max_emails_per_check: int = 10
    ):
        """
        Inicializa el monitor de correos.
        
        Args:
            analyzer: Instancia de MessageAnalyzer
            gmail_connector: Instancia de GmailConnector
            threat_db: Instancia de ThreatDatabase
            check_interval: Segundos entre verificaciones (default: 30)
            max_emails_per_check: Cantidad máxima de correos por verificación
        """
        self.analyzer = analyzer
        self.connector = gmail_connector
        self.threat_db = threat_db
        self.check_interval = check_interval
        self.max_emails_per_check = max_emails_per_check
        self.is_running = False
        self.callback = None  # Para WebSocket/notificaciones en tiempo real
        # Control simple de cuota para llamadas a Gemini (timestamps de llamadas)
        self.call_timestamps = deque()
        self.gemini_max_calls = int(os.environ.get('GEMINI_MAX_CALLS_PER_MINUTE', 15))
    
    def set_threat_callback(self, callback: Callable):
        """
        Define una función callback que se disparará cuando se detecte una amenaza.
        
        Args:
            callback: Función(threat_id, risk_level, sender)
        """
        self.callback = callback
    
    def start_monitoring(self, create_labels: bool = True):
        """
        Inicia el monitoreo de correos.
        
        Args:
            create_labels: Si True, crea etiquetas en Gmail para las amenazas
        """
        self.is_running = True
        logger.info("🚀 Monitor de correos iniciado")
        
        if create_labels:
            self._setup_gmail_labels()
        
        try:
            while self.is_running:
                self._check_and_analyze_emails()
                time.sleep(self.check_interval)
        
        except KeyboardInterrupt:
            logger.info("⏹ Monitor detenido por usuario")
            self.stop_monitoring()
        except Exception as e:
            logger.error(f"❌ Error en monitor: {e}")
            self.is_running = False
    
    def stop_monitoring(self):
        """Detiene el monitoreo"""
        self.is_running = False
        logger.info("Monitor de correos detenido")
    
    def _check_and_analyze_emails(self):
        """Verifica correos nuevos y los analiza"""
        try:
            logger.debug("Verificando correos nuevos...")
            
            # Obtener correos no leídos
            emails = self.connector.get_unread_emails(max_results=self.max_emails_per_check)
            
            if not emails:
                logger.debug("No hay correos nuevos")
                return
            
            logger.info(f"📬 Se encontraron {len(emails)} correos nuevos")
            
            for email_msg in emails:
                self._analyze_single_email(email_msg['id'])
        
        except Exception as e:
            logger.error(f"Error verificando correos: {e}")
    
    def _analyze_single_email(self, message_id: str) -> int:
        """
        Analiza un correo individual.
        
        Args:
            message_id: ID del mensaje en Gmail
        
        Returns:
            threat_id si fue una amenaza, -1 si fue seguro, 0 si hubo error
        """
        try:
            logger.info(f"Analizando correo: {message_id[:10]}...")
            
            # Obtener contenido del correo
            email_data = self.connector.get_email_content(message_id)
            if not email_data:
                logger.warning(f"No se pudo obtener contenido del correo {message_id}")
                return 0
            
            # Verificar si remitente está bloqueado
            if self.threat_db.is_sender_blocked(email_data.get('from', '')):
                logger.warning(f"Remitente bloqueado: {email_data['from']}")
                self.connector.move_to_label(message_id, 'SPAM')
                return 0

            # Pre-filtro local para ahorrar llamadas a Gemini
            try:
                send, reasons = True, {}
            except Exception:
                send, reasons = True, {}

            if not send:
                logger.info(f"Prefiltro: correo {message_id[:10]} marcado como seguro (no enviado a Gemini)")
                # Construir resultado seguro mínimo y guardarlo
                safe_result = {
                    'message': {
                        'content': (email_data.get('body') or '')[:200] + ('...' if len((email_data.get('body') or ''))>200 else ''),
                        'type': 'email',
                        'sender': email_data.get('from', ''),
                        'subject': email_data.get('subject', '')
                    },
                    'analysis': {
                        'risk_level': 'safe',
                        'risk_score': 0.05,
                        'threat_category': 'none',
                        'explanation': 'Prefiltro local: no se detectaron indicadores sospechosos.',
                        'indicators': [],
                        'recommendation': 'Ninguna acción requerida.'
                    },
                    'metadata': {
                        'analyzed_at': None,
                        'model_used': 'prefilter'
                    }
                }
                _ = self.threat_db.save_threat(safe_result, message_id, email_data)
                # Marcar como leído y salir
                try:
                    self.connector.mark_as_read(message_id)
                except Exception:
                    pass
                return -1
            
            # Analizar con Gemini
            # Control sencillo de cuota: limitar llamadas por minuto
            now = time.time()
            # limpiar timestamps viejos (>60s)
            while self.call_timestamps and now - self.call_timestamps[0] > 60:
                self.call_timestamps.popleft()

            if len(self.call_timestamps) >= self.gemini_max_calls:
                # Si el tiempo de espera es pequeño, esperamos, si no, saltamos este ciclo
                oldest = self.call_timestamps[0]
                wait = 60 - (now - oldest)
                if wait <= 5:
                    logger.info(f"Límite de llamadas a Gemini alcanzado, esperando {wait:.1f}s")
                    time.sleep(wait)
                    now = time.time()
                    while self.call_timestamps and now - self.call_timestamps[0] > 60:
                        self.call_timestamps.popleft()
                else:
                    logger.warning("Límite de llamadas a Gemini alcanzado; posponiendo análisis de este correo")
                    return 0

            analysis_result = self.analyzer.analyze(
                content=email_data['body'],
                msg_type='email',
                sender=email_data.get('from', 'Desconocido'),
                subject=email_data.get('subject', '')
            )

            # Registrar timestamp de llamada (si no falló la llamada)
            try:
                self.call_timestamps.append(time.time())
                # mantener deque en tamaño razonable
                while len(self.call_timestamps) > self.gemini_max_calls:
                    self.call_timestamps.popleft()
            except Exception:
                pass
            
            # Convertir a diccionario y guardar en BD
            analysis_dict = analysis_result.to_dict()
            threat_id = self.threat_db.save_threat(analysis_dict, message_id, email_data)
            
            if threat_id == -1:
                logger.debug(f"Correo {message_id} ya fue analizado previamente")
                return 0
            
            # Procesar según nivel de riesgo
            risk_level = analysis_result.risk_level.value
            
            if risk_level == 'dangerous':
                logger.warning(f"🚨 AMENAZA PELIGROSA detectada: {email_data['from']}")
                self.connector.move_to_label(message_id, 'Security Staff/Peligroso')
                
                if self.callback:
                    self.callback(threat_id, 'dangerous', email_data['from'])
                
                return threat_id
            
            elif risk_level == 'suspicious':
                logger.warning(f"⚠️  CORREO SOSPECHOSO: {email_data['from']}")
                self.connector.move_to_label(message_id, 'Security Staff/Sospechoso')
                
                if self.callback:
                    self.callback(threat_id, 'suspicious', email_data['from'])
                
                return threat_id
            
            else:  # safe
                logger.info(f"✅ Correo seguro de: {email_data['from']}")
                # No mover a carpeta, solo dejar como leído
                return -1
            
            # Marcar como leído en todos los casos
            self.connector.mark_as_read(message_id)
        
        except Exception as e:
            logger.error(f"Error analizando correo {message_id}: {e}")
            return 0
    
    def _setup_gmail_labels(self):
        """Crea etiquetas de Security Staff en Gmail si no existen"""
        try:
            logger.info("Configurando etiquetas en Gmail...")
            
            labels_to_create = [
                'Security Staff/Peligroso',
                'Security Staff/Sospechoso',
                'Security Staff/Whitelisted'
            ]
            
            for label_name in labels_to_create:
                try:
                    self.connector.create_label(label_name)
                except Exception as e:
                    if 'already exists' in str(e).lower():
                        logger.debug(f"Etiqueta {label_name} ya existe")
                    else:
                        logger.warning(f"Error creando etiqueta {label_name}: {e}")
        
        except Exception as e:
            logger.error(f"Error configurando etiquetas: {e}")
    
    def get_threat_summary(self) -> dict:
        """Obtiene un resumen de amenazas activas"""
        try:
            stats = self.threat_db.get_statistics()
            
            dangerous_threats = self.threat_db.get_threats(
                limit=5,
                risk_level='dangerous'
            )
            suspicious_threats = self.threat_db.get_threats(
                limit=5,
                risk_level='suspicious'
            )
            
            return {
                'statistics': stats,
                'recent_dangerous': dangerous_threats,
                'recent_suspicious': suspicious_threats
            }
        
        except Exception as e:
            logger.error(f"Error obteniendo resumen: {e}")
            return {}
    
    def analyze_email_manually(self, message_id: str) -> dict:
        """
        Analiza un correo específico bajo demanda.
        
        Args:
            message_id: ID del correo en Gmail
        
        Returns:
            Diccionario con resultado del análisis
        """
        try:
            email_data = self.connector.get_email_content(message_id)
            if not email_data:
                return {'error': 'No se pudo obtener el correo'}
            
            result = self.analyzer.analyze(
                content=email_data['body'],
                msg_type='email',
                sender=email_data.get('from', ''),
                subject=email_data.get('subject', '')
            )
            
            return result.to_dict()
        
        except Exception as e:
            logger.error(f"Error en análisis manual: {e}")
            return {'error': str(e)}
