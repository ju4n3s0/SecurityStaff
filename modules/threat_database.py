"""
Módulo para almacenar y recuperar análisis de amenazas en base de datos
"""

import sqlite3
import json
import logging
from datetime import datetime
from typing import List, Optional, Dict

logger = logging.getLogger(__name__)


class ThreatDatabase:
    """Gestor de base de datos SQLite para almacenar análisis de amenazas"""
    
    def __init__(self, db_file: str = 'threats.db'):
        """
        Inicializa la conexión a la BD.
        
        Args:
            db_file: Ruta del archivo SQLite
        """
        self.db_file = db_file
        self.conn = None
        self._initialize()
    
    def _initialize(self):
        """Crea tablas si no existen"""
        try:
            self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row  # Acceder por nombre de columna
            
            cursor = self.conn.cursor()
            
            # Tabla principal de amenazas
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    gmail_message_id TEXT UNIQUE,
                    sender TEXT NOT NULL,
                    subject TEXT,
                    body TEXT,
                    risk_level TEXT,
                    risk_score REAL,
                    threat_category TEXT,
                    explanation TEXT,
                    indicators TEXT,
                    recommendation TEXT,
                    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'flagged',
                    user_action TEXT,
                    is_whitelisted INTEGER DEFAULT 0,
                    model_used TEXT
                )
            ''')
            
            # Índices para búsquedas rápidas
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_risk_level 
                ON threats(risk_level)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_analyzed_at 
                ON threats(analyzed_at DESC)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_sender 
                ON threats(sender)
            ''')
            cursor.execute('''
                CREATE UNIQUE INDEX IF NOT EXISTS idx_gmail_message_id 
                ON threats(gmail_message_id)
            ''')
            
            # Tabla de historial de acciones
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id INTEGER NOT NULL,
                    action TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(threat_id) REFERENCES threats(id)
                )
            ''')
            
            # Tabla de remitentes bloqueados
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_senders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            self.conn.commit()
            logger.info(f"✓ Base de datos inicializada: {self.db_file}")
        
        except sqlite3.Error as e:
            logger.error(f"Error inicializando BD: {e}")
            raise
    
    def save_threat(self, analysis: dict, gmail_message_id: str, email_data: dict) -> int:
        """
        Guarda un análisis de amenaza en la BD.
        
        Args:
            analysis: Diccionario con resultado del análisis (from MessageResult.to_dict())
            gmail_message_id: ID del mensaje en Gmail
            email_data: Diccionario con datos del correo (from email_connector)
        
        Returns:
            ID de la fila insertada
        """
        try:
            cursor = self.conn.cursor()
            
            a = analysis['analysis']
            
            cursor.execute('''
                INSERT INTO threats (
                    gmail_message_id, sender, subject, body,
                    risk_level, risk_score, threat_category,
                    explanation, indicators, recommendation,
                    analyzed_at, model_used
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                gmail_message_id,
                email_data.get('from', ''),
                email_data.get('subject', ''),
                email_data.get('body', '')[:1000],  # Primeros 1000 caracteres
                a.get('risk_level'),
                a.get('risk_score'),
                a.get('threat_category'),
                a.get('explanation'),
                json.dumps(a.get('indicators', [])),
                a.get('recommendation'),
                analysis['metadata'].get('analyzed_at'),
                analysis['metadata'].get('model_used')
            ))
            
            self.conn.commit()
            threat_id = cursor.lastrowid
            logger.info(f"Amenaza guardada con ID: {threat_id}")
            return threat_id
        
        except sqlite3.IntegrityError:
            logger.warning(f"Mensaje {gmail_message_id} ya fue analizado")
            return -1
        except Exception as e:
            logger.error(f"Error guardando amenaza: {e}")
            return -1
    
    def get_threats(self, limit: int = 50, risk_level: Optional[str] = None, is_whitelisted: bool = False) -> List[dict]:
        """
        Recupera amenazas de la BD.
        
        Args:
            limit: Cantidad máxima de resultados
            risk_level: Filtrar por nivel (safe, suspicious, dangerous)
            is_whitelisted: Si True, solo muestra whitelist. Si False, solo no-whitelist
        
        Returns:
            Lista de amenazas
        """
        try:
            cursor = self.conn.cursor()
            
            query = 'SELECT * FROM threats WHERE is_whitelisted = ? '
            params = [1 if is_whitelisted else 0]
            
            if risk_level:
                query += 'AND risk_level = ? '
                params.append(risk_level)
            
            query += 'ORDER BY analyzed_at DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            threats = []
            for row in rows:
                threat = dict(row)
                threat['indicators'] = json.loads(threat.get('indicators', '[]'))
                threats.append(threat)
            
            return threats
        
        except Exception as e:
            logger.error(f"Error recuperando amenazas: {e}")
            return []
    
    def get_threat_by_id(self, threat_id: int) -> Optional[dict]:
        """Obtiene una amenaza específica por ID"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM threats WHERE id = ?', (threat_id,))
            row = cursor.fetchone()
            
            if row:
                threat = dict(row)
                threat['indicators'] = json.loads(threat.get('indicators', '[]'))
                return threat
            return None
        
        except Exception as e:
            logger.error(f"Error obteniendo amenaza: {e}")
            return None
    
    def get_threat_by_gmail_id(self, gmail_message_id: str) -> Optional[dict]:
        """Obtiene una amenaza por su ID en Gmail"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                'SELECT * FROM threats WHERE gmail_message_id = ?',
                (gmail_message_id,)
            )
            row = cursor.fetchone()
            
            if row:
                threat = dict(row)
                threat['indicators'] = json.loads(threat.get('indicators', '[]'))
                return threat
            return None
        
        except Exception as e:
            logger.error(f"Error obteniendo amenaza: {e}")
            return None
    
    def mark_as_whitelisted(self, threat_id: int, reason: str = "") -> bool:
        """Marca una amenaza como segura (whitelist)"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                'UPDATE threats SET is_whitelisted = 1, user_action = ? WHERE id = ?',
                (reason or "Marcado como seguro por usuario", threat_id)
            )
            self.conn.commit()
            logger.info(f"Amenaza {threat_id} añadida a whitelist")
            return True
        except Exception as e:
            logger.error(f"Error actualizando amenaza: {e}")
            return False
    
    def mark_as_confirmed_threat(self, threat_id: int) -> bool:
        """Marca una amenaza como confirmada por el usuario"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                'UPDATE threats SET user_action = ? WHERE id = ?',
                ("Confirmada como amenaza por usuario", threat_id)
            )
            self.conn.commit()
            logger.info(f"Amenaza {threat_id} confirmada")
            return True
        except Exception as e:
            logger.error(f"Error actualizando amenaza: {e}")
            return False
    
    def block_sender(self, sender: str, reason: str = "") -> bool:
        """Bloquea un remitente"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                'INSERT OR REPLACE INTO blocked_senders (sender, reason) VALUES (?, ?)',
                (sender, reason or "Bloqueado manualmente")
            )
            self.conn.commit()
            logger.info(f"Remitente bloqueado: {sender}")
            return True
        except Exception as e:
            logger.error(f"Error bloqueando remitente: {e}")
            return False
    
    def is_sender_blocked(self, sender: str) -> bool:
        """Verifica si un remitente está bloqueado"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT id FROM blocked_senders WHERE sender = ?', (sender,))
            return cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Error verificando remitente bloqueado: {e}")
            return False
    
    def get_statistics(self) -> dict:
        """Obtiene estadísticas de amenazas"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('SELECT COUNT(*) as total FROM threats')
            total = cursor.fetchone()['total']
            
            cursor.execute('SELECT COUNT(*) as dangerous FROM threats WHERE risk_level = ?', ('dangerous',))
            dangerous = cursor.fetchone()['dangerous']
            
            cursor.execute('SELECT COUNT(*) as suspicious FROM threats WHERE risk_level = ?', ('suspicious',))
            suspicious = cursor.fetchone()['suspicious']
            
            cursor.execute('SELECT COUNT(*) as safe FROM threats WHERE risk_level = ?', ('safe',))
            safe = cursor.fetchone()['safe']
            
            cursor.execute('''
                SELECT threat_category, COUNT(*) as count 
                FROM threats 
                GROUP BY threat_category 
                ORDER BY count DESC
            ''')
            categories = {row['threat_category']: row['count'] for row in cursor.fetchall()}
            
            return {
                'total': total,
                'dangerous': dangerous,
                'suspicious': suspicious,
                'safe': safe,
                'categories': categories
            }
        
        except Exception as e:
            logger.error(f"Error obteniendo estadísticas: {e}")
            return {}
    
    def close(self):
        """Cierra la conexión a la BD"""
        if self.conn:
            self.conn.close()
            logger.info("Conexión a BD cerrada")
