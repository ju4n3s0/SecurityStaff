"""
Módulo para conectar y obtener correos de Gmail usando Google API
"""

import logging
import base64
import pickle
import os
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)


class GmailConnector:
    """Conector a Gmail API para obtener y procesar correos"""

    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
    
    def __init__(self, credentials_file: str = 'credentials.json', token_file: str = 'token.pickle'):
        """
        Inicializa la conexión a Gmail.
        
        Args:
            credentials_file: Archivo credentials.json descargado de Google Cloud Console
            token_file: Archivo para almacenar el token de acceso (se crea automáticamente)
        """
        self.credentials_file = credentials_file
        self.token_file = token_file
        self.service = None
        self._authenticate()
    
    def _authenticate(self):
        """Autentica con Google OAuth2"""
        creds = None
        
        # Si existe token almacenado, lo cargamos
        if os.path.exists(self.token_file):
            with open(self.token_file, 'rb') as token:
                creds = pickle.load(token)
                logger.info("Token cargado desde archivo")
        
        # Si no hay credenciales válidas, realizar flujo de autenticación
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                logger.info("Refrescando token expirado...")
                creds.refresh(Request())
            else:
                logger.info("Iniciando flujo de autenticación de Google...")
                if not os.path.exists(self.credentials_file):
                    raise FileNotFoundError(
                        f"Archivo '{self.credentials_file}' no encontrado.\n"
                        f"Descárgalo desde: https://console.cloud.google.com/ (OAuth 2.0 Client ID - Desktop)"
                    )
                
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.credentials_file,
                    self.SCOPES
                )
                creds = flow.run_local_server(port=0)
            
            # Guardartoken para futuras sesiones
            with open(self.token_file, 'wb') as token:
                pickle.dump(creds, token)
                logger.info(f"Token guardado en {self.token_file}")
        
        self.service = build('gmail', 'v1', credentials=creds)
        logger.info("✓ Conectado a Gmail API")
    
    def get_unread_emails(self, max_results: int = 10) -> list:
        """
        Obtiene los correos no leídos más recientes.
        
        Args:
            max_results: Cantidad máxima de correos a retornar
        
        Returns:
            Lista de IDs de correos
        """
        try:
            results = self.service.users().messages().list(
                userId='me',
                q='is:unread',
                maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            logger.info(f"Se encontraron {len(messages)} correos no leídos")
            return messages
        
        except Exception as e:
            logger.error(f"Error al obtener correos no leídos: {e}")
            return []
    
    def get_email_content(self, message_id: str) -> dict:
        """
        Extrae el contenido completo de un correo.
        
        Args:
            message_id: ID del correo en Gmail
        
        Returns:
            Diccionario con: from, subject, body, date
        """
        try:
            message = self.service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()
            
            headers = message['payload']['headers']
            body_data = self._extract_body(message['payload'])
            
            email_data = {
                'message_id': message_id,
                'from': self._get_header(headers, 'From'),
                'to': self._get_header(headers, 'To'),
                'subject': self._get_header(headers, 'Subject'),
                'date': self._get_header(headers, 'Date'),
                'body': body_data,
                'headers': headers
            }
            
            return email_data
        
        except Exception as e:
            logger.error(f"Error extrayendo contenido de correo {message_id}: {e}")
            return {}
    
    def _extract_body(self, payload: dict) -> str:
        """Extrae el cuerpo de texto del mensaje"""
        body = ""
        
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    if 'data' in part['body']:
                        body = base64.urlsafe_b64decode(
                            part['body']['data']
                        ).decode('utf-8')
                        break
        else:
            if 'body' in payload and 'data' in payload['body']:
                body = base64.urlsafe_b64decode(
                    payload['body']['data']
                ).decode('utf-8')
        
        return body.strip()
    
    @staticmethod
    def _get_header(headers: list, header_name: str) -> str:
        """Obtiene el valor de un header específico"""
        for header in headers:
            if header['name'] == header_name:
                return header['value']
        return ""
    
    def mark_as_read(self, message_id: str) -> bool:
        """
        Marca un correo como leído.
        
        Args:
            message_id: ID del correo
        
        Returns:
            True si fue exitoso
        """
        try:
            self.service.users().messages().modify(
                userId='me',
                id=message_id,
                body={'removeLabelIds': ['UNREAD']}
            ).execute()
            logger.info(f"Correo {message_id[:10]}... marcado como leído")
            return True
        except Exception as e:
            logger.error(f"Error al marcar como leído: {e}")
            return False
    
    def move_to_label(self, message_id: str, label_name: str) -> bool:
        """
        Mueve un correo a una etiqueta (carpeta).
        
        Args:
            message_id: ID del correo
            label_name: Nombre de la etiqueta (ej: "Malware", "Phishing")
        
        Returns:
            True si fue exitoso
        """
        try:
            # Obtener ID de la etiqueta por nombre
            labels_result = self.service.users().labels().list(userId='me').execute()
            labels = labels_result.get('labels', [])
            
            label_id = None
            for label in labels:
                if label['name'] == label_name:
                    label_id = label['id']
                    break
            
            if not label_id:
                logger.warning(f"Etiqueta '{label_name}' no encontrada")
                return False
            
            self.service.users().messages().modify(
                userId='me',
                id=message_id,
                body={'addLabelIds': [label_id]}
            ).execute()
            logger.info(f"Correo movido a {label_name}")
            return True
        
        except Exception as e:
            logger.error(f"Error al mover correo: {e}")
            return False
    
    def create_label(self, label_name: str) -> str:
        """
        Crea una nueva etiqueta en Gmail.
        
        Args:
            label_name: Nombre de la etiqueta
        
        Returns:
            ID de la etiqueta creada
        """
        try:
            label_body = {
                'name': label_name,
                'labelListVisibility': 'labelShow',
                'messageListVisibility': 'show'
            }
            
            result = self.service.users().labels().create(
                userId='me',
                body=label_body
            ).execute()
            
            logger.info(f"Etiqueta '{label_name}' creada con ID: {result['id']}")
            return result['id']
        
        except Exception as e:
            logger.error(f"Error al crear etiqueta: {e}")
            return ""
    
    def get_email_headers_only(self, message_id: str) -> dict:
        """
        Obtiene solo los headers de un correo (más rápido).
        
        Args:
            message_id: ID del correo
        
        Returns:
            Diccionario con: from, subject, date
        """
        try:
            message = self.service.users().messages().get(
                userId='me',
                id=message_id,
                format='metadata',
                metadataHeaders=['From', 'Subject', 'Date']
            ).execute()
            
            headers = message['payload']['headers']
            return {
                'from': self._get_header(headers, 'From'),
                'subject': self._get_header(headers, 'Subject'),
                'date': self._get_header(headers, 'Date'),
                'message_id': message_id
            }
        
        except Exception as e:
            logger.error(f"Error extrayendo headers: {e}")
            return {}
