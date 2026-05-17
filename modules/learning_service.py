from datetime import date
from modules.learning_data import LESSONS, QUESTIONS


class LearningService:
    """
    Servicio encargado del módulo de aprendizaje sobre phishing.

    Funcionalidades:
    - Lección diaria
    - Registro de lecciones completadas
    - Preguntas de práctica
    - Validación de respuestas
    - Seguimiento del progreso
    - Recomendaciones preventivas contextuales
    """

    def __init__(self):
        # Progreso del usuario almacenado en memoria
        # (suficiente para el proyecto del curso)
        self.user_progress = {
            "completed_lessons": [],
            "completed_questions": [],
            "last_daily_lesson_date": None,
        }

    # ==========================================================
    # LECCIÓN DIARIA
    # ==========================================================
    def get_daily_lesson(self):
        """
        Retorna la lección correspondiente al día actual.
        Si el usuario ya la vio hoy, la marca como ya visualizada.
        """
        today = str(date.today())

        if not LESSONS:
            return {
                "error": "No hay lecciones disponibles."
            }

        # Seleccionar lección del día
        lesson_index = date.today().toordinal() % len(LESSONS)
        lesson = LESSONS[lesson_index].copy()

        lesson["already_viewed"] = (
            self.user_progress["last_daily_lesson_date"] == today
        )

        return lesson

    # ==========================================================
    # COMPLETAR LECCIÓN
    # ==========================================================
    def complete_lesson(self, lesson_id):
        """
        Marca una lección como completada.
        """
        if lesson_id not in self.user_progress["completed_lessons"]:
            self.user_progress["completed_lessons"].append(lesson_id)

        self.user_progress["last_daily_lesson_date"] = str(date.today())

    # ==========================================================
    # OBTENER PREGUNTAS
    # ==========================================================
    def get_questions(self):
        """
        Retorna todas las preguntas de práctica.
        """
        return QUESTIONS

    # ==========================================================
    # VALIDAR RESPUESTA
    # ==========================================================
    def check_answer(self, question_id, selected_index):
        """
        Valida la respuesta de una pregunta.
        """
        question = next(
            (q for q in QUESTIONS if q["id"] == question_id),
            None
        )

        if question is None:
            return {
                "success": False,
                "error": "Pregunta no encontrada."
            }

        is_correct = selected_index == question["correct_answer"]

        # Registrar pregunta completada
        if question_id not in self.user_progress["completed_questions"]:
            self.user_progress["completed_questions"].append(question_id)

        return {
            "success": True,
            "correct": is_correct,
            "correct_answer": question["correct_answer"],
            "explanation": question["explanation"],
            "message": (
                "¡Excelente! Respuesta correcta."
                if is_correct
                else "Respuesta incorrecta."
            ),
        }

    # ==========================================================
    # PROGRESO
    # ==========================================================
    def get_progress(self):
        """
        Retorna el progreso del usuario.
        """
        completed_lessons = len(
            self.user_progress["completed_lessons"]
        )

        total_lessons = len(LESSONS)

        percentage = (
            round((completed_lessons / total_lessons) * 100)
            if total_lessons > 0
            else 0
        )

        if percentage == 0:
            motivational_message = (
                "¡Comienza hoy! Cada lección te ayuda a protegerte del phishing."
            )
        elif percentage < 50:
            motivational_message = (
                "¡Buen comienzo! Sigue aprendiendo."
            )
        elif percentage < 100:
            motivational_message = (
                "¡Excelente progreso! Ya sabes identificar muchas amenazas."
            )
        else:
            motivational_message = (
                "¡Felicitaciones! Completaste todas las lecciones."
            )

        return {
            "completed_lessons": completed_lessons,
            "total_lessons": total_lessons,
            "percentage": percentage,
            "motivational_message": motivational_message,
        }

    # ==========================================================
    # RECOMENDACIONES CONTEXTUALES
    # ==========================================================
    def get_contextual_recommendations(self, threat_category):
        """
        Retorna recomendaciones preventivas según la categoría de amenaza.
        """
        recommendations = {
            "phishing": [
                "Verifica directamente con la entidad oficial.",
                "No ingreses tus credenciales en enlaces sospechosos.",
                "Revisa cuidadosamente el dominio del remitente."
            ],
            "fraud": [
                "Desconfía de premios inesperados.",
                "No compartas información personal.",
                "Confirma la información por canales oficiales."
            ],
            "malware": [
                "No descargues archivos adjuntos desconocidos.",
                "Mantén actualizado tu antivirus.",
                "Escanea cualquier archivo antes de abrirlo."
            ],
            "spam": [
                "Ignora mensajes promocionales sospechosos.",
                "No hagas clic en enlaces no solicitados."
            ],
            "social_engineering": [
                "No actúes bajo presión.",
                "Verifica la identidad del remitente."
            ],
        }

        return recommendations.get(
            threat_category,
            [
                "Analiza cuidadosamente el mensaje antes de interactuar.",
                "Verifica la información con fuentes oficiales."
            ],
        )