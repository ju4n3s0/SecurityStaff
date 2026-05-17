from flask import Flask, request, jsonify
import os

from modules.analysis_service import AnalysisService
from modules.learning_service import LearningService
from flask import render_template

# ==========================================
# CONFIGURACIÓN DE LA APLICACIÓN
# ==========================================
app = Flask(__name__)

# Servicio principal de análisis
service = AnalysisService(
    api_key=os.getenv("GEMINI_API_KEY")
)

# Servicio del módulo de aprendizaje
learning_service = LearningService()


# ==========================================
# HOME / HEALTH CHECK
# ==========================================
@app.route("/", methods=["GET"])
def home():
    """
    Endpoint básico para verificar que la aplicación está activa.
    """
    return jsonify({
        "status": "Shield activo",
        "version": "1.0",
        "services": {
            "analysis": True,
            "learning": True
        }
    })


# ==========================================
# ANÁLISIS DE MENSAJES
# ==========================================
@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Analiza un email o SMS y devuelve:
    - Nivel de riesgo
    - Categoría de amenaza
    - Recomendaciones
    - Recomendaciones preventivas del módulo educativo
    """

    data = request.get_json(silent=True) or {}

    content = data.get("content")
    msg_type = data.get("type")
    sender = data.get("sender", "")
    subject = data.get("subject", "")

    if not content or not msg_type:
        return jsonify({
            "error": "Faltan datos obligatorios: content y type"
        }), 400

    # Ejecutar análisis principal
    result = service.analyze_message(
        content=content,
        msg_type=msg_type,
        sender=sender,
        subject=subject
    )

    # Si el resultado ya viene como dict
    if isinstance(result, dict):
        result_dict = result
    else:
        result_dict = result.to_dict()

    # Obtener threat_category
    threat_category = (
        result_dict
        .get("analysis", {})
        .get("threat_category", "none")
    )

    # Agregar recomendaciones educativas contextuales (CA1)
    result_dict["learning_recommendations"] = (
        learning_service.get_contextual_recommendations(
            threat_category
        )
    )

    return jsonify(result_dict)


# ==========================================
# HISTORIAL
# ==========================================
@app.route("/history", methods=["GET"])
def history():
    """
    Retorna todos los registros del historial.
    """
    return jsonify(service.history.get_all())


@app.route("/history/<int:record_id>", methods=["GET"])
def history_detail(record_id):
    """
    Retorna el detalle de un registro específico.
    """
    record = service.history.get_by_id(record_id)

    if not record:
        return jsonify({
            "error": "No encontrado"
        }), 404

    return jsonify(record)


@app.route("/history/<int:record_id>/false-positive", methods=["POST"])
def false_positive(record_id):
    """
    Marca un análisis como falso positivo.
    """
    success = service.history.mark_false_positive(record_id)

    return jsonify({
        "success": success
    })


# ==========================================
# MÓDULO DE APRENDIZAJE - LECCIÓN DIARIA
# ==========================================
@app.route("/api/learning/daily-lesson", methods=["GET"])
def get_daily_lesson():
    """
    Retorna la mini lección del día.
    """
    return jsonify(
        learning_service.get_daily_lesson()
    )


@app.route("/api/learning/complete-lesson", methods=["POST"])
def complete_lesson():
    """
    Marca una lección como completada.
    """
    data = request.get_json(silent=True) or {}

    lesson_id = data.get("lesson_id")

    if lesson_id is None:
        return jsonify({
            "error": "lesson_id es requerido"
        }), 400

    learning_service.complete_lesson(lesson_id)

    return jsonify({
        "success": True
    })


# ==========================================
# MÓDULO DE APRENDIZAJE - QUIZ
# ==========================================
@app.route("/api/learning/questions", methods=["GET"])
def get_questions():
    """
    Retorna la lista de preguntas de práctica.
    """
    return jsonify(
        learning_service.get_questions()
    )


@app.route("/api/learning/check-answer", methods=["POST"])
def check_answer():
    """
    Evalúa una respuesta del quiz.
    """
    data = request.get_json(silent=True) or {}

    question_id = data.get("question_id")
    selected_index = data.get("selected_index")

    if question_id is None or selected_index is None:
        return jsonify({
            "error": "question_id y selected_index son requeridos"
        }), 400

    result = learning_service.check_answer(
        question_id=question_id,
        selected_index=selected_index
    )

    return jsonify(result)


# ==========================================
# MÓDULO DE APRENDIZAJE - PROGRESO
# ==========================================
@app.route("/api/learning/progress", methods=["GET"])
def get_progress():
    """
    Retorna el progreso del usuario.
    """
    return jsonify(
        learning_service.get_progress()
    )


# ==========================================
# INICIO DE LA APLICACIÓN
# ==========================================
@app.route("/learning")
def learning_page():
    return render_template("learning.html")

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5002,
        debug=True
    )