# =====================================================================
# SOLUCIÓN DEFINITIVA
# =====================================================================
# El problema es que Python sigue importando el módulo
# modules.learning_service en lugar de la clase LearningService.
#
# REEMPLAZA LAS PRIMERAS LÍNEAS DE app.py POR ESTO EXACTAMENTE.
# =====================================================================
from modules.learning_service import LearningService
from flask import Flask, request, jsonify, render_template
import os

from modules.analysis_service import AnalysisService

# =====================================================================
# INSTANCIAS DE SERVICIOS
# =====================================================================

app = Flask(__name__)

service = AnalysisService(
    api_key=os.getenv("GEMINI_API_KEY")
)

# IMPORTANTE: instancia de la clase, NO del módulo
learning_service = LearningService()



# =====================================================================
# RUTA PRINCIPAL
# =====================================================================

@app.route("/")
def home():
    return render_template("index.html")


# =====================================================================
# HEALTH CHECK
# =====================================================================

@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "message": "Security Staff funcionando correctamente"
    })


# =====================================================================
# PÁGINA DEL MÓDULO DE APRENDIZAJE
# =====================================================================

@app.route("/learning")
def learning_page():
    return render_template("learning.html")


# =====================================================================
# API - LECCIÓN DIARIA
# =====================================================================

@app.route("/api/learning/daily-lesson", methods=["GET"])
def api_daily_lesson():
    return jsonify(learning_service.get_daily_lesson())


# =====================================================================
# API - MARCAR LECCIÓN COMO COMPLETADA
# =====================================================================

@app.route("/api/learning/complete-lesson", methods=["POST"])
def api_complete_lesson():
    data = request.get_json() or {}
    lesson_id = data.get("lesson_id")

    if lesson_id is None:
        return jsonify({
            "success": False,
            "error": "lesson_id es requerido"
        }), 400

    learning_service.complete_lesson(lesson_id)

    return jsonify({
        "success": True
    })


# =====================================================================
# API - PREGUNTAS DE PRÁCTICA
# =====================================================================

@app.route("/api/learning/questions", methods=["GET"])
def api_questions():
    return jsonify(learning_service.get_questions())


# =====================================================================
# API - VALIDAR RESPUESTA
# =====================================================================

@app.route("/api/learning/check-answer", methods=["POST"])
def api_check_answer():
    data = request.get_json() or {}

    question_id = data.get("question_id")
    selected_option = data.get("selected_option")

    if question_id is None or selected_option is None:
        return jsonify({
            "success": False,
            "error": "question_id y selected_option son requeridos"
        }), 400

    result = learning_service.check_answer(
        question_id,
        selected_option
    )

    return jsonify(result)


# =====================================================================
# API - PROGRESO
# =====================================================================

@app.route("/api/learning/progress", methods=["GET"])
def api_progress():
    return jsonify(learning_service.get_progress())


# =====================================================================
# API - ANALIZAR MENSAJE
# =====================================================================

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json() or {}

    content = data.get("content")
    msg_type = data.get("type")
    sender = data.get("sender", "")
    subject = data.get("subject", "")

    if not content or not msg_type:
        return jsonify({
            "error": "Faltan datos"
        }), 400

    result = service.analyze_message(
        content,
        msg_type,
        sender,
        subject
    )

    return jsonify(result)


# =====================================================================
# HISTORIAL
# =====================================================================

@app.route("/history", methods=["GET"])
def history():
    return jsonify(service.history.get_all())


@app.route("/history/<int:record_id>", methods=["GET"])
def history_detail(record_id):
    record = service.history.get_by_id(record_id)

    if not record:
        return jsonify({
            "error": "No encontrado"
        }), 404

    return jsonify(record)


@app.route("/history/<int:record_id>/false-positive", methods=["POST"])
def false_positive(record_id):
    ok = service.history.mark_false_positive(record_id)

    return jsonify({
        "success": ok
    })


# =====================================================================
# EJECUCIÓN
# =====================================================================

if __name__ == "__main__":
    print("""
======================================
SECURITY STAFF - Detector Mensajes
     Maliciosos con Gemini AI
======================================

> Servidor iniciado en http://localhost:5002
> API Key configurada: {}
""".format(
        "Sí" if os.getenv("GEMINI_API_KEY") else "No (configura GEMINI_API_KEY)"
    ))

    app.run(
        host="0.0.0.0",
        port=5002,
        debug=True
    )