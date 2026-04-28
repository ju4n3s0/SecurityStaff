from flask import Flask, request, jsonify
import os
from modules.analysis_service import AnalysisService

app = Flask(__name__)

service = AnalysisService(api_key=os.getenv("GEMINI_API_KEY"))

# -------------------------
# ANALIZAR MENSAJE
# -------------------------
@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.json

    content = data.get("content")
    msg_type = data.get("type")
    sender = data.get("sender", "")
    subject = data.get("subject", "")

    if not content or not msg_type:
        return jsonify({"error": "Faltan datos"}), 400

    result = service.analyze_message(content, msg_type, sender, subject)

    return jsonify(result)


# -------------------------
# HISTORIAL
# -------------------------
@app.route("/history", methods=["GET"])
def history():
    return jsonify(service.history.get_all())


@app.route("/history/<int:id>", methods=["GET"])
def history_detail(id):
    record = service.history.get_by_id(id)
    if not record:
        return jsonify({"error": "No encontrado"}), 404
    return jsonify(record)


@app.route("/history/<int:id>/false-positive", methods=["POST"])
def false_positive(id):
    ok = service.history.mark_false_positive(id)
    return jsonify({"success": ok})


# -------------------------
# HEALTH CHECK
# -------------------------
@app.route("/")
def home():
    return jsonify({"status": "Shield activo"})


if __name__ == "__main__":
    app.run(port=5002, debug=True)