from flask import Flask, request, jsonify
import os
from modules.analyzer import MessageAnalyzer

app = Flask(__name__)

# Analizador (Ollama)
analyzer = MessageAnalyzer(api_key='')  # API key not used with Ollama

# -------------------------
# ANALIZAR MENSAJE
# -------------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    if not data:
        return jsonify({"error": "No JSON data"}), 400

    content = data.get("content")
    msg_type = data.get("type", "sms")
    sender = data.get("sender", "")
    subject = data.get("subject", "")

    if not content or not msg_type:
        return jsonify({"error": "Faltan datos: content y type son requeridos"}), 400

    try:
        result = analyzer.analyze(content, msg_type, sender, subject)
        return jsonify(result.to_dict())
    except Exception as e:
        return jsonify({"error": f"Error interno: {str(e)}"}), 500


# -------------------------
# HEALTH CHECK
# -------------------------
@app.route("/")
def home():
    return jsonify({"status": "Shield activo (Ollama)", "analyzer_configured": analyzer._configured})


if __name__ == "__main__":
    app.run(port=5002, debug=True)