from datetime import date

    def check_answer(self, question_id, selected_index):
        question = next(q for q in QUIZ_QUESTIONS if q["id"] == question_id)

        is_correct = selected_index == question["correct_answer"]

        if question_id not in self.user_progress["completed_questions"]:
            self.user_progress["completed_questions"].append(question_id)

        return {
            "correct": is_correct,
            "correct_answer": question["correct_answer"],
            "explanation": question["explanation"],
            "message": (
                "¡Excelente! Respuesta correcta."
                if is_correct
                else "Respuesta incorrecta."
            ),
        }

    # -----------------------------
    # Progreso
    # -----------------------------
    def get_progress(self):
        completed = len(self.user_progress["completed_lessons"])
        total = len(LESSONS)
        percentage = round((completed / total) * 100) if total else 0

        if percentage == 0:
            motivational_message = (
                "¡Comienza hoy! Cada lección te ayuda a protegerte del phishing."
            )
        else:
            motivational_message = None

        return {
            "completed_lessons": completed,
            "total_lessons": total,
            "percentage": percentage,
            "motivational_message": motivational_message,
        }

    # -----------------------------
    # Recomendaciones contextuales
    # -----------------------------
    def get_contextual_recommendations(self, threat_category):
        recommendations = {
            "phishing": [
                "Verifica directamente con la entidad oficial.",
                "No ingreses tus credenciales en enlaces sospechosos.",
            ],
            "fraud": [
                "Desconfía de premios inesperados.",
                "No compartas información personal.",
            ],
            "malware": [
                "No descargues archivos adjuntos desconocidos.",
                "Mantén actualizado tu antivirus.",
            ],
        }

        return recommendations.get(
            threat_category,
            ["Analiza cuidadosamente el mensaje antes de interactuar."],
        )