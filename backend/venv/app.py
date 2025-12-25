from flask import Flask, request, jsonify
from flask_cors import CORS
from core import PhishRadarAnalyzer

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

analyzer = PhishRadarAnalyzer()

def normalize_for_frontend(report: dict):
    """
    🔐 STRICT FRONTEND VERDICT NORMALIZATION
    """

    verdict = report.get("verdict")
    threat = report.get("threat_summary")

    if verdict == "INVALID":
        return {
            "url": report.get("url"),
            "status": "INVALID",
            "reason": "Invalid or malformed URL."
        }

    if verdict in ["CRITICAL", "HIGH"]:
        return {
            "url": report.get("url"),
            "status": "NOT SAFE",
            "reason": threat or "High-risk phishing indicators detected."
        }

    if verdict == "MEDIUM":
        return {
            "url": report.get("url"),
            "status": "SUSPICIOUS",
            "reason": threat or "Website shows suspicious behavior."
        }

    if verdict in ["LOW", "SAFE"]:
        return {
            "url": report.get("url"),
            "status": "SAFE",
            "reason": threat or "No significant phishing indicators detected."
        }

    # 🔥 FALLBACK (never call it SAFE)
    return {
        "url": report.get("url"),
        "status": "SUSPICIOUS",
        "reason": "Unable to confidently classify the website. Proceed with caution."
    }
    """
    🔐 SINGLE FRONTEND CONTRACT
    """
    verdict = report.get("verdict", "ERROR")

    verdict_map = {
        "SAFE": "SAFE",
        "LOW": "SAFE",
        "MEDIUM": "SUSPICIOUS",
        "HIGH": "NOT SAFE",
        "CRITICAL": "NOT SAFE",
        "INVALID": "INVALID",
        "ERROR": "ERROR"
    }

    return {
        "url": report.get("url"),
        "status": verdict_map.get(verdict, "SUSPICIOUS"),
        "reason": report.get("threat_summary", "No clear verdict available.")
    }

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({
            "status": "INVALID",
            "reason": "URL is required"
        }), 400

    raw_report = analyzer.analyze(data["url"])
    frontend_response = normalize_for_frontend(raw_report)

    return jsonify(frontend_response), 200

if __name__ == "__main__":
    app.run(debug=True, port=5000)