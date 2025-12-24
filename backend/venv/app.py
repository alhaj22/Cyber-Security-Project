from flask import Flask, request, jsonify
from flask_cors import CORS

# 🔥 IMPORT YOUR CORE ANALYZER
from core import PhishRadarAnalyzer

app = Flask(__name__)
CORS(app)

# 🔥 CREATE SINGLE ANALYZER INSTANCE
analyzer = PhishRadarAnalyzer()

@app.route("/")
def home():
    return jsonify({
        "status": "Backend running",
        "engine": "PhishRadar",
        "version": "1.0.0"
    })

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url")
    deep_scan = data.get("deep_scan", True)

    if not url:
        return jsonify({"error": "URL missing"}), 400

    try:
        # 🔥 CORE CONNECTION HERE
        result = analyzer.analyze(url, deep_scan=deep_scan)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "error": "Analysis failed",
            "details": str(e)
        }), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
