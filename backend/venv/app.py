from flask import Flask, request, jsonify
from flask_cors import CORS

# 🔥 Import core analyzer
from core import PhishRadarAnalyzer

app = Flask(__name__)

# 🔥 Proper CORS config for React
CORS(
    app,
    resources={r"/*": {"origins": ["http://localhost:3000"]}},
    supports_credentials=True
)

# 🔥 Single analyzer instance (IMPORTANT)
analyzer = PhishRadarAnalyzer()


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "Backend running",
        "engine": "PhishRadar",
        "version": "1.0.0"
    })


@app.route("/scan", methods=["POST", "OPTIONS"])
def scan():
    # Handle preflight request
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    url = data.get("url")
    deep_scan = data.get("deep_scan", True)

    if not url:
        return jsonify({"error": "URL missing"}), 400

    try:
        # 🔥 Core engine call
        result = analyzer.analyze(url, deep_scan=deep_scan)
        return jsonify(result), 200

    except Exception as e:
        return jsonify({
            "error": "Analysis failed",
            "details": str(e)
        }), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
