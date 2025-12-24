from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # React ko allow karega

@app.route("/")
def home():
    return jsonify({
        "status": "Backend running",
        "message": "Python backend connected successfully 🚀"
    })

@app.route("/scan", methods=["POST"])
def scan_url():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL not provided"}), 400

    # TEMP RESULT (later real logic)
    result = {
        "url": url,
        "safe": False,
        "risk_score": 72,
        "reason": "Suspicious keywords detected"
    }

    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
