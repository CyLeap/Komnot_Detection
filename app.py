from flask import Flask, request, jsonify
from services.verification_service import VerificationService
from models.url_classifier import URLClassifier
from utils.url_utils import extract_features, is_valid_url

app = Flask(__name__)

# Initialize services
verification_service = VerificationService()
url_classifier = URLClassifier()

# Load and train ML model if data exists
try:
    from utils.url_utils import load_urls_from_csv
    urls, labels = load_urls_from_csv('data/sample_urls.csv')
    features = [extract_features(url) for url in urls]
    url_classifier.train(features, labels)
    print("ML model trained successfully.")
except FileNotFoundError:
    print("Sample data not found. ML model not trained.")


@app.route('/verify-url', methods=['POST'])
def verify_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data['url']

    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL format"}), 400

    # First, check with traditional method
    status = verification_service.verify_url(url)

    # If unknown and ML model is trained, use ML prediction
    if status == "unknown" and url_classifier.is_trained:
        features = extract_features(url)
        ml_prediction = url_classifier.predict(features)
        status = "malicious" if ml_prediction == 1 else "safe"

    return jsonify({"status": status}), 200


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"}), 200


if __name__ == '__main__':
    app.run(debug=True)
