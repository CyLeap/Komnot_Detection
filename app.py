from flask import Flask, request, jsonify, Response, render_template_string
import requests
from urllib.parse import urlparse
from services.verification_service import VerificationService
from models.url_classifier import URLClassifier
from utils.url_utils import extract_features, is_valid_url, load_urls_from_csv
from utils.translation_utils import translate_to_khmer

app = Flask(__name__)

# Initialize services
verification_service = VerificationService()
url_classifier = URLClassifier()

# Load and train ML model if data exists
try:
    urls, labels = load_urls_from_csv('data/sample_urls.csv')
    features = [extract_features(url) for url in urls]
    url_classifier.train(features, labels)
    print("ML model trained successfully.")
except FileNotFoundError:
    print("Sample data not found. ML model not trained.")


# Catch-all route for proxy functionality
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def proxy(path):
    # Get the target URL from query parameter or form data
    target_url = request.args.get('url') or request.form.get('url')

    # Check if this is a direct proxy request (browser sending URL as path)
    if not target_url and path.startswith(('http://', 'https://')):
        target_url = path
    # Check if this is a browser proxy request (no url parameter, has host header)
    elif not target_url and 'Host' in request.headers and path:
        # Reconstruct URL from Host header and path
        host = request.headers.get('Host')
        if host:
            scheme = 'https' if request.headers.get(
                'X-Forwarded-Proto') == 'https' else 'http'
            if path.startswith('/'):
                target_url = f"{scheme}://{host}{path}"
            else:
                target_url = f"{scheme}://{host}/{path}"

    if not target_url:
        # If no URL provided, show the gateway interface
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>កំណត់់ URL Gateway</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
                .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color: #333; text-align: center; }
                .url-form { margin: 20px 0; }
                input[type="text"] { width: 100%; padding: 12px; margin: 10px 0; border: 2px solid #ddd; border-radius: 5px; font-size: 16px; }
                button { padding: 12px 24px; background-color: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
                button:hover { background-color: #0056b3; }
                .info { background-color: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #007bff; }
                .warning { background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ កំណត់ URL Gateway</h1>
                <div class="info">
                    <strong>វិធីសាស្ត្រដំណើរការ:</strong><br>
                    • បញ្ចូល URL ណាមួយដើម្បីពិនិត្យមើលថាតើវាមានសុវត្ថិភាពទេ<br>
                    • URL ដែលមានសុវត្ថិភាពនឹងត្រូវបានបញ្ជូនដោយស្វ័យប្រវត្តិ<br>
                    • URL ដែលសង្ស័យនឹងបង្ហាញទំព័របញ្ជាក់
                </div>
                <form class="url-form" action="/" method="GET">
                    <input type="text" name="url" placeholder="https://example.com" required>
                    <button type="submit">ពិនិត្យ និងចូលមើល</button>
                </form>
                <div class="warning">
                    <strong>ចំណាំ:</strong> ច្រកចេញចូលនេះវិភាគ URL សម្រាប់ការគំរាមកំហែងសុវត្ថិភាពដែលអាចមានដោយប្រើម៉ាស៊ីនរៀន និងវិធីសាស្ត្រប្រពៃណី។
                </div>
            </div>
        </body>
        </html>
        ''')

    # Validate URL format
    if not is_valid_url(target_url):
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>URL មិនត្រឹមត្រូវ - Komnot Gateway</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background-color: #f8d7da; }
                .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; border: 2px solid #dc3545; }
                h1 { color: #dc3545; }
                .error { color: #721c24; }
                button { padding: 10px 20px; background-color: #6c757d; color: white; border: none; border-radius: 5px; cursor: pointer; }
                button:hover { background-color: #545b62; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>❌ ទម្រង់ URL មិនត្រឹមត្រូវ</h1>
                <p class="error">URL ដែលអ្នកបានបញ្ចូលមិនត្រឹមត្រូវទេ: <strong>{{ target_url }}</strong></p>
                <p>សូមពិនិត្យ URL ឡើងវិញ ហើយព្យាយាមម្តងទៀត។</p>
                <button onclick="window.history.back()">ត្រឡប់ក្រោយ</button>
            </div>
        </body>
        </html>
        ''', target_url=target_url), 400

    # Check URL safety
    status = verification_service.verify_url(target_url)

    # If unknown and ML model is trained, use ML prediction
    if status == "unknown" and url_classifier.is_trained:
        try:
            features = extract_features(target_url)
            ml_prediction = url_classifier.predict(features)
            status = "malicious" if ml_prediction == 1 else "safe"
        except Exception as e:
            print(f"ML prediction error: {e}")
            status = "unknown"

    # If malicious, show confirmation page
    if status == "malicious":
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>⚠️ ការព្រមានសុវត្ថិភាព - Komnot Gateway</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background-color: #f8d7da; }
                .container { max-width: 700px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; border: 3px solid #dc3545; }
                h1 { color: #dc3545; }
                .warning { background-color: #f8d7da; padding: 20px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #dc3545; }
                .url-display { background-color: #f1f1f1; padding: 10px; border-radius: 3px; font-family: monospace; word-break: break-all; }
                .buttons { margin-top: 30px; text-align: center; }
                .btn-safe { padding: 12px 24px; background-color: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; margin: 0 10px; }
                .btn-danger { padding: 12px 24px; background-color: #dc3545; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; margin: 0 10px; }
                .btn-danger:hover { background-color: #c82333; }
                .btn-safe:hover { background-color: #218838; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🚨 ការព្រមានសុវត្ថិភាព</h1>
                <div class="warning">
                    <strong>URL នេះត្រូវបានចាត់ទុកថាអាចមានគំរាមកំហែង!</strong><br><br>
                    <strong>URL:</strong> <span class="url-display">{{ target_url }}</span><br><br>
                    ការវិភាគរបស់យើងបង្ហាញថាតំបន់បណ្តាញនេះអាចមាន malware, phishing, ឬការគំរាមកំហែងសុវត្ថិភាពផ្សេងទៀត។
                </div>
                <div class="buttons">
                    <button class="btn-danger" onclick="window.history.back()">បោះបង់ - ត្រឡប់ក្រោយ</button>
                    <form action="/proxy" method="POST" style="display: inline;">
                        <input type="hidden" name="url" value="{{ target_url }}">
                        <input type="hidden" name="confirmed" value="true">
                        <button type="submit" class="btn-safe">ខ្ញុំយល់ពីហានិភ័យ - បន្តទៀត</button>
                    </form>
                </div>
            </div>
        </body>
        </html>
        ''', target_url=target_url)

    # If safe or confirmed malicious, proxy the request
    try:
        # Prepare the request to forward
        url_parts = urlparse(target_url)
        if not url_parts.scheme:
            target_url = 'http://' + target_url

        # Forward the request
        headers = dict(request.headers)
        # Remove host header as it should be the target's host
        headers.pop('Host', None)

        # Handle different HTTP methods
        if request.method == 'GET':
            resp = requests.get(target_url, headers=headers,
                                params=request.args, allow_redirects=False)
        elif request.method == 'POST':
            if request.is_json:
                resp = requests.post(
                    target_url, headers=headers, json=request.get_json(), allow_redirects=False)
            else:
                resp = requests.post(
                    target_url, headers=headers, data=request.form, allow_redirects=False)
        elif request.method == 'PUT':
            resp = requests.put(target_url, headers=headers,
                                data=request.data, allow_redirects=False)
        elif request.method == 'DELETE':
            resp = requests.delete(
                target_url, headers=headers, allow_redirects=False)
        elif request.method == 'PATCH':
            resp = requests.patch(
                target_url, headers=headers, data=request.data, allow_redirects=False)
        elif request.method == 'HEAD':
            resp = requests.head(
                target_url, headers=headers, allow_redirects=False)
        elif request.method == 'OPTIONS':
            resp = requests.options(
                target_url, headers=headers, allow_redirects=False)
        else:
            return jsonify({"error": "Unsupported HTTP method"}), 405

        # Create response
        response = Response(resp.content, resp.status_code)

        # Copy response headers
        for header, value in resp.headers.items():
            if header.lower() not in ['content-encoding', 'transfer-encoding']:
                response.headers[header] = value

        return response

    except requests.RequestException as e:
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>កំហុសក្នុងការតភ្ជាប់ - Komnot Gateway</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background-color: #f8d7da; }
                .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; border: 2px solid #dc3545; }
                h1 { color: #dc3545; }
                .error { color: #721c24; }
                button { padding: 10px 20px; background-color: #6c757d; color: white; border: none; border-radius: 5px; cursor: pointer; }
                button:hover { background-color: #545b62; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>❌ កំហុសក្នុងការតភ្ជាប់</h1>
                <p class="error">មិនអាចតភ្ជាប់ទៅ: <strong>{{ target_url }}</strong></p>
                <p>កំហុស: {{ error }}</p>
                <button onclick="window.history.back()">ត្រឡប់ក្រោយ</button>
            </div>
        </body>
        </html>
        ''', target_url=target_url, error=str(e)), 502


# Special route for confirmed malicious URLs
@app.route('/proxy', methods=['POST'])
def proxy_confirmed():
    target_url = request.form.get('url')
    confirmed = request.form.get('confirmed')

    if not target_url or confirmed != 'true':
        return jsonify({"error": "Invalid request"}), 400

    # Redirect to the main proxy with the confirmed URL
    from flask import redirect
    return redirect(f'/?url={target_url}&confirmed=true')


if __name__ == '__main__':
    app.run(debug=True)
