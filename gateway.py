from flask import Flask, jsonify, request, Response, render_template_string, redirect
import requests
from urllib.parse import urljoin, urlparse, quote, unquote
from services.verification_service import VerificationService
from models.url_classifier import URLClassifier
from utils.url_utils import extract_features, is_valid_url, load_urls_from_csv
import threading
import socket
import ssl

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


def check_url_status(url):
    """Check if URL is safe or malicious."""
    status = verification_service.verify_url(url)
    
    if status == "unknown" and url_classifier.is_trained:
        try:
            features = extract_features(url)
            ml_prediction = url_classifier.predict(features)
            status = "malicious" if ml_prediction == 1 else "safe"
        except Exception as e:
            print(f"ML prediction error: {e}")
            status = "unknown"
    
    return status


@app.route('/', methods=['GET'])
def gateway_home():
    """Show the gateway homepage with instructions."""
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>🛡️ Komnot URL Gateway</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 40px 20px;
            }
            .container { 
                max-width: 800px; 
                margin: 0 auto; 
                background: white; 
                padding: 40px; 
                border-radius: 20px; 
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }
            h1 { 
                color: #333; 
                text-align: center; 
                font-size: 32px;
                margin-bottom: 10px;
            }
            .subtitle {
                text-align: center;
                color: #666;
                margin-bottom: 30px;
                font-size: 16px;
            }
            .url-form { 
                margin: 30px 0; 
                background: #f8f9fa;
                padding: 30px;
                border-radius: 15px;
            }
            input[type="text"] { 
                width: 100%; 
                padding: 16px; 
                margin: 10px 0; 
                border: 2px solid #ddd; 
                border-radius: 10px; 
                font-size: 16px; 
                box-sizing: border-box;
                transition: border-color 0.3s;
            }
            input[type="text"]:focus {
                outline: none;
                border-color: #667eea;
            }
            button { 
                width: 100%; 
                padding: 16px 24px; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white; 
                border: none; 
                border-radius: 10px; 
                cursor: pointer; 
                font-size: 16px;
                font-weight: 600;
                transition: transform 0.2s, box-shadow 0.2s;
                box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
            }
            button:hover { 
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(102, 126, 234, 0.5);
            }
            .info { 
                background: linear-gradient(135deg, #e7f3ff 0%, #f0e7ff 100%);
                padding: 25px; 
                border-radius: 15px; 
                margin: 20px 0; 
                border-left: 5px solid #667eea;
            }
            .info-title {
                font-weight: 700;
                color: #333;
                margin-bottom: 15px;
                font-size: 18px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .info-list {
                list-style: none;
                padding: 0;
            }
            .info-list li {
                padding: 8px 0;
                padding-left: 30px;
                position: relative;
                color: #555;
            }
            .info-list li:before {
                content: "✓";
                position: absolute;
                left: 0;
                color: #667eea;
                font-weight: bold;
                font-size: 20px;
            }
            .warning-box {
                background: #fff3cd;
                border: 2px solid #ffc107;
                border-radius: 15px;
                padding: 25px;
                margin: 20px 0;
            }
            .warning-title {
                color: #856404;
                font-weight: 700;
                margin-bottom: 15px;
                font-size: 18px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .warning-text {
                color: #856404;
                line-height: 1.6;
            }
            .feature-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 30px 0;
            }
            .feature-card {
                background: white;
                padding: 25px;
                border-radius: 15px;
                border: 2px solid #e9ecef;
                text-align: center;
                transition: transform 0.2s, box-shadow 0.2s;
            }
            .feature-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            }
            .feature-icon {
                font-size: 40px;
                margin-bottom: 15px;
            }
            .feature-title {
                font-weight: 600;
                color: #333;
                margin-bottom: 10px;
            }
            .feature-desc {
                color: #666;
                font-size: 14px;
            }
            @media (max-width: 600px) {
                .container { padding: 25px; }
                h1 { font-size: 24px; }
                .feature-grid { grid-template-columns: 1fr; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Komnot URL Gateway</h1>
            <p class="subtitle">Your personal web security checkpoint</p>
            
            <form class="url-form" action="/check" method="GET">
                <input type="text" name="url" placeholder="Enter URL (e.g., http://example.com)" required>
                <button type="submit">🔍 Check & Visit URL</button>
            </form>

            <div class="feature-grid">
                <div class="feature-card">
                    <div class="feature-icon">🤖</div>
                    <div class="feature-title">AI-Powered</div>
                    <div class="feature-desc">Machine learning detects threats</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">⚡</div>
                    <div class="feature-title">Real-Time</div>
                    <div class="feature-desc">Instant URL analysis</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">🔒</div>
                    <div class="feature-title">Secure</div>
                    <div class="feature-desc">Blocks malicious sites</div>
                </div>
            </div>
            
            <div class="info">
                <div class="info-title">🎯 How It Works</div>
                <ul class="info-list">
                    <li>Enter any URL in the form above</li>
                    <li>Our AI analyzes it for threats</li>
                    <li>Safe URLs redirect automatically</li>
                    <li>Suspicious URLs show a warning page</li>
                </ul>
            </div>

            <div class="warning-box">
                <div class="warning-title">⚠️ Important Note</div>
                <div class="warning-text">
                    This gateway works best with the manual URL checker above. 
                    For browser-wide protection, please use the manual checker interface 
                    rather than configuring as a system proxy.
                </div>
            </div>
        </div>
    </body>
    </html>
    ''')


@app.route('/check', methods=['GET'])
def check_url():
    """Check a URL and either redirect or show warning."""
    target_url = request.args.get('url', '').strip()

    if not target_url:
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Error - Komnot Gateway</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
                .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
                h1 { color: #dc3545; }
                a { color: #007bff; text-decoration: none; font-weight: 600; }
                a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>❌ Error</h1>
                <p>No URL provided</p>
                <p><a href="/">← Go back to home</a></p>
            </div>
        </body>
        </html>
        '''), 400

    # Add http:// if no scheme
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    # Validate URL
    if not is_valid_url(target_url):
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Invalid URL - Komnot Gateway</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
                .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
                h1 { color: #dc3545; }
                a { color: #007bff; text-decoration: none; font-weight: 600; }
                a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>❌ Invalid URL</h1>
                <p><strong>{{ target_url }}</strong> is not a valid URL</p>
                <p><a href="/">← Go back to home</a></p>
            </div>
        </body>
        </html>
        ''', target_url=target_url), 400

    # Check URL safety
    status = check_url_status(target_url)

    # If malicious, show confirmation
    if status == "malicious":
        encoded_url = quote(target_url)
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>⚠️ Security Warning - Komnot Gateway</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .warning-container {
                    background: white;
                    max-width: 600px;
                    width: 100%;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    overflow: hidden;
                    animation: slideIn 0.4s ease-out;
                }
                @keyframes slideIn {
                    from { opacity: 0; transform: translateY(-20px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                .warning-header {
                    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                    padding: 40px 30px;
                    text-align: center;
                    color: white;
                }
                .warning-icon {
                    font-size: 64px;
                    margin-bottom: 15px;
                    animation: pulse 2s infinite;
                }
                @keyframes pulse {
                    0%, 100% { transform: scale(1); }
                    50% { transform: scale(1.1); }
                }
                .warning-header h1 {
                    font-size: 28px;
                    font-weight: 700;
                    margin-bottom: 10px;
                }
                .warning-header p {
                    font-size: 16px;
                    opacity: 0.95;
                }
                .warning-body {
                    padding: 40px 30px;
                }
                .url-display {
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 12px;
                    margin-bottom: 30px;
                    border-left: 4px solid #f5576c;
                }
                .url-label {
                    font-size: 12px;
                    font-weight: 600;
                    color: #6c757d;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    margin-bottom: 8px;
                }
                .url-text {
                    font-family: 'Courier New', monospace;
                    font-size: 14px;
                    color: #212529;
                    word-break: break-all;
                    line-height: 1.6;
                }
                .threat-info {
                    background: #fff3cd;
                    border: 1px solid #ffc107;
                    border-radius: 12px;
                    padding: 20px;
                    margin-bottom: 30px;
                }
                .threat-info h3 {
                    color: #856404;
                    font-size: 16px;
                    margin-bottom: 12px;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }
                .threat-info ul {
                    list-style: none;
                    padding-left: 0;
                }
                .threat-info li {
                    color: #856404;
                    font-size: 14px;
                    padding: 6px 0;
                    padding-left: 24px;
                    position: relative;
                }
                .threat-info li:before {
                    content: "⚠️";
                    position: absolute;
                    left: 0;
                }
                .button-group {
                    display: flex;
                    gap: 15px;
                    flex-direction: column;
                }
                .btn {
                    padding: 16px 24px;
                    border: none;
                    border-radius: 12px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    text-decoration: none;
                    text-align: center;
                    transition: all 0.3s ease;
                    display: block;
                }
                .btn-safe {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
                }
                .btn-safe:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.5);
                }
                .btn-danger {
                    background: white;
                    color: #667eea;
                    border: 2px solid #667eea;
                }
                .btn-danger:hover {
                    background: #f8f9fa;
                    transform: translateY(-2px);
                }
                @media (max-width: 600px) {
                    .warning-header h1 { font-size: 24px; }
                    .warning-body { padding: 30px 20px; }
                }
            </style>
        </head>
        <body>
            <div class="warning-container">
                <div class="warning-header">
                    <div class="warning-icon">🛡️</div>
                    <h1>Threat Detected</h1>
                    <p>This website may be dangerous</p>
                </div>
                <div class="warning-body">
                    <div class="url-display">
                        <div class="url-label">Flagged URL</div>
                        <div class="url-text">{{ target_url }}</div>
                    </div>
                    
                    <div class="threat-info">
                        <h3>⚠️ Potential Threats</h3>
                        <ul>
                            <li>Malware or virus distribution</li>
                            <li>Phishing or credential theft</li>
                            <li>Fraudulent or deceptive content</li>
                            <li>Data compromise risks</li>
                        </ul>
                    </div>
                    
                    <div class="button-group">
                        <a href="/" class="btn btn-safe">← Go Back to Safety</a>
                        <a href="/visit/{{ encoded_url }}" class="btn btn-danger">
                            Proceed Anyway (Not Recommended)
                        </a>
                    </div>
                </div>
            </div>
        </body>
        </html>
        ''', target_url=target_url, encoded_url=encoded_url)

    # If safe, redirect to the URL directly
    print(f"✓ Safe URL detected, redirecting to: {target_url}")
    return redirect(target_url)


@app.route('/visit/<path:url>', methods=['GET'])
def visit_url(url):
    """Redirect to URL after user confirms they want to visit a flagged site."""
    target_url = unquote(url)
    print(f"⚠ User proceeding to flagged URL: {target_url}")
    return redirect(target_url)


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "ml_model_trained": url_classifier.is_trained,
        "blacklist_count": len(verification_service.blacklist),
        "whitelist_count": len(verification_service.whitelist)
    }), 200


if __name__ == '__main__':
    print("\n" + "="*60)
    print("🛡️  Komnot URL Gateway Starting")
    print("="*60)
    print("\n📍 Access the gateway at: http://127.0.0.1:5000")
    print("\n💡 Usage:")
    print("   - Open http://127.0.0.1:5000 in your browser")
    print("   - Enter URLs manually for safety checking")
    print("   - Safe URLs redirect automatically")
    print("   - Malicious URLs show warning page")
    print("\n" + "="*60 + "\n")
    
    app.run(host='127.0.0.1', port=5000, debug=True)