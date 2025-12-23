# Komnot Detection

A security gateway for URL verification using Python and Flask.

## Overview

This project creates a web gateway that automatically checks URLs for security threats. When you browse the web through this gateway, it analyzes each URL to determine if it's safe or potentially malicious. Safe URLs are forwarded automatically, while suspicious URLs show a confirmation page asking if you want to proceed.

## Features

- **Automatic URL Analysis**: Checks URLs against blacklists, whitelists, and ML models
- **Machine Learning Integration**: Uses trained models for enhanced detection
- **Interactive Gateway**: Web interface for manual URL checking
- **Proxy Functionality**: Can be configured as a browser proxy
- **Security Warnings**: Clear alerts for potentially dangerous sites

## Project Structure

- `gateway.py`: Main gateway application (recommended)
- `app.py`: Original API-only version
- `models/`: Machine learning models and data processing
- `services/`: Business logic for URL verification
- `data/`: Datasets for training and testing
- `utils/`: Utility functions for URL parsing and feature extraction
- `tests/`: Unit and integration tests

## Getting Started

1. Install Python 3.8+
2. Clone the repository
3. **CRITICAL: Set up API keys securely (see Security section below)**
4. Install dependencies: `pip install -r requirements.txt`
5. Run the gateway: `python gateway.py`

## 🔐 Security - API Key Setup

**NEVER commit API keys to version control!** This is a critical security risk.

### Step-by-Step API Key Setup:

1. **Copy the example environment file:**

   ```bash
   cp .env.example .env
   ```

2. **Get your API keys:**

   - **Gemini API Key**: Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
   - **PhishTank API Key** (optional): Visit [PhishTank API Registration](https://phishtank.com/api_register.php)

3. **Edit `.env` file with your actual keys:**

   ```bash
   GEMINI_API_KEY=your_actual_gemini_key_here
   PHISHTANK_API_KEY=your_actual_phishtank_key_here
   ```

4. **Verify `.gitignore` includes `.env`:**
   - The `.gitignore` file already excludes `.env` files
   - Never remove this protection!

### What happens if API keys are missing:

- The system will use fallback sample data
- Gemini AI features will be disabled
- PhishTank API features will be disabled
- The application will still work with basic functionality

## Usage

### Option 1: Web Interface

1. Start the gateway: `python gateway.py`
2. Open http://127.0.0.1:5000 in your browser
3. Enter any URL to check it manually

### Option 2: Browser Proxy

1. Start the gateway: `python gateway.py`
2. Configure your browser to use `127.0.0.1:5000` as HTTP proxy
3. Browse normally - all URLs will be automatically checked

### Browser Proxy Setup

**Firefox:**

- Settings → Network Settings → Settings
- Manual proxy configuration
- HTTP Proxy: 127.0.0.1, Port: 5000

**Chrome:**

- Settings → Advanced → System → Open proxy settings
- LAN settings → Use a proxy server
- Address: 127.0.0.1, Port: 5000

## How It Works

1. **URL Analysis**: Each URL is checked against:

   - Blacklist (known malicious sites)
   - Whitelist (trusted sites)
   - Machine learning model (behavioral analysis)

2. **Decision Making**:

   - **Safe URLs**: Forwarded automatically without interruption
   - **Malicious URLs**: Show confirmation page with security warning
   - **Unknown URLs**: Analyzed by ML model if available

3. **User Control**: For suspicious URLs, users can choose to proceed or cancel

## API Endpoints (Legacy)

### Verify URL

POST /verify-url
Content-Type: application/json

```json
{
  "url": "https://example.com"
}
```

Response:

```json
{
"status": "safe" | "malicious" | "unknown"
}
```

## Advanced Data Collection

### Gemini AI Integration

The system now uses Google's Gemini AI to generate realistic malicious URLs for training:

```python
from data_collector import DataCollector

collector = DataCollector()

# Generate additional malicious URLs with Gemini
malicious_urls = collector.generate_malicious_urls_with_gemini(count=100)
```

**Setup Gemini API:**

1. Get API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create `.env` file: `GEMINI_API_KEY=your_key_here`
3. Install: `pip install google-generativeai python-dotenv`

### Alexa Top Sites Collection

Collect legitimate URLs from Alexa rankings for balanced training data:

```python
# Get top legitimate sites from Alexa
legitimate_urls = collector.get_alexa_top_sites_enhanced(limit=500)
```

### Enhanced Data Pipeline

Run the complete enhanced data collection pipeline:

```python
# Collect all data with AI assistance
dataset = collector.collect_all_data(
    phishtank_api_key=None,  # Use sample data if no API key
    limit=1000,
    use_gemini=True  # Enable AI-generated URLs
)
```

**Benefits:**

- **Faster Collection**: Gemini generates URLs in seconds
- **Better Quality**: AI creates realistic phishing patterns
- **Comprehensive Coverage**: Alexa provides diverse legitimate examples
- **Scalable**: Generate thousands of training URLs quickly

## Future Enhancements

- Real-time threat intelligence feeds
- Mobile app integration
- Advanced ML model architectures
- Browser extension integration
