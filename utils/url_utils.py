import re
from urllib.parse import urlparse
import pandas as pd


def extract_domain(url):
    """Extract the domain from a URL."""
    parsed = urlparse(url)
    return parsed.netloc


def extract_features(url):
    """Extract features from a URL for ML classification."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query

    # Known legitimate domains whitelist
    legitimate_domains = {
        'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
        'twitter.com', 'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
        'microsoft.com', 'apple.com', 'netflix.com', 'paypal.com', 'ebay.com',
        'reddit.com', 'whatsapp.com', 'telegram.org', 'discord.com', 'zoom.us',
        'slack.com', 'dropbox.com', 'onedrive.live.com', 'gmail.com', 'outlook.com',
        'yahoo.com', 'bing.com', 'duckduckgo.com', 'cnn.com', 'bbc.com', 'nytimes.com'
    }

    # Check if domain is in whitelist
    is_whitelisted = 1 if any(domain.endswith(
        '.' + legit) or domain == legit for legit in legitimate_domains) else 0

    features = [
        len(url),  # URL length
        1 if parsed.scheme == 'https' else 0,  # HTTPS
        len(domain),  # Domain length
        domain.count('.'),  # Number of dots in domain
        1 if re.search(r'[0-9]', domain) else 0,  # Has numbers in domain
        # Has hyphens/underscores in domain
        1 if re.search(r'[-_]', domain) else 0,
        len(path),  # Path length
        1 if query else 0,  # Has query parameters
        1 if re.search(r'(login|account|verify|password|bank|secure|update|alert)',
                       url.lower()) else 0,  # Suspicious keywords
        is_whitelisted,  # Is whitelisted legitimate domain
        # Additional suspicious patterns
        # Long number sequences in domain
        1 if re.search(r'\d{4,}', domain) else 0,
        1 if len(domain) > 50 else 0,  # Very long domain
        1 if domain.count('-') > 2 else 0,  # Multiple hyphens
        1 if re.search(r'(free|win|prize|lucky|gift)',
                       url.lower()) else 0,  # Common scam keywords
    ]
    return features


def is_valid_url(url):
    """Check if the URL is valid."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:  # noqa: E722
        return False


def load_urls_from_csv(filepath):
    """Load URLs and labels from CSV file."""
    df = pd.read_csv(filepath, header=None, names=['url', 'label'])
    urls = df['url'].tolist()
    labels = df['label'].tolist()
    return urls, labels
