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
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query

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
        1 if re.search(r'(login|account|verify|password|bank)',
                       url.lower()) else 0  # Suspicious keywords
    ]
    return features


def is_valid_url(url):
    """Check if the URL is valid."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def load_urls_from_csv(filepath):
    """Load URLs and labels from CSV file."""
    df = pd.read_csv(filepath)
    urls = df['url'].tolist()
    labels = df['label'].tolist()
    return urls, labels
