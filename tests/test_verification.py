import pytest
from services.verification_service import VerificationService
from utils.url_utils import extract_domain, extract_features, is_valid_url


def test_extract_domain():
    assert extract_domain("https://example.com/path") == "example.com"
    assert extract_domain("http://sub.example.com") == "sub.example.com"


def test_extract_features():
    features = extract_features("https://example.com/login?user=admin")
    assert len(features) == 5  # Should return 5 features
    assert features[1] == 1  # HTTPS
    assert features[4] == 1  # Has suspicious word 'login'


def test_is_valid_url():
    assert is_valid_url("https://example.com") == True
    assert is_valid_url("not-a-url") == False


def test_verification_service():
    service = VerificationService()

    # Test blacklist
    assert service.verify_url(
        "https://example-malicious-site.com/path") == "malicious"

    # Test whitelist
    assert service.verify_url(
        "https://trusted-news-site.com/article") == "safe"

    # Test unknown
    assert service.verify_url("https://unknown-site.com") == "unknown"

    # Test adding to lists
    service.add_to_blacklist("new-malicious.com")
    assert service.verify_url("https://new-malicious.com") == "malicious"

    service.add_to_whitelist("new-trusted.com")
    assert service.verify_url("https://new-trusted.com") == "safe"
