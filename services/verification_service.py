from utils.url_utils import extract_domain


class VerificationService:
    def __init__(self):
        # Sample lists - replace with real data sources
        self.blacklist = ["example-malicious-site.com", "phishing.com"]
        self.whitelist = ["trusted-news-site.com", "official-government.com"]

    def verify_url(self, url):
        """Verify if a URL is safe, malicious, or unknown."""
        domain = extract_domain(url)

        if domain in self.blacklist:
            return "malicious"
        elif domain in self.whitelist:
            return "safe"
        else:
            return "unknown"

    def add_to_blacklist(self, domain):
        """Add a domain to the blacklist."""
        if domain not in self.blacklist:
            self.blacklist.append(domain)

    def add_to_whitelist(self, domain):
        """Add a domain to the whitelist."""
        if domain not in self.whitelist:
            self.whitelist.append(domain)
