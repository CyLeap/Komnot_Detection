import requests
import pandas as pd
from bs4 import BeautifulSoup
import os
from urllib.parse import urlparse
import google.genai as genai
from dotenv import load_dotenv


class DataCollector:
    def __init__(self):
        self.data_dir = 'data'
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

        # Load environment variables for Gemini API
        load_dotenv()
        self.gemini_api_key = os.getenv('GEMINI_API_KEY')
        if self.gemini_api_key:
            self.gemini_client = genai.Client(api_key=self.gemini_api_key)
        else:
            self.gemini_client = None

    def download_phishtank_csv(self, api_key=None):
        """
        Download verified phishing URLs from PhishTank API
        If API key is not provided or fails, use fallback sample data
        """
        if api_key and api_key != "your_phishtank_api_key_here":
            url = "https://data.phishtank.com/data/online-valid.csv"
            headers = {
                "User-Agent": "Komnot-Detection/1.0",
                "Authorization": f"Bearer {api_key}"
            }

            print("Attempting to download PhishTank data with API key...")
            try:
                response = requests.get(url, headers=headers, timeout=30)

                if response.status_code == 200:
                    filepath = os.path.join(
                        self.data_dir, 'phishtank_urls.csv')
                    with open(filepath, 'wb') as f:
                        f.write(response.content)

                    # Load and process CSV
                    df = pd.read_csv(filepath, low_memory=False)
                    malicious_urls = df['url'].dropna().tolist()

                    print(
                        f"Downloaded {len(malicious_urls)} malicious URLs from PhishTank")
                    return malicious_urls
                else:
                    print(
                        f"API key authentication failed: {response.status_code}")
                    print("Falling back to sample malicious URLs...")

            except Exception as e:
                print(f"Error downloading with API key: {str(e)}")
                print("Falling back to sample malicious URLs...")

        # Fallback: Use sample malicious URLs
        print("Using sample malicious URLs (PhishTank API not available)...")
        sample_malicious_urls = [
            "https://paypal-secure-login.com/",
            "https://netflix-account-update.net/",
            "https://amazon-login-verify.com/",
            "https://bankofamerica-secure.com/",
            "https://facebook-security-alert.com/",
            "https://google-account-recovery.net/",
            "https://microsoft-office365-login.com/",
            "https://apple-id-verification.net/",
            "https://instagram-password-reset.com/",
            "https://twitter-account-suspended.net/",
            "https://linkedin-security-check.com/",
            "https://ebay-payment-confirmation.com/",
            "https://chase-bank-alert.com/",
            "https://wellsfargo-online-banking.net/",
            "https://citi-bank-login.com/",
            "https://usaa-military-banking.com/",
            "https://capital-one-alert.net/",
            "https://discover-card-update.com/",
            "https://american-express-verify.net/",
            "https://visa-card-security.com/",
            "https://mastercard-alert.net/",
            "https://dropbox-file-share.com/",
            "https://onedrive-login.net/",
            "https://gmail-security-alert.com/",
            "https://outlook-web-access.net/",
            "https://yahoo-mail-update.com/",
            "https://aol-account-recovery.net/",
            "https://github-security-check.com/",
            "https://stackoverflow-login.net/",
            "https://slack-workspace-invite.com/",
            "https://zoom-meeting-join.net/",
            "https://teams-microsoft-login.com/",
            "https://discord-server-invite.net/",
            "https://twitch-streamer-alert.com/",
            "https://youtube-channel-update.net/",
            "https://tiktok-account-verify.com/",
            "https://snapchat-password-reset.net/",
            "https://whatsapp-web-login.com/",
            "https://telegram-channel-join.net/",
            "https://spotify-premium-free.com/",
            "https://netflix-free-account.net/",
            "https://hulu-unlimited-access.com/",
            "https://disney-plus-login.net/",
            "https://hbo-max-watch.com/",
            "https://prime-video-amazon.net/",
            "https://crunchyroll-premium.com/",
            "https://udemy-free-courses.net/",
            "https://coursera-unlimited.com/"
        ]

        # Save sample data as CSV for consistency
        sample_data = pd.DataFrame({
            'phish_id': range(1, len(sample_malicious_urls) + 1),
            'url': sample_malicious_urls,
            'phish_detail_url': [f"http://www.phishtank.com/phish_detail.php?phish_id={i}" for i in range(1, len(sample_malicious_urls) + 1)],
            'submission_time': ['2024-01-01T00:00:00+00:00'] * len(sample_malicious_urls),
            'verified': ['yes'] * len(sample_malicious_urls),
            'verification_time': ['2024-01-01T00:00:00+00:00'] * len(sample_malicious_urls),
            'online': ['yes'] * len(sample_malicious_urls),
            'target': ['Various'] * len(sample_malicious_urls)
        })

        filepath = os.path.join(self.data_dir, 'phishtank_urls.csv')
        sample_data.to_csv(filepath, index=False)

        print(f"Using {len(sample_malicious_urls)} sample malicious URLs")
        return sample_malicious_urls

    def get_alexa_top_sites(self, limit=1000):
        """
        Scrape top sites from Alexa (free tier)
        Note: Alexa website structure may change, monitor for updates
        """
        url = "https://www.alexa.com/topsites/"
        headers = {
            "User-Agent": "Komnot-Detection/1.0 (Research Project)"
        }

        print("Collecting Alexa top sites...")
        try:
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                sites = []

                # Find site links (Alexa structure as of 2024)
                site_elements = soup.find_all('a', href=True)

                for element in site_elements:
                    href = element.get('href')
                    if href and href.startswith('http') and 'alexa.com' not in href:
                        # Clean up the URL
                        # Remove query parameters
                        clean_url = href.split('?')[0]
                        if clean_url not in sites:
                            sites.append(clean_url)

                # Limit results
                legitimate_urls = sites[:limit]
                print(
                    f"Collected {len(legitimate_urls)} legitimate URLs from Alexa")
                return legitimate_urls
            else:
                print(f"Error accessing Alexa: {response.status_code}")
                return []

        except Exception as e:
            print(f"Error: {str(e)}")
            return []

    def create_combined_dataset(self, malicious_urls, legitimate_urls, filename='combined_dataset.csv'):
        """
        Combine malicious and legitimate URLs into labeled dataset
        """
        print("Creating combined dataset...")

        dataset = []

        # Add malicious URLs (label = 1)
        for url in malicious_urls:
            if self.is_valid_url(url):
                dataset.append({
                    'url': url,
                    'label': 1,
                    'type': 'malicious'
                })

        # Add legitimate URLs (label = 0)
        for url in legitimate_urls:
            if self.is_valid_url(url):
                dataset.append({
                    'url': url,
                    'label': 0,
                    'type': 'legitimate'
                })

        # Create DataFrame and save
        df = pd.DataFrame(dataset)
        filepath = os.path.join(self.data_dir, filename)
        df.to_csv(filepath, index=False)

        print(f"Created dataset with {len(dataset)} URLs")
        print(f"Malicious: {len([d for d in dataset if d['label'] == 1])}")
        print(f"Legitimate: {len([d for d in dataset if d['label'] == 0])}")
        print(f"Saved to: {filepath}")

        return df

    def generate_malicious_urls_with_gemini(self, count=50):
        """
        Generate realistic malicious URLs using Gemini AI
        """
        if not self.gemini_client:
            print("Gemini API key not configured. Skipping AI generation.")
            return []

        prompt = f"""
        Generate {count} realistic phishing/malicious URLs that could be used in cyber attacks.
        Focus on common phishing targets like:
        - Banking websites (paypal, chase, bankofamerica, etc.)
        - Social media (facebook, instagram, twitter, linkedin)
        - Email services (gmail, outlook, yahoo)
        - Cloud storage (dropbox, onedrive)
        - Streaming services (netflix, spotify, hulu)
        - Government/military (usaa, capital-one)
        - Tech companies (microsoft, apple, google)

        Make them look convincing by using:
        - Typosquatting (paypa1.com, netfl1x.com)
        - Subdomain abuse (secure.paypal-login.com)
        - Similar domains (paypal-secure.com, netflix-update.net)
        - Common phishing words (login, secure, verify, update, alert)

        Return only the URLs, one per line, starting with https://
        Do not include any explanations or additional text.
        """

        try:
            print(f"Generating {count} malicious URLs with Gemini AI...")
            response = self.gemini_client.models.generate_content(
                model='gemini-2.0-flash-exp',
                contents=prompt
            )
            urls_text = response.text.strip()

            # Parse URLs from response
            urls = []
            for line in urls_text.split('\n'):
                line = line.strip()
                if line.startswith('https://') and self.is_valid_url(line):
                    urls.append(line)

            print(
                f"Successfully generated {len(urls)} malicious URLs with Gemini")
            return urls[:count]  # Limit to requested count

        except Exception as e:
            print(f"Error generating URLs with Gemini: {str(e)}")
            return []

    def get_alexa_top_sites_enhanced(self, limit=500, use_gemini=False):
        """
        Enhanced Alexa top sites collection with optional Gemini assistance
        """
        print("Collecting Alexa top sites with enhanced method...")

        # First try regular Alexa scraping
        legitimate_urls = self.get_alexa_top_sites(limit=limit)

        # If Gemini is enabled and we have few results, use Gemini to suggest more sites
        if use_gemini and self.gemini_model and len(legitimate_urls) < limit:
            additional_needed = limit - len(legitimate_urls)

            prompt = f"""
            Generate {additional_needed} legitimate website URLs that are commonly visited and trusted.
            Focus on popular websites like:
            - News sites (cnn.com, bbc.com, nytimes.com)
            - Shopping (amazon.com, ebay.com, walmart.com)
            - Search engines (google.com, bing.com)
            - Educational (wikipedia.org, coursera.org)
            - Government (gov.uk, whitehouse.gov)
            - Health (nih.gov, mayoclinic.org)
            - Technology (github.com, stackoverflow.com)

            Return only the URLs, one per line, starting with https://
            Include only well-known, legitimate websites.
            """

            try:
                print(
                    f"Using Gemini to generate {additional_needed} additional legitimate URLs...")
                response = self.gemini_model.generate_content(prompt)
                gemini_urls = []

                for line in response.text.strip().split('\n'):
                    line = line.strip()
                    if line.startswith('https://') and self.is_valid_url(line):
                        gemini_urls.append(line)

                legitimate_urls.extend(gemini_urls)
                legitimate_urls = list(
                    set(legitimate_urls))  # Remove duplicates

            except Exception as e:
                print(f"Error using Gemini for additional URLs: {str(e)}")

        print(f"Total legitimate URLs collected: {len(legitimate_urls)}")
        return legitimate_urls[:limit]

    def is_valid_url(self, url):
        """
        Basic URL validation
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:  # noqa: E722
            return False

    def collect_all_data(self, phishtank_api_key=None, limit=500, use_gemini=True):
        """
        Enhanced data collection pipeline with Gemini AI support
        """
        print("Starting enhanced data collection...")

        # Collect malicious URLs
        malicious_urls = self.download_phishtank_csv(phishtank_api_key)

        # Use Gemini to generate additional malicious URLs if available
        if use_gemini and self.gemini_client:
            gemini_malicious = self.generate_malicious_urls_with_gemini(
                count=limit//2)
            if gemini_malicious:
                malicious_urls.extend(gemini_malicious)
                malicious_urls = list(set(malicious_urls))  # Remove duplicates
                print(
                    f"Total malicious URLs: {len(malicious_urls)} (PhishTank: {len(malicious_urls) - len(gemini_malicious)}, Gemini: {len(gemini_malicious)})")

        # Collect legitimate URLs with enhanced method
        legitimate_urls = self.get_alexa_top_sites_enhanced(
            limit=limit, use_gemini=use_gemini)

        # Create combined dataset
        if malicious_urls and legitimate_urls:
            dataset = self.create_combined_dataset(
                malicious_urls[:limit],
                legitimate_urls[:limit]
            )
            return dataset
        else:
            print("Failed to collect sufficient data")
            return None


# Usage example
if __name__ == "__main__":
    collector = DataCollector()

    # Option 1: Use PhishTank API key (if you have one)
    # API_KEY = "your_actual_phishtank_api_key"

    # Option 2: Use None for automatic fallback to sample data
    API_KEY = None  # Will use sample malicious URLs

    # Collect data
    dataset = collector.collect_all_data(API_KEY, limit=500)

    if dataset is not None:
        print("Data collection completed successfully!")
        print(f"Dataset shape: {dataset.shape}")
        print("\nFirst 10 entries:")
        print(dataset.head(10))
        print("\nLabel distribution:")
        print(dataset['label'].value_counts())
    else:
        print("Data collection failed. Check internet connection.")
