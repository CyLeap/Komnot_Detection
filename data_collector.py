import requests
import pandas as pd
from bs4 import BeautifulSoup
import os
from urllib.parse import urlparse


class DataCollector:
    def __init__(self):
        self.data_dir = 'data'
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

    def download_phishtank_csv(self, api_key):
        """
        Download verified phishing URLs from PhishTank API
        Requires free API key from https://phishtank.com/developer_info.php
        """
        url = "https://data.phishtank.com/data/online-valid.csv"
        headers = {
            "User-Agent": "Komnot-Detection/1.0",
            "Authorization": f"Bearer {api_key}"
        }

        print("Downloading PhishTank data...")
        try:
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                filepath = os.path.join(self.data_dir, 'phishtank_urls.csv')
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
                    f"Error downloading PhishTank data: {response.status_code}")
                print(f"Response: {response.text}")
                return []

        except Exception as e:
            print(f"Error: {str(e)}")
            return []

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

    def is_valid_url(self, url):
        """
        Basic URL validation
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def collect_all_data(self, phishtank_api_key, limit=500):
        """
        Complete data collection pipeline
        """
        print("Starting complete data collection...")

        # Collect malicious URLs
        malicious_urls = self.download_phishtank_csv(phishtank_api_key)

        # Collect legitimate URLs
        legitimate_urls = self.get_alexa_top_sites(limit=limit)

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

    # Replace with your actual PhishTank API key
    API_KEY = "your_phishtank_api_key_here"

    # Collect data
    dataset = collector.collect_all_data(API_KEY, limit=500)

    if dataset is not None:
        print("Data collection completed successfully!")
        print(dataset.head())
    else:
        print("Data collection failed. Check API key and internet connection.")
