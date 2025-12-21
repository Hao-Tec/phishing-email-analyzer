import sys
import os

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.url_scraper import URLScraper

scraper = URLScraper()
print("Scraper initialized")
try:
    # This will likely fail to resolve/connect in sandbox unless I allow external access or mock it.
    # But I just want to see if it runs.
    res = scraper.scrape("http://example.com")
    print(res)
except Exception as e:
    print(f"Error: {e}")
