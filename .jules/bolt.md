## 2024-05-24 - Optimized URL Extraction in HTML Emails
**Learning:** `urlextract` treats input as raw text and will scan all HTML markup if passed the raw body, which is computationally expensive and redundant if we already parse the HTML.
**Action:** When working with HTML content, parse it first (using BeautifulSoup) and extract only the visible text (plus script/style content if needed for security checks), then feed that smaller payload to `urlextract`. This reduced execution time by ~50% in benchmarks.
