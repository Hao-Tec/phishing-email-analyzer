## 2024-05-24 - Optimized URL Extraction in HTML Emails
**Learning:** `urlextract` treats input as raw text and will scan all HTML markup if passed the raw body, which is computationally expensive and redundant if we already parse the HTML.
**Action:** When working with HTML content, parse it first (using BeautifulSoup) and extract only the visible text (plus script/style content if needed for security checks), then feed that smaller payload to `urlextract`. This reduced execution time by ~50% in benchmarks.

## 2024-05-25 - Optimized Doppelganger Domain Detection
**Learning:** `difflib.SequenceMatcher` performs expensive pre-computation on the second sequence (`b`). In a loop comparing one string (sender) against many targets, constantly recreating the matcher or swapping arguments inefficiently triggers this cost repeatedly.
**Action:** Pre-compute the target set (union of whitelists) to avoid $O(N)$ allocation per email. Instantiate `SequenceMatcher` once with the constant sender as `b`, and use `set_seq1(target)` to update `a` inside the loop. This amortizes the initialization cost across all checks.

## 2024-05-26 - Optimized Suffix Checking and List Allocation
**Learning:** Checking string suffixes using a generator expression like `any(s.endswith(x) for x in list)` is significantly slower (~92%) than passing a tuple directly to `endswith()` (e.g., `s.endswith(tuple)`), which is implemented in C. Additionally, defining lists (like URL shorteners) inside frequently called methods causes unnecessary re-allocation.
**Action:** Converted constant lists to module-level tuples for use with `endswith()`, and moved list definitions outside of loops/methods. This simplifies the code and drastically improves the performance of suffix checks in tight loops.
