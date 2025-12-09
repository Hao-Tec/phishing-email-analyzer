from src.llm_analyzer import LLMCache
import logging

# Configure logging to see warnings
logging.basicConfig(level=logging.INFO)

c = LLMCache()
print(f"DB Path: {c.db_path}")

text = "test email content"
response = {"score": 0.9, "summary": "Phishing"}

print("Putting...")
c.put(text, response)

print("Getting...")
cached = c.get(text)
print(f"Cached: {cached}")

if cached == response:
    print("SUCCESS: Cache works.")
else:
    print("FAILURE: Cache mismatch.")
