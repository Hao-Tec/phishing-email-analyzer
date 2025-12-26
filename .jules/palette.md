## 2025-12-16 - [Recommendations in HTML Report]
**Learning:** Users often scan reports for "what do I do now?" rather than technical findings. Missing this section in HTML (while present in text) was a major gap.
**Action:** Always verify that different output formats (HTML, Text, JSON) maintain feature parity for critical sections like Recommendations.

## 2025-12-26 - [Dynamic HTML Generation Pitfalls]
**Learning:** Generating HTML reports with embedded CSS/JS using Python f-strings requires careful escaping of braces (`{{` and `}}`). Failure to do so leads to `NameError` or `SyntaxError` at runtime, which might be missed if only checking for string presence.
**Action:** When adding CSS or JS blocks to the reporter, always double-escape braces and use unit tests that actually execute the generation method to catch syntax errors.
