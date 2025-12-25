## 2025-12-16 - [Recommendations in HTML Report]
**Learning:** Users often scan reports for "what do I do now?" rather than technical findings. Missing this section in HTML (while present in text) was a major gap.
**Action:** Always verify that different output formats (HTML, Text, JSON) maintain feature parity for critical sections like Recommendations.

## 2025-12-25 - [Semantic Report Structure]
**Learning:** Single-page reports with internal navigation links should use `<nav>` landmarks instead of generic `<div>`s to help screen reader users identify the navigation region quickly.
**Action:** Use semantic HTML tags (`<nav>`, `<main>`, `<article>`) for document structure and ensure decorative icons are hidden with `aria-hidden="true"` to reduce screen reader noise.
