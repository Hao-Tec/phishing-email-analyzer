# Contributing to Phishing Email Analyzer

First off, thanks for taking the time to contribute! 🎉

The following is a set of guidelines for contributing to the Phishing Email Analyzer. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## Getting Started

1.  **Fork the repository** on GitHub.
2.  **Clone your fork** locally:
    ```bash
    git clone https://github.com/your-username/phishing-email-analyzer.git
    ```
3.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
4.  **Create a branch** for your feature or bugfix:
    ```bash
    git checkout -b feature/amazing-feature
    ```

## Development Standards

### Code Style

We strictly adhere to PEP 8 standards. Before submitting a PR, ensure your code is linted.

- **Linter**: `flake8`
- **Max Line Length**: 79 characters

**Run Linting:**

```bash
flake8 src
```

_If `flake8` reports errors, the CI build will fail._

### Testing

Please ensure your changes do not break existing functionality.

- Test with the samples provided in `samples/`.
- If adding a new heuristic, add a corresponding test case if possible.

## Submitting a Pull Request

1.  Push your branch to your fork.
2.  Open a Pull Request against the `main` branch.
3.  Describe your changes clearly in the description.
4.  Reference any related issues (e.g., `Closes #123`).

## Reporting Bugs

Please use the [Issue Tracker](https://github.com/Hao-Tec/phishing-email-analyzer/issues) to report bugs. Include:

- Your OS version.
- Python version.
- Steps to reproduce the error.
- (Optional) A sample anonymized email that causes the crash.

## Security Vulnerabilities

**Do not** report security vulnerabilities via public issues. Please see [SECURITY.md](SECURITY.md) for instructions.
