# Contributing

Thank you for considering contributing to the Cybersecurity Learning Toolkit.

## Getting Started

1. **Fork the repository** using the Fork button on GitHub.
2. **Clone your fork** locally:

   ```bash
   git clone https://github.com/<YOUR_USERNAME>/cybersecurity-learning-toolkit.git
   cd cybersecurity-learning-toolkit
   ```

3. **Create a branch** for your change:

   ```bash
   git checkout -b feature/your-feature-name
   ```

## Making Changes

- Follow PEP 8, use type hints, and include docstrings on every public function.
- Keep functions focused on a single responsibility.
- Never add offensive, stealth, or evasion functionality.
- Never commit secrets, API keys, passwords, or personal data.
- Update the relevant project README when you change CLI behavior.

## Running Tests

The test suite requires no internet access and no third-party packages:

```bash
python -m unittest discover -s tests -v
```

Or with pytest (optional):

```bash
pip install -r requirements-dev.txt
pytest tests -v
```

All tests must pass before a pull request is reviewed.

## Submitting a Pull Request

1. Commit your changes with a clear, descriptive message:

   ```bash
   git add .
   git commit -m "feat: add X"
   ```

2. Push your branch:

   ```bash
   git push origin feature/your-feature-name
   ```

3. Open a pull request against the `main` branch and describe:
   - What the change does.
   - Why it is needed.
   - How it was tested.

## Code of Conduct

All contributors must follow the project's
[Code of Conduct](CODE_OF_CONDUCT.md).
