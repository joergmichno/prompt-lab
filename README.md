# 🧪 Prompt Lab

**Interactive Prompt Injection Playground**

[![CI](https://github.com/joergmichno/prompt-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/joergmichno/prompt-lab/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-31_passed-brightgreen?style=flat&logo=pytest&logoColor=white)](tests/)
[![Live Demo](https://img.shields.io/badge/Live_Demo-Online-brightgreen?style=flat&logo=rocket&logoColor=white)](https://prompttools.co)

A web-based security testing tool that lets you explore and understand prompt injection attacks in real time. Powered by [ClawGuard](https://github.com/joergmichno/clawguard) detection patterns.

**[Live Demo →](https://prompttools.co)**

---

## What It Does

Paste any text and instantly see:
- **Risk Score** (0–10) with color-coded severity
- **Detected Threats** with category, pattern name, and matched context
- **9 Example Attacks** from Easy to Hard across all attack categories

### Detection Categories

| Category | Patterns | Examples |
|----------|----------|----------|
| **Prompt Injection** | 8 | Direct overrides, role play escapes, delimiter injection, context overflow |
| **Dangerous Commands** | 4 | Shell exploits, reverse shells, privilege escalation |
| **Code Obfuscation** | 5 | `eval()`, `getattr()`, magic attributes, base64 encoding |
| **Data Exfiltration** | 5 | API keys, private keys, webhook URLs, database strings |
| **Social Engineering** | 3 | Authority impersonation, urgency manipulation, trust exploitation |

**25+ detection patterns** across 5 categories, supporting English and German attacks.

## Quick Start

```bash
# Clone
git clone https://github.com/joergmichno/prompt-lab.git
cd prompt-lab

# Install
pip install -r requirements.txt

# Run
python app.py
```

Open [http://localhost:5000](http://localhost:5000) in your browser.

## Example Attacks

The playground includes 9 pre-built attacks you can test with one click:

| Attack | Category | Difficulty |
|--------|----------|------------|
| Direct Override | Prompt Injection | Easy |
| Role Play Escape | Prompt Injection | Easy |
| Delimiter Injection | Prompt Injection | Medium |
| Reverse Shell | Dangerous Commands | Hard |
| Eval Obfuscation | Code Obfuscation | Medium |
| API Key Exfiltration | Data Exfiltration | Medium |
| Authority Impersonation | Social Engineering | Easy |
| Synonym Override (DE) | Prompt Injection | Hard |
| Multi-Vector Attack | Combined | Hard |

## API

The scanner is also available as a JSON API:

```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "Ignore all previous instructions"}'
```

Response:
```json
{
  "risk_score": 4,
  "risk_label": "MEDIUM",
  "is_safe": false,
  "findings_count": 1,
  "findings": [
    {
      "severity": "CRITICAL",
      "category": "Prompt Injection",
      "pattern_name": "Direct Override (EN)",
      "match": "Ignore all previous instructions",
      "line": 1,
      "context": "Ignore all previous instructions"
    }
  ]
}
```

## Testing

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

31 tests covering all detection categories, risk scoring, deduplication, and example integrity.

## Project Structure

```
prompt-lab/
├── app.py              # Flask web server
├── scanner.py          # Detection engine (25+ patterns)
├── templates/
│   └── index.html      # Dark-mode UI with real-time scanning
├── tests/
│   └── test_scanner.py # 31 tests across all categories
├── requirements.txt
└── requirements-dev.txt
```

## Related Projects

- **[ClawGuard](https://github.com/joergmichno/clawguard)** — Full CLI security scanner (38+ patterns, 53 tests)
- **[DocQA](https://github.com/joergmichno/docqa)** — RAG-based document Q&A tool

## License

MIT License — see [LICENSE](LICENSE) for details.

---

**Built by [Jörg Michno](https://github.com/joergmichno)** — Explore prompt injection attacks safely. 🧪
