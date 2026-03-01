"""
Prompt Lab — Interactive Prompt Injection Playground.
A web-based security testing tool powered by ClawGuard patterns.
"""

from flask import Flask, render_template, request, jsonify
from scanner import scan, EXAMPLES, PATTERNS

app = Flask(__name__)


@app.route("/")
def index():
    """Render the main playground page."""
    category_stats = {cat: len(patterns) for cat, patterns in PATTERNS.items()}
    total_patterns = sum(category_stats.values())
    return render_template(
        "index.html",
        examples=EXAMPLES,
        categories=category_stats,
        total_patterns=total_patterns,
    )


@app.route("/scan", methods=["POST"])
def scan_text():
    """Scan submitted text and return results as JSON."""
    data = request.get_json()
    text = data.get("text", "").strip()

    if not text:
        return jsonify({"error": "No text provided"}), 400

    if len(text) > 10000:
        return jsonify({"error": "Text too long (max 10,000 characters)"}), 400

    result = scan(text)

    return jsonify({
        "risk_score": result.risk_score,
        "risk_label": result.risk_label,
        "is_safe": result.is_safe,
        "findings_count": len(result.findings),
        "findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "pattern_name": f.pattern_name,
                "match": f.match,
                "line": f.line,
                "context": f.context,
            }
            for f in result.findings
        ],
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
