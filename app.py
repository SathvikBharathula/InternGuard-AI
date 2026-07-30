"""
Flask backend for the AI-Powered Fake Job Posting Detection app.
Uses the pre-trained Logistic Regression + TF-IDF model.
"""

import re
import string
import joblib
import numpy as np
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# ── Load pre-trained artefacts ──────────────────────────────────────────────
tfidf = joblib.load("tfidf.pkl")
model = joblib.load("fake_job_model.pkl")


# ── Text pre-processing (mirrors the notebook) ──────────────────────────────
def clean_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r"http\S+|www\S+", "", text)
    text = text.translate(str.maketrans("", "", string.punctuation))
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# ── Routes ──────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True)

    title       = data.get("title", "")
    location    = data.get("location", "")
    description = data.get("description", "")
    requirements = data.get("requirements", "")

    # Combine fields exactly like training
    combined = f"{title} {location} {description} {requirements}"
    cleaned  = clean_text(combined)

    # Vectorise & predict
    vec   = tfidf.transform([cleaned])
    pred  = int(model.predict(vec)[0])
    proba = model.predict_proba(vec)[0]

    fake_prob    = round(float(proba[1]) * 100, 1)
    legit_prob   = round(float(proba[0]) * 100, 1)
    is_fake      = pred == 1
    confidence   = fake_prob if is_fake else legit_prob

    # Risk level
    if fake_prob >= 70:
        risk = "HIGH"
    elif fake_prob >= 40:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    # Red-flag keywords (simple heuristic layer on top of model)
    red_flags = []
    combined_lower = combined.lower()
    heuristics = {
        "work from home": "Suspiciously vague remote work offer",
        "no experience required": "Unrealistic entry barrier",
        "earn money fast": "Get-rich-quick language detected",
        "guaranteed income": "Guaranteed income promises are a red flag",
        "send money": "Requesting money transfer — major scam indicator",
        "wire transfer": "Wire transfer requests are scam indicators",
        "western union": "Western Union payment — common fraud pattern",
        "bitcoin": "Cryptocurrency payment — common fraud pattern",
        "upfront fee": "Upfront fee requests are a red flag",
        "training fee": "Training fee requests are suspicious",
        "background check fee": "Legitimate employers never charge background check fees",
        "must be 18": "Age-only requirement suggests lack of role clarity",
        "click here": "Urgency/clickbait language detected",
    }
    for kw, msg in heuristics.items():
        if kw in combined_lower:
            red_flags.append(msg)

    return jsonify({
        "is_fake":     is_fake,
        "fake_prob":   fake_prob,
        "legit_prob":  legit_prob,
        "confidence":  confidence,
        "risk":        risk,
        "red_flags":   red_flags,
        "verdict":     "FAKE" if is_fake else "LEGITIMATE",
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
