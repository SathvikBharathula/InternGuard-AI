"""
InternGuard AI - ML Predictor Module
Loads and runs the pre-trained TF-IDF vectorizer and Logistic Regression model.
Paths are strictly anchored to the project root directory.
"""

import os
import re
import string
import joblib
import numpy as np


class MLPredictor:
    """
    Encapsulates pre-trained ML inference for fake internship detection.
    Guarantees deterministic feature extraction, probability extraction using model.classes_,
    and backward-compatible prediction semantics.
    """

    def __init__(self, model_path: str = None, tfidf_path: str = None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        self.model_path = model_path or os.path.join(base_dir, "fake_job_model.pkl")
        self.tfidf_path = tfidf_path or os.path.join(base_dir, "tfidf.pkl")

        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"ML Model file not found at: {self.model_path}")
        if not os.path.exists(self.tfidf_path):
            raise FileNotFoundError(f"TF-IDF file not found at: {self.tfidf_path}")

        self.tfidf = joblib.load(self.tfidf_path)
        self.model = joblib.load(self.model_path)

        # Accurately resolve class indices from model.classes_
        classes = list(self.model.classes_)
        self.fake_idx = classes.index(1) if 1 in classes else 1
        self.legit_idx = classes.index(0) if 0 in classes else 0

    @staticmethod
    def clean_text(text: str) -> str:
        """
        Cleans input text mirroring the training pipeline:
        lowercases, removes URLs, strips punctuation, and normalizes whitespace.
        """
        if not isinstance(text, str):
            text = str(text or "")
        text = text.lower()
        text = re.sub(r"http\S+|www\S+", "", text)
        text = text.translate(str.maketrans("", "", string.punctuation))
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def predict(
        self,
        title: str = "",
        location: str = "",
        description: str = "",
        requirements: str = "",
        **kwargs
    ) -> dict:
        """
        Combines fields, cleans text, transforms via TF-IDF, and predicts fraud probability.
        Preserves original prediction semantics and response fields.
        """
        combined = f"{title} {location} {description} {requirements}"
        cleaned = self.clean_text(combined)

        # Vectorize and predict
        vec = self.tfidf.transform([cleaned])
        pred = int(self.model.predict(vec)[0])
        proba = self.model.predict_proba(vec)[0]

        fake_prob = round(float(proba[self.fake_idx]) * 100, 1)
        legit_prob = round(float(proba[self.legit_idx]) * 100, 1)
        is_fake = pred == 1
        confidence = fake_prob if is_fake else legit_prob

        # Risk level determination
        if fake_prob >= 70:
            risk = "HIGH"
        elif fake_prob >= 40:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        verdict = "FAKE" if is_fake else "LEGITIMATE"

        return {
            "is_fake": is_fake,
            "fake_prob": fake_prob,
            "legit_prob": legit_prob,
            "confidence": confidence,
            "risk": risk,
            "verdict": verdict,
            "combined_text": combined,
        }
