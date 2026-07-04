from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib

from app.normalization.cwe_classifier import CWE_BY_ID, DEFAULT_CWE
from app.schemas import VulnerabilityFinding


DEFAULT_MODEL_PATH = Path("models/cwe_tfidf_logreg.joblib")


def text_from_finding(finding: VulnerabilityFinding) -> str:
    """Build model input text from a canonical vulnerability finding."""
    parts = [
        finding.title or "",
        finding.description or "",
        finding.endpoint or "",
        finding.parameter or "",
        finding.file_path or "",
        finding.package or "",
        finding.version or "",
        finding.tool_name or "",
        finding.source_type.value if finding.source_type else "",
    ]
    return " ".join(str(p) for p in parts if p).strip()


@dataclass
class MLCWEPrediction:
    cwe: str
    cwe_name: str
    confidence: float
    evidence: list[str]
    model_version: str = "tfidf_logreg_v1"


class MLCWEClassifier:
    """Thin wrapper around a trained scikit-learn CWE classifier.

    The trained artifact is expected to be a dict with:
      - model: sklearn Pipeline supporting predict/predict_proba
      - labels: list[str]
      - metadata: dict
    """

    def __init__(self, artifact: dict[str, Any]):
        self.artifact = artifact
        self.model = artifact["model"]
        self.labels = list(artifact.get("labels", []))
        self.metadata = artifact.get("metadata", {})

    @classmethod
    def load(cls, model_path: str | Path = DEFAULT_MODEL_PATH) -> "MLCWEClassifier":
        path = Path(model_path)
        if not path.exists():
            raise FileNotFoundError(
                f"ML model not found at {path}. Run: python -m app.ml.train_cwe_classifier --output {path}"
            )
        artifact = joblib.load(path)
        return cls(artifact)

    def predict_text(self, text: str) -> MLCWEPrediction:
        pred = str(self.model.predict([text])[0])
        confidence = 0.5
        top_terms: list[str] = []

        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba([text])[0]
            classes = list(self.model.classes_)
            confidence = float(probs[classes.index(pred)])

            # A lightweight, explainable evidence summary for MVP use.
            tokens = [tok for tok in text.lower().replace("/", " ").replace("_", " ").split() if len(tok) > 3]
            seen = []
            for token in tokens:
                clean = token.strip(".,:;()[]{}'\"")
                if clean and clean not in seen:
                    seen.append(clean)
            top_terms = seen[:8]

        rule = CWE_BY_ID.get(pred, DEFAULT_CWE)
        return MLCWEPrediction(
            cwe=rule.cwe,
            cwe_name=rule.name,
            confidence=round(confidence, 3),
            evidence=["ML classifier prediction", *top_terms],
            model_version=str(self.metadata.get("model_version", "tfidf_logreg_v1")),
        )

    def predict_finding(self, finding: VulnerabilityFinding) -> MLCWEPrediction:
        # Source-supplied recognized CWE still gets priority, because scanners may already map accurately.
        if finding.cwe and finding.cwe in CWE_BY_ID:
            rule = CWE_BY_ID[finding.cwe]
            return MLCWEPrediction(
                cwe=rule.cwe,
                cwe_name=rule.name,
                confidence=0.95,
                evidence=["CWE supplied by source and recognized"],
                model_version=str(self.metadata.get("model_version", "tfidf_logreg_v1")),
            )
        return self.predict_text(text_from_finding(finding))
