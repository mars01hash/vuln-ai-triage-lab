from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from app.ml.cwe_ml_classifier import SentenceTransformerEncoder

DEFAULT_TRAINING_DATA = Path("data/cwe_training_findings.jsonl")
DEFAULT_MODEL_PATH = Path("models/cwe_tfidf_logreg.joblib")
DEFAULT_METRICS_PATH = Path("output/cwe_training_metrics.json")


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def build_model(encoder: str = "tfidf", embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2") -> Pipeline:
    if encoder == "embeddings":
        vectorizer = SentenceTransformerEncoder(model_name=embedding_model)
    else:
        vectorizer = TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            min_df=1,
            max_features=8000,
        )

    return Pipeline(
        steps=[
            (
                "tfidf",
                vectorizer,
            ),
            (
                "clf",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    solver="lbfgs",
                ),
            ),
        ]
    )


def train_classifier(
    input_path: str | Path = DEFAULT_TRAINING_DATA,
    output_path: str | Path = DEFAULT_MODEL_PATH,
    metrics_path: str | Path = DEFAULT_METRICS_PATH,
    test_size: float = 0.25,
    random_state: int = 42,
    encoder: str = "tfidf",
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2",
) -> dict[str, Any]:
    rows = load_jsonl(input_path)
    if not rows:
        raise ValueError(f"No training rows found in {input_path}")

    x = [str(row["text"]) for row in rows]
    y = [str(row["cwe"]) for row in rows]
    label_counts = Counter(y)

    stratify = y if min(label_counts.values()) >= 2 else None
    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify,
    )

    model = build_model(encoder, embedding_model)
    model.fit(x_train, y_train)

    y_pred = model.predict(x_test)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    labels = sorted(label_counts.keys())
    matrix = confusion_matrix(y_test, y_pred, labels=labels).tolist()

    # Train a final model on all available rows after holdout evaluation.
    # The holdout metrics above remain the honest MVP benchmark; the saved model uses all labels.
    final_model = build_model(encoder, embedding_model)
    final_model.fit(x, y)

    model_version = f"embeddings_{embedding_model.split('/')[-1]}_logreg_v1" if encoder == "embeddings" else "tfidf_logreg_v1"

    artifact = {
        "model": final_model,
        "labels": labels,
        "metadata": {
            "model_version": model_version,
            "training_rows": len(rows),
            "train_rows": len(x_train),
            "test_rows": len(x_test),
            "label_counts": dict(label_counts),
        },
    }

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, output_path)

    metrics = {
        "model_path": str(output_path),
        "accuracy": round(float(accuracy), 4),
        "macro_f1": round(float(report.get("macro avg", {}).get("f1-score", 0.0)), 4),
        "weighted_f1": round(float(report.get("weighted avg", {}).get("f1-score", 0.0)), 4),
        "labels": labels,
        "label_counts": dict(label_counts),
        "confusion_matrix_labels": labels,
        "confusion_matrix": matrix,
        "classification_report": report,
        "note": "Small synthetic dataset for MVP demonstration. Replace with historical labeled scanner findings for real evaluation.",
    }

    metrics_path = Path(metrics_path)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train a TF-IDF + Logistic Regression CWE classifier.")
    parser.add_argument("--input", default=str(DEFAULT_TRAINING_DATA))
    parser.add_argument("--output", default=str(DEFAULT_MODEL_PATH))
    parser.add_argument("--metrics", default=str(DEFAULT_METRICS_PATH))
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--encoder", default="tfidf", choices=["tfidf", "embeddings"], help="Feature extraction method to use.")
    parser.add_argument("--embedding-model", default="sentence-transformers/all-MiniLM-L6-v2", help="Pre-trained embedding model name.")
    args = parser.parse_args()
    metrics = train_classifier(
        args.input,
        args.output,
        args.metrics,
        args.test_size,
        encoder=args.encoder,
        embedding_model=args.embedding_model,
    )
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
