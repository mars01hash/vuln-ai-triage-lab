# Machine Learning Classifier Module

This component trains and serves a machine learning classifier to categorize vulnerability findings into canonical CWE classes. 

Version 6.0 upgrades this module by introducing swappable feature encoders: traditional TF-IDF keyword counts or deep semantic Sentence-Transformers embeddings.

## Key Features
1. **Multi-Model Feature Extraction**: Can be trained using standard TF-IDF bag-of-words or Sentence-Transformers embeddings (default: `sentence-transformers/all-MiniLM-L6-v2`).
2. **Lazy-Loading**: The heavy Sentence-Transformers PyTorch model is only loaded into memory when predictions are first executed.
3. **Dynamic Serialization**: Excludes internal model parameters from standard joblib dump routines, keeping the serialized `.joblib` model footprint extremely small (~20KB instead of 100MB+).

## Files
* `cwe_ml_classifier.py`: Exposes prediction logic and defines the custom `SentenceTransformerEncoder`.
* `train_cwe_classifier.py`: Orchestrates the scikit-learn pipeline training CLI.
* `calibration.py`: Computes statistical calibration indicators (ECE, Brier score, and bin counts).

## How to train the model
Execute the training script from the root workspace directory.

**Using TF-IDF Feature Extraction (Default / Backward Compatible)**:
```bash
python -m app.ml.train_cwe_classifier --input data/cwe_training_findings.jsonl --output models/cwe_tfidf_logreg.joblib --metrics output/cwe_training_metrics.json --encoder tfidf
```

**Using Sentence-Transformers Embeddings (Deep Learning)**:
```bash
python -m app.ml.train_cwe_classifier --input data/cwe_training_findings.jsonl --output models/cwe_tfidf_logreg.joblib --metrics output/cwe_training_metrics.json --encoder embeddings
```

## Python Usage
```python
from app.ml.cwe_ml_classifier import MLCWEClassifier

# Load trained joblib model (works seamlessly for both tfidf and embeddings models)
classifier = MLCWEClassifier.load("models/cwe_tfidf_logreg.joblib")

# Predict CWE mapping
prediction = classifier.predict_finding(finding)
print(f"Predicted CWE: {prediction.cwe} with confidence {prediction.confidence}")
```

## Why it works
Rule-based keyword mapping fails when finding descriptions use synonyms or unexpected phrasing. 
* **TF-IDF**: Counts word-cooccurrences (1-gram and 2-grams) and fits Logistic Regression multi-class probabilities.
* **Embeddings**: Represents the text as a high-dimensional dense vector capturing semantic proximity. This maps synonyms (e.g. "bypass", "improper credential", "unauthenticated login") to the same contextual space, improving classification generalization.
