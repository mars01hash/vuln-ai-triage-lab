# Machine Learning Classifier Module

This component trains and serves a TF-IDF + Logistic Regression machine learning classifier to categorize findings into canonical CWE classes.

## Files
* `cwe_ml_classifier.py`: Serves prediction logic wrapper.
* `train_cwe_classifier.py`: Command-line training pipeline using scikit-learn.

## How to train the model
Execute the training script from the root workspace directory:
```bash
python -m app.ml.train_cwe_classifier --input data/cwe_training_findings.jsonl --output models/cwe_tfidf_logreg.joblib --metrics output/cwe_training_metrics.json
```

## Python Usage
```python
from app.ml.cwe_ml_classifier import MLCWEClassifier

# Load trained joblib model
classifier = MLCWEClassifier.load("models/cwe_tfidf_logreg.joblib")

# Predict CWE mapping
prediction = classifier.predict_finding(finding)
print(f"Predicted CWE: {prediction.cwe} with confidence {prediction.confidence}")
```

## Why it works
Rule-based keyword mapping fails when finding descriptions use synonyms or unexpected phrasing. TF-IDF vectorization counts word-cooccurrences (1-gram and 2-grams) and Logistic Regression determines multi-class probabilities, enabling generalizable classification.
