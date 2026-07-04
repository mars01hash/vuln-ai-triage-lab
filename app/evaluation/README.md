# Evaluation Module

This component evaluates classifier mapping correctness against annotated expected labels to ensure pipeline reliability.

## Files
* `evaluate.py`: Accuracy evaluation runner.

## CLI Usage
Compare rule mode vs. ML mode using evaluation datasets:
```bash
# Rule Mode Evaluation
python -m app.evaluation.evaluate --input data/eval_labeled_findings.json

# ML Mode Evaluation
python -m app.evaluation.evaluate --input data/eval_labeled_findings.json --use-ml
```

## Why it works
CWE classifiers can experience regression or drift. Providing a local metric validation script lets you measure and compare accuracy changes immediately whenever keyword rules are added or ML models are retrained.
