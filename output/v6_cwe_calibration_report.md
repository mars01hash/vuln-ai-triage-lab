# CWE Classifier Calibration Report

## Summary

- Accuracy: **1.0**
- Macro F1: **1.0**
- Multiclass Brier score: **0.3089**
- Expected Calibration Error: **0.518**
- Mean confidence: **0.482**

## Reliability Bins

| Confidence Bin | Count | Accuracy | Mean Confidence | Gap |
|---|---:|---:|---:|---:|
| 0.0-0.2 | 0 | 0.0 | 0.0 | 0.0 |
| 0.2-0.4 | 1 | 1.0 | 0.351 | 0.649 |
| 0.4-0.6 | 4 | 1.0 | 0.4423 | 0.5577 |
| 0.6-0.8 | 2 | 1.0 | 0.6267 | 0.3733 |
| 0.8-1.0 | 0 | 0.0 | 0.0 | 0.0 |

## Example Predictions

| Finding | Expected | Predicted | Confidence | Correct |
|---|---|---|---:|---|
| SAST-001 | CWE-89 | CWE-89 | 0.4345 | True |
| SAST-002 | CWE-798 | CWE-798 | 0.6044 | True |
| SAST-003 | CWE-79 | CWE-79 | 0.4046 | True |
| DAST-001 | CWE-89 | CWE-89 | 0.4914 | True |
| DAST-002 | CWE-79 | CWE-79 | 0.649 | True |
| SCA-001 | CWE-20 | CWE-20 | 0.4388 | True |
| SCA-002 | CWE-22 | CWE-22 | 0.351 | True |

## How to interpret this

A calibrated model should not only rank findings correctly; its confidence should be meaningful. For example, findings predicted with about 0.80 confidence should be correct about 80% of the time over a sufficiently large validation set.

The bundled dataset is intentionally small for demonstration. Replace it with historical labeled scanner findings before using these metrics as real evidence.