# Feedback Module

This component captures and aggregates manual reviewer feedback (approvals/rejections) for triaged security findings.

## Files
* `feedback_store.py`: Append-only feedback log manager.

## Python Usage
```python
from app.feedback.feedback_store import FeedbackStore
from app.schemas import TriageFeedback

store = FeedbackStore("output/human_feedback.jsonl")

feedback = TriageFeedback(
    finding_id="SAST-001",
    decision="approved",
    reviewer="security_analyst",
    notes="Confirmed vulnerability. WAF patch deployed successfully."
)

store.add(feedback)
print(store.summary())  # Prints overall approval stats
```

## Why it works
AI-assisted recommendations require continuous calibration. Logging human actions (whether the developer agreed with the classification, priority, or virtual WAF patches) creates an audit log and generates datasets for model fine-tuning.
