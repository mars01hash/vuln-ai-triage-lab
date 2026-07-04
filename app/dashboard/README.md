# Streamlit Dashboard Module

This component provides an interactive web-based UI for security analysts to review findings, audit priority scores, inspect ModSecurity virtual patches, and log human reviews.

## Files
* `streamlit_app.py`: Streamlit dashboard web application.

## Running the Dashboard
Run the following command from the root directory:
```bash
streamlit run app/dashboard/streamlit_app.py
```
Open your browser at `http://localhost:8501`.

## Features
* **Key KPI Cards:** Displays metrics for total findings, critical vulnerability counts, duplicate groupings, and proposed WAF rules.
* **Findings Grid:** Interactive sorting table containing scores, reachability status, and decisions.
* **Triage Analysis Panel:** Displays explainable text summaries, recommended remediation fix instructions, and SecRules for selected issues.
* **Report Downloader:** Generates markdown batch reports at the click of a button.

## Why it works
Automated pipelines require human-in-the-loop validation before applying code modifications or firewall overrides. The dashboard provides a convenient operational workflow for security analysts to review decisions and submit feedback.
