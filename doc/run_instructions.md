# Vuln AI Triage Lab - বিভিন্ন মোড এবং ব্যবহারের নির্দেশিকা (Run Instructions)

এই ডকুমেন্টেশনে প্রজেক্টের বিভিন্ন ইউজ কেস (Use Case) যেমন— **Rules Mode**, **ML Mode**, **SQLite/Chroma Memory**, **Streamlit Dashboard**, এবং **Benchmark Evaluation** কীভাবে কমান্ড লাইন (CLI), ওয়েব ড্যাশবোর্ড এবং এপিআই (API) এর মাধ্যমে রান করবেন তার বিস্তারিত কমান্ড দেওয়া হলো।

---

## ১. প্রজেক্টের প্রাথমিক প্রস্তুতি (Setup & Training)

ক্লিন রান নিশ্চিত করতে প্রথমে মডেল ট্রেনিং এবং কাস্টম ফিক্সচার ফাইলগুলো একত্রিত করে একটি ক্যানোনিকাল জেসন পে-লোড তৈরি করতে হবে।

* **মডেল ট্রেনিং রান করার কমান্ড:**
  ```bash
  python -m app.ml.train_cwe_classifier
  ```
* **স্ক্যানার ইন্টিগ্রেশন ফাইল একত্রিত করার কমান্ড:**
  ```bash
  python -m app.scanners.run_all --output output/scanner_findings_all.json
  ```

---

## ২. CLI (Command Line) এর মাধ্যমে সংস্করণ ৪ (v4) রান করার কমান্ড

পাওয়ারশেল (PowerShell) বা সিএমডি-তে এক লাইনে কপি করে নিচের কমান্ডগুলো রান করতে পারেন।

### Use Case ১: রুল-ভিত্তিক মোড (Rule Mode - Without ML)
বাস্তব স্ক্যানারের কাঁচা ফাইন্ডিংসের ওপর শুধুমাত্র রুল দিয়ে রান করতে:
```bash
python -m app.cli --input output/scanner_findings_all.json --pretty
```

### Use Case ২: মেশিন লার্নিং ও ভেক্টর ডাটাবেজ মোড (ML & SQLite Memory Mode)
ট্রেইনড ML CWE ক্লাসিফায়ার এবং SQLite মেমরি ব্যাকএন্ড সক্রিয় করে রান করতে:
```bash
python -m app.cli --input output/scanner_findings_all.json --use-ml --memory-backend sqlite --memory-file output/v4_memory.sqlite --pretty
```

### Use Case ৩: ওয়ান-ক্লিক V4 ডেমো রান
সবগুলো ধাপ একসাথে রান করতে ডেমো ব্যাচ স্ক্রিপ্ট ব্যবহার করুন:
* **উইন্ডোজ:**
  ```cmd
  scripts\run_v4_demo.bat
  ```
* **লিনাক্স/ম্যাক:**
  ```bash
  chmod +x scripts/*.sh
  ./scripts/run_v4_demo.sh
  ```

---

## ৩. স্ট্রিমলিট ওয়েব ড্যাশবোর্ড (Streamlit Dashboard Web GUI)

ড্যাশবোর্ডের মাধ্যমে ত্রুটিগুলো ভিজ্যুয়াল গ্রাফ আকারে দেখতে এবং ইন্টারেক্টিভ টেবিলে ফিল্টার করতে নিচের কমান্ডটি রান করুন:

```bash
streamlit run app/dashboard/streamlit_app.py
```
*(এটি স্বয়ংক্রিয়ভাবে আপনার ডিফল্ট ব্রাউজারে `http://localhost:8501` পোর্টে ড্যাশবোর্ডটি ওপেন করবে।)*

---

## ৪. পূর্ণাঙ্গ সিস্টেম বেঞ্চমার্ক ইভ্যালুয়েশন (Full System Benchmark)

পাইপলাইনের CWE ক্লাসিফিকেশন একুরেসি, ঝুঁকি রাংকিংয়ের যথার্থতা এবং WAF রুলের ভুল প্রস্তাবনা রেট পরিমাপ করতে নিচের বেঞ্চমার্ক কমান্ডটি রান করুন:

* **Rule-based Mode Benchmark:**
  ```bash
  python -m app.evaluation.full_benchmark --output output/full_benchmark_metrics.json --report output/full_benchmark_report.md
  ```
* **ML-based Mode Benchmark:**
  ```bash
  python -m app.evaluation.full_benchmark --use-ml --output output/full_benchmark_metrics_ml.json --report output/full_benchmark_report_ml.md
  ```

---

## ৫. REST API এর মাধ্যমে সংস্করণ ৪ (v4) রান করার কমান্ড

প্রথমে এপিআই সার্ভারটি চালু করুন:
```bash
uvicorn app.main:app --reload
```

সার্ভার চালু হওয়ার পর উইন্ডোজ পাওয়ারশেল অথবা লিনাক্স cURL ব্যবহার করে নিচের কমান্ড দিয়ে রিকোয়েস্ট পাঠাতে পারবেন।

### Use Case ১: ML & LLM মোড সক্রিয় করে এপিআই কল
এপিআই রিকোয়েস্টে ML এবং LLM মোড সক্রিয় করতে ইউআরএল শেষে কুয়েরি প্যারামিটার `?use_ml=true&use_llm=true` যোগ করতে হবে:

* **উইন্ডোজ পাওয়ারশেল (PowerShell) কমান্ড:**
  ```powershell
  Invoke-RestMethod -Uri "http://127.0.0.1:8000/triage/batch?use_ml=true&use_llm=true" -Method Post -InFile "output/scanner_findings_all.json" -Headers @{"Content-Type"="application/json"} | ConvertTo-Json -Depth 5
  ```
* **লিনাক্স/ম্যাক (cURL) cURL কমান্ড:**
  ```bash
  curl -X POST "http://127.0.0.1:8000/triage/batch?use_ml=true&use_llm=true" -H "Content-Type: application/json" -d @output/scanner_findings_all.json
  ```

### Use Case ২: হিউম্যান ফিডব্যাক এপিআইতে সাবমিট করা
মানুষের এপ্রুভাল বা প্রপোজাল প্রত্যাখ্যান সাবমিট করতে:

* **উইন্ডোজ পাওয়ারশেল (PowerShell) কমান্ড:**
  ```powershell
  $body = @{
      finding_id = "SEMGREP-001"
      decision = "approved"
      reviewer = "security_lead"
      notes = "Verified and WAF patch confirmed."
  } | ConvertTo-Json
  Invoke-RestMethod -Uri "http://127.0.0.1:8000/feedback" -Method Post -Body $body -Headers @{"Content-Type"="application/json"}
  ```
* **লিনাক্স/ম্যাক (cURL) কমান্ড:**
  ```bash
  curl -X POST "http://127.0.0.1:8000/feedback" -H "Content-Type: application/json" -d '{"finding_id": "SEMGREP-001", "decision": "approved", "reviewer": "security_lead", "notes": "Verified"}'
  ```

### Use Case ৩: জমা হওয়া ফিডব্যাক সামারি দেখা
* **কমান্ড:**
  ```bash
  curl http://127.0.0.1:8000/feedback/summary
  ```
