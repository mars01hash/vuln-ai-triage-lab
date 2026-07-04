# Vuln AI Triage Lab - বিভিন্ন মোড এবং ব্যবহারের নির্দেশিকা (Run Instructions)

এই ডকুমেন্টেশনে প্রজেক্টের বিভিন্ন ইউজ কেস (Use Case) যেমন— **Rules (Without ML) Mode**, **ML Mode**, **Persistent Memory Mode**, এবং **Batch Reporting Mode** কীভাবে কমান্ড লাইন (CLI) এবং এপিআই (API) এর মাধ্যমে রান করবেন তা বিস্তারিত কমান্ডসহ ব্যাখ্যা করা হলো।

---

## ১. প্রজেক্টের প্রাথমিক প্রস্তুতি (Setup & Training)

যেকোনো কমান্ড রান করার পূর্বে মডেলটি ট্রেইন করে রাখা ভালো। ট্রেইনিং স্ক্রিপ্ট রান করার কমান্ড:

* **উইন্ডোজ এবং লিনাক্স উভয় ক্ষেত্রে সাধারণ কমান্ড:**
  ```bash
  python -m app.ml.train_cwe_classifier
  ```

---

## ২. CLI (Command Line) এর মাধ্যমে বিভিন্ন ইউজ কেস রান করার কমান্ড

কমান্ড লাইনে আউটপুটগুলোকে সুন্দরভাবে সাজিয়ে পড়তে প্রতিটি কমান্ডের শেষে `--pretty` যুক্ত করা হয়েছে।

### Use Case ১: রুল-ভিত্তিক মোড (Rule Mode - Without ML)
মেশিন লার্নিং ব্যতিরেকে শুধুমাত্র ডিকশনারি কি-ওয়ার্ড ম্যাচিং ও হার্ডকোডেড রুলের মাধ্যমে ফাইল রান করাতে:

* **উইন্ডোজ এবং লিনাক্স (এক লাইনে):**
  ```bash
  python -m app.cli --input data/sample_findings_all.json --pretty
  ```

---

### Use Case ২: মেশিন লার্নিং মোড (ML Mode - With ML)
ট্রেইন করা TF-IDF + Logistic Regression ক্লাসিফায়ার ব্যবহার করে CWE নরমালাইজ করতে `--use-ml` ফ্ল্যাগটি যুক্ত করতে হবে:

* **উইন্ডোজ এবং লিনাক্স (এক লাইনে):**
  ```bash
  python -m app.cli --input data/sample_findings_all.json --use-ml --pretty
  ```

---

### Use Case ৩: পারসিস্টেন্ট মেমরি মোড (Persistent Memory Mode)
আগের ফাইন্ডিংগুলোর মেমরি সংরক্ষণ করতে এবং ডুপ্লিকেট সনাক্ত করতে `--memory-file` দিয়ে একটি JSON ফাইলের লোকেশন সেট করতে হবে:

* **উইন্ডোজ এবং লিনাক্স (এক লাইনে):**
  ```bash
  python -m app.cli --input data/sample_findings_all.json --memory-file output/memory.json --pretty
  ```

---

### Use Case ৪: ব্যাচ রিপোর্টিং মোড (Executive Batch Report Mode)
প্রসেসিং করা ফলাফলের ওপর ম্যানেজার-রিডেবল ব্যাচ সামারি রিপোর্ট জেনারেট করতে `--report` দিয়ে মার্কডাউন ফাইলের লোকেশন ডিক্লেয়ার করতে হবে:

* **উইন্ডোজ এবং লিনাক্স (এক লাইনে):**
  ```bash
  python -m app.cli --input data/sample_findings_all.json --use-ml --report output/batch_report.md --pretty
  ```

---

### Use Case ৫: একুরেসি মূল্যায়ন (CWE Classifier Evaluation)
আপনার ক্লাসিফায়ার মোডগুলোর পারফরম্যান্স তুলনা ও পরীক্ষা করতে:

* **Rule-based Classifier Evaluation:**
  ```bash
  python -m app.evaluation.evaluate --input data/eval_labeled_findings.json
  ```
* **ML-based Classifier Evaluation:**
  ```bash
  python -m app.evaluation.evaluate --input data/eval_labeled_findings.json --use-ml
  ```

---

## ৩. REST API এর মাধ্যমে বিভিন্ন ইউজ কেস রান করার কমান্ড

প্রথমে এপিআই সার্ভারটি চালু করুন:
```bash
uvicorn app.main:app --reload
```
সার্ভারটি সাধারণত `http://127.0.0.1:8000` পোর্টে রান হবে। এরপর নিচের অ্যান্ডপয়েন্টগুলোতে রিকোয়েস্ট পাঠাতে পারবেন।

### Use Case ১: Rule Mode (Without ML) - API
ইউআরএলে বাড়তি কোনো ফ্ল্যাগ না দিলে এটি ডিফল্ট রুল মোডে রান করবে।

* **উইন্ডোজ পাওয়ারশেল (PowerShell) কমান্ড:**
  ```powershell
  Invoke-RestMethod -Uri "http://127.0.0.1:8000/triage/batch" -Method Post -InFile "data/sample_findings_all.json" -Headers @{"Content-Type"="application/json"} | ConvertTo-Json -Depth 5
  ```
* **লিনাক্স/ম্যাক (cURL) কমান্ড:**
  ```bash
  curl -X POST "http://127.0.0.1:8000/triage/batch" -H "Content-Type: application/json" -d @data/sample_findings_all.json
  ```

---

### Use Case ২: ML Mode (With ML) - API
এপিআই রিকোয়েস্টে ML ক্লাসিফায়ার সচল করতে কুয়েরি প্যারামিটার `?use_ml=true` ব্যবহার করতে হবে।

* **উইন্ডোজ পাওয়ারশেল (PowerShell) কমান্ড:**
  ```powershell
  Invoke-RestMethod -Uri "http://127.0.0.1:8000/triage/batch?use_ml=true" -Method Post -InFile "data/sample_findings_all.json" -Headers @{"Content-Type"="application/json"} | ConvertTo-Json -Depth 5
  ```
* **লিনাক্স/ম্যাক (cURL) কমান্ড:**
  ```bash
  curl -X POST "http://127.0.0.1:8000/triage/batch?use_ml=true" -H "Content-Type: application/json" -d @data/sample_findings_all.json
  ```

---

### Use Case ৩: এপিআই মেমরি স্ট্যাটাস দেখা (Check API Memory Status)
এপিআই লাইফটাইমে কতগুলো রেকর্ড ডুপ্লিকেট হিসেবে চেক করা হয়েছে তার মেমরি সামারি দেখতে:

* **ব্রাউজারে ওপেন করুন:**
  ```text
  http://127.0.0.1:8000/memory/summary
  ```
* **টার্মিনাল থেকে কল করার কমান্ড (উইন্ডোজ ও লিনাক্স):**
  ```bash
  curl http://127.0.0.1:8000/memory/summary
  ```
