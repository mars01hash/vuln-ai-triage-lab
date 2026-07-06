# Vuln AI Triage Lab - v5 to v6 এর আপডেট সমূহ

এই ডকুমেন্টে Vuln AI Triage Lab এর পঞ্চম সংস্করণ (v5) থেকে ষষ্ঠ সংস্করণ (v6) এ কী কী পরিবর্তন ও নতুন ফিচার যুক্ত করা হয়েছে তার বিস্তারিত বিবরণ দেওয়া হলো।

---

## ১. সংক্ষেপে v5 এবং v6 এর তুলনামূলক পার্থক্য

| ফিচার এলাকা | সংস্করণ ৫ (v5) | সংস্করণ ৬ (v6) |
| :--- | :--- | :--- |
| **ফিচার এক্সট্রাকশন (Feature Extraction)** | শুধুমাত্র TF-IDF (Term Frequency-Inverse Document Frequency) ব্যবহার করে শব্দ কি-ওয়ার্ড গণনা করা হতো। | **Sentence-Transformers Embeddings** (`all-MiniLM-L6-v2`) যুক্ত করা হয়েছে যা শব্দের গভীর অর্থগত মিল বিশ্লেষণ করে। |
| **মডেল সাইজ ও মেমরি ফুটপ্রিন্ট** | TF-IDF এর জন্য ফাইল সাইজ ছোট ছিল, কিন্তু ডিপ লার্নিং মডেলে বড় সাইজ এড়ানোর অপশন ছিল না। | কাস্টম **Dynamic State Pickling** এবং **Lazy-Loading** যুক্ত করা হয়েছে, ফলে ভারী পিকেল বাদ দিয়ে মডেলের জবলিব সাইজ মাত্র **২০ কিলোবাইটে** নেমে এসেছে। |
| **CLI কন্ট্রোল** | শুধুমাত্র `--use-ml` ফ্ল্যাগ ছিল, ব্যাকএন্ড কনফিগারেশনের আলাদা অপশন ছিল না। | `--encoder` (`tfidf` অথবা `embeddings`) এবং `--embedding-model` কমান্ড আর্গুমেন্ট যুক্ত করা হয়েছে। |
| **টেস্ট কাভারেজ (Automated Tests)** | শুধুমাত্র বেসিক ক্যালিব্রেশন এবং পলিসি টেস্ট। | সেন্টেন্স এনকোডারের সিরিয়ালাইজেশন, লেজি লোডিং এবং ইনফারেন্স টেস্টিং নিশ্চিত করতে মক (Mock) টেস্ট কেস যুক্ত করা হয়েছে। |

---

## ২. নতুন মডিউল ও কোড ফাইলের বিস্তারিত বিবরণ

সংস্করণ ৬ (v6) এ যুক্ত হওয়া নতুন লজিক ও পরিবর্তনের ভূমিকা নিচে ব্যাখ্যা করা হলো:

### ক. কাস্টম সেন্টেন্স-ট্রান্সফরমার এনকোডার
* **ফাইল:** [cwe_ml_classifier.py](file:///g:/vuln-ai-triage-lab/app/ml/cwe_ml_classifier.py)
* **কাজ:** এটি `sklearn` এর `BaseEstimator` এবং `TransformerMixin` ব্যবহার করে একটি কাস্টম ট্র্যান্সফরমার ক্লাস ইমপ্লিমেন্ট করে।
  * `__getstate__`: মডেল ডাম্প বা পিকেল করার সময় ভারী পাইটর্চ ওয়েটস রেফারেন্স মুছে দেয়।
  * `__setstate__`: পিকেল লোড করার সময় মডেল অবজেক্ট খালি রাখে এবং প্রথমবার প্রেডিকশন রান করার সময় এটি অলস লোডিং (Lazy Load) করে।

### খ. ট্রেইনিং আর্গুমেন্ট ও মডেল ভার্সন কন্ট্রোল
* **ফাইল:** [train_cwe_classifier.py](file:///g:/vuln-ai-triage-lab/app/ml/train_cwe_classifier.py)
* **কাজ:**
  * `--encoder`: ডিফল্ট `tfidf` এর পাশাপাশি `embeddings` মোড সাপোর্ট করে।
  * `--embedding-model`: প্রাক-প্রশিক্ষিত (Pre-trained) Sentence-Transformers মডেলের নাম নির্ধারণ করে।
  * মেটাডেটাতে মডেল ভার্সন (যেমন: `embeddings_all-MiniLM-L6-v2_logreg_v1`) স্বয়ংক্রিয়ভাবে জেনারেট করে।

---

## ৩. ইন্টিগ্রেশন ও রানিং কমান্ডের পরিবর্তন

v6 পাইপলাইনে মডেল ট্রেইন এবং টেস্ট করার নতুন কমান্ড সমূহ:

### ক. এমবেডিংস ব্যবহার করে মডেল ট্রেইনিং
```bash
.venv\Scripts\python -m app.ml.train_cwe_classifier --input data/cwe_training_findings.jsonl --output models/cwe_tfidf_logreg.joblib --metrics output/cwe_training_metrics.json --encoder embeddings
```
* `--encoder embeddings`: সেন্টেন্স এমবেডিংস ব্যবহার করার জন্য বাধ্য করে।

### খ. অটোমেটেড টেস্ট রান
এমবেডিংস ও লেজি লোডিংয়ের সঠিকতা যাচাই করতে:
```bash
pytest tests/test_v5_calibration_and_policy.py
```

### গ. মডেল ক্যালিব্রেশন ও ইভালুয়েশন রান
```bash
.venv\Scripts\python -m app.evaluation.model_calibration --input data/sample_findings_all.json --labels data/eval_labeled_findings.json --output output/v5_cwe_calibration_metrics.json --report output/v5_cwe_calibration_report.md
```

---

## ৪. কেন এই আপডেটগুলো করা হলো? (Rationale)

১. **শব্দার্থের গভীর বিশ্লেষণ (Deep Semantic Triage):** অনেক সময় SAST এবং DAST স্ক্যানার রিপোর্টে হুবহু কি-ওয়ার্ড (যেমন: "SQL Injection") লেখা থাকে না। Sentence-Transformers ব্যবহারের ফলে বাক্যগুলোর ভেতরের লুকায়িত অর্থ অনুধাবন করে মডেল অত্যন্ত নিখুঁতভাবে সঠিক CWE ট্যাগ করতে পারে।
২. **রিসোর্স ও স্টোরেজ অপ্টিমাইজেশন (Zero Weight Overhead):** এমবেডিংস মডেলগুলোর ওয়েট সাধারণত ১০০MB+ বা তার বেশি হয়ে থাকে। কাস্টম সিরিয়ালাইজেশন ফাইল সাইজ মাত্র ২০KB-তে সীমাবদ্ধ রাখে, যা নেটওয়ার্ক ব্যান্ডউইডথ ও ডিস্ক স্পেস সাশ্রয় করে।
৩. **ইলাস্টিক মডেল ইন্টিগ্রেশন:** পাইপলাইন ডিক্লারেশনে কোনো পরিবর্তন না এনেই Scikit-learn Pipeline এর প্রথম স্টেপটি পরিবর্তন করা হয়েছে, ফলে মূল এপিআই সার্ভার কোনো ডাউনটাইম বা পরিবর্তন ছাড়াই সরাসরি রান হতে পারে।
