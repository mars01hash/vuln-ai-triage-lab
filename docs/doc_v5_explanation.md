# Vuln AI Triage Lab v5 - প্রজেক্ট পরিচিতি ও কার্যপ্রণালী

এই প্রজেক্টটি একটি **AI-assisted AppSec vulnerability intelligence pipeline** বা স্বয়ংক্রিয় নিরাপত্তা ত্রুটি সনাক্তকরণ ও ট্রিয়েজ পাইপলাইন। এটি বিভিন্ন সিকিউরিটি টুলস (যেমন: SAST, DAST, SCA) থেকে প্রাপ্ত র ফিন্ডিংগুলোকে (raw findings) গ্রহণ করে সেগুলোকে একটি নির্দিষ্ট স্ট্যান্ডার্ডে রূপান্তর করে, ডুপ্লিকেট সনাক্ত করে, ত্রুটির গুরুত্ব অনুযায়ী স্কোরিং করে এবং ভার্চুয়াল প্যাচ বা WAF (Web Application Firewall) রুল প্রোপোজাল তৈরি করে।

সংস্করণ ৫ (v5) এ আগের ভেক্টর মেমরি ও স্ক্যানার অ্যাডাপ্টারের ওপরে একটি **মডেল ক্যালিব্রেশন মডিউল (Multiclass Brier score, Expected Calibration Error)**, **থ্রেট ইনটেলিজেন্স এনরিচমেন্ট লেয়ার (exploit probability/CISA KEV)**, **কলগ্রাফ-ভিত্তিক স্ট্যাটিক রিচিবিলিটি গেট (Callgraph route match)**, **ফিডব্যাক রিট্রেনিং লুপ (augmented feedback to training)**, **কমপ্লায়েন্স অডিট লগার (JSONL logging)** এবং **MCP (Model Context Protocol) টুলস ইন্টারফেস** যুক্ত করা হয়েছে।

নিচে প্রতিটি কম্পোনেন্ট কীভাবে এবং কেন কাজ করে তা বাংলায় বিস্তারিত ব্যাখ্যা করা হলো।

---

## ১. ডাটা ফ্লো (System Architecture & Data Flow)

পাইপলাইনে ডাটা ফ্লো বা প্রসেসিং নিচের ধাপগুলো অনুসরণ করে সম্পন্ন হয়:

```mermaid
graph TD
    A1[Raw Scanner Output: Semgrep/ZAP/Dep-Check] --> A2[Scanner Adapters: Parse JSON to schema]
    A2 --> B[Parse to VulnerabilityFinding model]
    B --> C[Pipeline Orchestrator: TriagePipeline]
    C --> D1{CWE Classifier Mode}
    D1 -- ML -- > D2[ML Classifier: TF-IDF + LogReg]
    D1 -- Rules --> D3[Rule-based Classifier: Keywords Map]
    D2 & D3 --> D4[Threat Intel Enrichment: Exploit/KEV signal]
    D4 --> E1[Callgraph Reachability Gate Check]
    E1 --> E2[Entity Extractor]
    C --> F1[SQLite Vector Memory: Deduplication check]
    C --> G[Priority Scorer: Exploitability-weighted risk scoring]
    C --> H[WAF Proposal Gate Check]
    C --> I[OpenAI LLM / Local Triage Agent]
    I --> K[Deterministic Approval Policy]
    K --> J[NormalizedFinding Output]
    J --> L1[Streamlit Dashboard Web GUI]
    J --> L2[Audit Logger: Append to JSONL]
    J --> L3[Feedback retraining loop: Augment model]
    J --> L4[CWE Calibration Metrics Evaluator]
```

---

## ২. প্রতিটি নতুন ও পরিবর্তিত কম্পোনেন্টের বিস্তারিত কোড ব্যাখ্যা

### ক. থ্রেট ইনটেলিজেন্স এনরিচমেন্ট (Threat Intelligence Enrichment)
* **ফাইল:** [enrichment.py](file:///g:/vuln-ai-triage-lab/app/threat_intel/enrichment.py)
* **কীভাবে কাজ করে:** 
  * এটি পাইপলাইনের ভেতরে ফাইন্ডিংগুলোর ওপর সক্রিয় শোষণের (exploitation) লাইভ ডাটা যোগ করে।
  * এটি `data/threat_intel_signals.json` ফিক্সচার ফাইল থেকে নির্দিষ্ট CWE আইডি অথবা SCA প্যাকেজের নামের সাথে মিলিয়ে এক্সপ্লয়েট লাইকলিহুড স্কোর (`exploit_likelihood`) এবং wild-exploitation ফ্ল্যাগ টেনে নিয়ে এসে ফাইন্ডিং অবজেক্টের সাথে যুক্ত করে।
  * কোনো ত্রুটির wild-exploitation ফ্ল্যাগ অন থাকলে বা স্কোর `0.85` বা তার বেশি হলে এটি সরাসরি ফাইন্ডিংটিকে "Exploit Available" হিসেবে চিহ্নিত করে পরবর্তী ঝুঁকি স্কোর বাড়িয়ে দেয়।

---

### খ. কলগ্রাফ-ভিত্তিক রিচিবিলিটি গেট (Callgraph Reachability Gate)
* **ফাইল:** [callgraph_reachability.py](file:///g:/vuln-ai-triage-lab/app/reachability/callgraph_reachability.py)
* **কীভাবে কাজ করে:** 
  * আগে শুধু এপিআই এন্ডপয়েন্ট সাফিক্স ম্যাচ করে রিচিবিলিটি মাপা হতো। সংস্করণ ৫-এ এটি সত্যিকারের স্ট্যাটিক অ্যানালাইসিস ফাইলের প্রবাহ বা কলগ্রাফ (Callgraph map) সিমুলেট করতে পারে।
  * এটি `data/callgraph_routes.json` থেকে আক্রান্ত সোর্স ফাইল পাথ এবং আক্রান্ত এন্ডপয়েন্টকে কোড ট্র্যাসিংয়ের ম্যাপিং ফাইলের সাথে মিলিয়ে দেখে সেই কোড ডোমেনটি আদৌ লাইভ ব্রাউজার ট্রাফিকের সাথে যুক্ত কিনা (Reachable) নাকি ডেড কোড (Dead code)। এটি নিশ্চিত করতে সাহায্য করে যে SCA এবং SAST ফাইন্ডিংসগুলো ফেক বা ফালস পজিটিভ নয়।

---

### গ. হিউম্যান ফিডব্যাক রিট্রেনিং লুপ (Retraining Loop)
* **ফাইল:** [build_training_set.py](file:///g:/vuln-ai-triage-lab/app/feedback/build_training_set.py)
* **কীভাবে কাজ করে:**
  * সিকিউরিটি অ্যানালিস্টরা যখন এপিআই বা ড্যাশবোর্ড থেকে ভুল CWE প্রেডিকশন ঠিক করেন (যেমন: `corrected_cwe` ফিল্ডের মাধ্যমে), তখন পাইপলাইনের ফিডব্যাক অ্যান্ডপয়েন্ট সেটি `api_human_feedback.jsonl` ফাইলে সংরক্ষণ করে।
  * এই স্ক্রিপ্টটি পূর্বের বেস ট্রেনিং ফাইলের সাথে মানুষের দেওয়া নতুন কারেকশনের টেক্সট সমন্বয় করে নতুন একটি বর্ধিত ট্রেনিং ডাটা সেট (`cwe_training_augmented_from_feedback.jsonl`) তৈরি করে এবং মডেলটিকে পুনরায় ট্রেন করার প্রসেস সম্পন্ন করে। এটি প্রজেক্টে একটি ডাইনামিক সেলফ-লার্নিং আর্কিটেকচার প্রদান করে।

---

### ঘ. কমপ্লায়েন্স অডিট লগার (Compliance Audit Logger)
* **ফাইল:** [audit_logger.py](file:///g:/vuln-ai-triage-lab/app/audit/audit_logger.py)
* **কীভাবে কাজ করে:**
  * অডিটিং এবং গভর্নেন্স কমপ্লায়েন্স নিশ্চিত করার জন্য, এটি প্রতিটি ফাইন্ডিং প্রসেসিংয়ের সময় নেওয়া গুরুত্বপূর্ণ ব্যাকএন্ড সিদ্ধান্তগুলো (যেমন: প্রেডিকশন কনফিডেন্স, প্রায়োরিটি ওয়েট, রিচিবিলিটি লজিক, মানুষের এপ্রুভাল রিকোয়ারমেন্টস) একটি অ্যাপেন্ড-অনলি জেসন লাইনস (`v5_audit_log.jsonl`) ফাইলে ডাম্প করে সেভ করে। এটি প্রজেক্টের কাজের সত্যতা প্রমাণ করতে ব্যবহৃত ফরেনসিক ওডিট ট্রেইল হিসেবে কাজ করে।

---

### ঙ. এমসিপি টুলস ইন্টারফেস (Model Context Protocol)
* **ফাইল:** [tool_contracts.py](file:///g:/vuln-ai-triage-lab/app/mcp/tool_contracts.py)
* **কীভাবে কাজ করে:**
  * পাইপলাইনের কোর ফাংশনগুলোকে LLM এজেন্ট যাতে সরাসরি এক্সিকিউট করতে পারে, সেজন্য এটি স্ট্যান্ডার্ড ডিকশনারি ফরম্যাটের টুল ডিক্লারেশন এবং ইনপুট/আউটপুট জেসন স্কিমা এক্সপোজ করে (যেমন: `normalize_vulnerability_to_cwe`, `enrich_with_threat_intel`)।

---

## ৩. মডেল ক্যালিব্রেশন ও বিশ্বস্ততা মূল্যায়ন (CWE Calibration Metrics)

সংস্করণ ৫ (v5)-এ শুধু Accuracy বা F1 স্কোরের ওপর ভরসা না করে মডেলের আত্মবিশ্বাস বা কনফিডেন্স ক্যালিব্রেশনের জন্য অত্যন্ত গুরুত্বপূর্ণ ম্যাথমেটিক্যাল ক্যালকুলেশন মডিউল যুক্ত করা হয়েছে:

* **মডিউল:** [app/ml/calibration.py](file:///g:/vuln-ai-triage-lab/app/ml/calibration.py) ও [app/evaluation/model_calibration.py](file:///g:/vuln-ai-triage-lab/app/evaluation/model_calibration.py)

### প্রধান ৩টি ক্যালিব্রেশন মেথডোলজি:
১. **Multiclass Brier Score:** এটি মডেলের প্রেডিক্ট করা সম্ভাব্য ডিস্ট্রিবিউশন এবং প্রকৃত ওয়ানের (One-hot actual label) মধ্যবর্তী গড় বর্গের পার্থক্য (mean squared error) পরিমাপ করে। স্কোর যত কম হবে (যেমন `0.0` এর কাছাকাছি), মডেলের প্রোবাবিলিটি স্কোর তত নিখুঁত।
২. **Expected Calibration Error (ECE):** মডেলের প্রেডিকশন কনফিডেন্সকে ৫টি বিনে (যেমন: ০.০ থেকে ০.২, ০.২ থেকে ০.৪ ইত্যাদি) ভাগ করা হয়। প্রতিটি বিনে কতগুলো উদাহরণ আছে এবং সেই বিনের প্রেডিকশন করা কনফিডেন্সের সাথে গড় সঠিকতা (Accuracy) এর গ্যাপ কতো, তা মেপে ECE বের করা হয়।
৩. **Reliability Bins Map:** প্রতিটি কনফিডেন্স বিনের বিস্তারিত আউটপুট মেপে জেসন ও মার্কডাউন ডল রিপোর্ট তৈরি করে, যা ডেভেলপারদের বোঝাতে সাহায্য করে যে মডেলের প্রেডিকশন কনফিডেন্স কি আসলেই বাস্তবের নির্ভুলতার সাথে মিলে যাচ্ছে কিনা।

---

## ৪. প্রজেক্টের গুরুত্বপূর্ণ সেফটি রুলস (Strict Safety Rules)

* **Threat intel override limits:** থ্রেট ইনটেলিজেন্স স্কোরকে অগ্রাধিকার দিলেও স্কোরিংয়ের ফাইনাল ওয়েটগুলো ডিটারমিনিস্টিক বাইজেন ইকুয়েশনে প্রসেস করা হয়।
* **Callgraph priority:** কলগ্রাফ ম্যাপ যদি কোনো ফাইলকে স্পষ্ট মৃত বা ডেড কোড (`unreachable_files`) বলে ঘোষণা করে, পাইপলাইন সেটিকে ফিজিক্যালি ব্লক বা ডিপ্যারোটিজ করতে বাধ্য থাকে।
* **Compliance immutability:** অডিট লগগুলো কোনোভাবে এডিট বা মডিফাই করা যায় না, এটি অ্যাপেন্ড-অনলি রাইটার দিয়ে প্রতি রান শেষে মেমরিতে পুশ করা হয়।
