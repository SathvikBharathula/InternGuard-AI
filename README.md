# 🛡️ InternGuard AI — Agentic AI-Based Fake Internship Detection & Verification System

[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.0-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-Academic%20%2F%20MIT-yellow.svg)](#)
[![Tests Status](https://img.shields.io/badge/Tests-86%2F86%20Passing-brightgreen.svg)](#running-the-test-suite)

**InternGuard AI** is an intelligent, multi-tiered verification platform engineered to protect students and fresh graduates from deceptive internship offers, advance-fee employment scams, and identity harvesting schemes.

Unlike traditional static classifiers that emit black-box probabilities, InternGuard AI combines **Statistical Machine Learning (TF-IDF + Logistic Regression)**, **Deterministic Heuristic Screening**, and an **Autonomous Groq-Powered Investigation Agent** to inspect recruiter credentials, external domains, and linguistic patterns, outputting a transparent, evidence-based verification report.

---

## 📌 Table of Contents
1. [Problem Statement & Motivation](#-problem-statement--motivation)
2. [Key Features](#-key-features)
3. [System Architecture & Multi-Tier Pipeline](#-system-architecture--multi-tier-pipeline)
4. [The Verification Engine](#-the-verification-engine)
   - [Machine Learning Predictor](#1-machine-learning-predictor)
   - [Deterministic Rule Screener](#2-deterministic-rule-screener)
   - [Autonomous Investigation Agent](#3-autonomous-investigation-agent)
   - [Four Specialized Verification Tools](#4-four-specialized-verification-tools)
   - [Evidence-Based Risk Scoring](#5-evidence-based-risk-scoring)
5. [Technology Stack](#-technology-stack)
6. [Project Folder Structure](#-project-folder-structure)
7. [Step-by-Step Windows Setup Guide](#-step-by-step-windows-setup-guide)
8. [Configuration (.env)](#-configuration-env)
9. [Running the Application](#-running-the-application)
10. [Running the Test Suite](#-running-the-test-suite)
11. [Example Usage & Sample Outputs](#-example-usage--sample-outputs)
12. [Security Protections](#-security-protections)
13. [Limitations & Future Enhancements](#-limitations--future-enhancements)
14. [Viva & Project Evaluation Summary](#-viva--project-evaluation-summary)

---

## 🎯 Problem Statement & Motivation

College students and fresh graduates are disproportionately targeted by fraudulent job and internship postings online. Common attack patterns include:
- **Advance-Fee Scams**: Demanding upfront "registration fees", "training material charges", or "refundable equipment security deposits".
- **Evasive Communication**: Conducting interviews strictly via Telegram or WhatsApp to evade enterprise tracking.
- **Phishing & Impersonation**: Using public free emails (`@gmail.com`) while claiming to represent Fortune 500 corporations, or registering typosquatted domains.
- **Unrealistic Earnings**: Luring young applicants with guaranteed selection and exorbitant daily stipends without interviews or qualifications.

Traditional detection approaches rely solely on static text classification, which suffers from high false-positive rates and cannot verify real-world external entities (such as email domain DNS records or company websites). **InternGuard AI solves this with active, autonomous verification.**

---

## ✨ Key Features

- **Multi-Tier Hybrid Detection**: Integrates statistical text classification, rule-based red-flag heuristics, and live agentic web verification.
- **Autonomous Tool-Calling Agent**: Employs an LLM agent (Groq Llama-3.3-70b) that independently decides which external verification tools to invoke based on available posting details.
- **Live Technical Entity Checking**:
  - Validates recruiter email syntax and queries DNS for active MX records.
  - Checks domain reachability over HTTP while blocking SSRF (Server-Side Request Forgery) attacks.
  - Scans for disposable/temporary email domains.
- **Advance-Fee & Coercion Detection**: Distinguishes genuine payment demands from benign negative disclaimers ("No fees are charged").
- **Transparent Risk Scoring (0–100)**: Displays an explicit mathematical score breakdown (ML baseline + heuristic score + capped investigative evidence).
- **Graceful Offline Degradation**: Works seamlessly even when Groq API keys are unconfigured or unavailable, falling back reliably to ML and heuristic screening without crashing.
- **Production-Grade Input Constraints**: Strict request size protection (1 MB limit, HTTP 413) and field length limits to prevent abuse.

---

## 🏗️ System Architecture & Multi-Tier Pipeline

InternGuard AI processes every internship posting through four sequential tiers:

```
[ Frontend Form (Browser) ]
            │ (POST /predict JSON)
            ▼
┌─────────────────────────────────────────────────────────────┐
│ Tier 1: Request & Input Validation (app.py)                 │
│ - 1 MB request envelope cap (HTTP 413)                      │
│ - Field length validation (HTTP 400 with exact counts)      │
│ - Strict non-truncation policy                              │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ Tier 2: Parallel Statistical & Heuristic Analysis           │
│ ├─ MLPredictor: TF-IDF (5,000 features) + Logistic Reg      │
│ └─ RuleScreener: 30+ regex patterns & payment rules         │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ Tier 3: Autonomous Groq Investigation Agent (core/agent.py) │
│ - Decides investigation plan using ReAct loop               │
│ - Executes specialized tools (Email, Web, Text, Fee)        │
│ - Enforces max 5 rounds + duplicate invocation prevention   │
│ - Graceful degradation if GROQ_API_KEY is unset             │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ Tier 4: Evidence-Based Report Generation (report_generator) │
│ - Evidence deduplication & scoring caps (45-pt fee, 75-pt)  │
│ - Zero-mitigation policy for passive technical reachability │
│ - Actionable student recommendations & unverified checklist │
└──────────────────────────┬──────────────────────────────────┘
            │
            ▼
[ Interactive Dashboard UI / JSON Response ]
```

---

## 🔍 The Verification Engine

### 1. Machine Learning Predictor
- **Module**: `core/ml_predictor.py`
- **Model**: Pre-trained `LogisticRegression` with balanced class weights.
- **Feature Extraction**: `TfidfVectorizer` (5,000 max features, sublinear term-frequency scaling, English stop-words).
- **Baseline Training Data**: EMSCAD (Employment Scam Aegean Dataset) containing 8,835 real and fake postings.
- **Output**: Fake probability ($0.0 \dots 1.0$), statistical verdict (`LEGITIMATE` / `SUSPICIOUS` / `FAKE`), and classification confidence.

### 2. Deterministic Rule Screener
- **Module**: `core/rule_screener.py`
- **Heuristic Engine**: Regular expressions targeting:
  - Advance payment requests (registration, application fee, laptop deposit).
  - Suspicious communication channels (Telegram username, WhatsApp-only hiring).
  - Unrealistic compensation claims (e.g., ₹20,000/day for zero experience).
  - Urgent pressure tactics (guaranteed spot, 24-hour expiration).
- **Smart Negation Parsing**: Uses contextual lookbehinds to avoid flagging statements like *"No registration fees are charged"* as scams.

### 3. Autonomous Investigation Agent
- **Module**: `core/agent.py`
- **LLM Engine**: Groq Cloud API running `llama-3.3-70b-versatile`.
- **Role**: Operates strictly as an investigator (collects evidence, executes tools, records observations). It **never** decides the final risk score or verdict directly, preventing LLM score inconsistency.
- **Safety Bounds**: Hard-capped at 5 iterative rounds; records errors without throwing unhandled exceptions.

### 4. Four Specialized Verification Tools

Located under [`core/tools/`](file:///C:/Users/sathv/Desktop/MINI_PROJECT/AI-Powered-Fake-Job-Posting-Detection/core/tools/):

| Tool | Module | Purpose & Capabilities |
|---|---|---|
| **`CompanyWebsiteVerificationTool`** | `website_verifier.py` | Validates website syntax; checks HTTP reachability; enforces strict **SSRF protection** by rejecting private IPs (RFC 1918), localhost loopbacks (`127.0.0.1`), and cloud metadata (`169.254.169.254`). |
| **`EmailVerificationTool`** | `email_verifier.py` | Validates RFC 5322 email syntax; resolves domain DNS MX records; identifies public freemail domains (`gmail.com`); flags known disposable email providers. |
| **`InternshipDescriptionAnalysisTool`** | `description_analyzer.py` | Analyzes description text for vague requirements, urgency tactics, unrealistic compensation claims, and guaranteed selection promises. |
| **`PaymentRequestDetectionTool`** | `payment_detector.py` | Scans for advance fees, equipment deposits, and unusual payment routing (crypto, wire, personal payment apps); separates benign disclaimers from demands. |

### 5. Evidence-Based Risk Scoring

Synthesized in [`core/report_generator.py`](file:///C:/Users/sathv/Desktop/MINI_PROJECT/AI-Powered-Fake-Job-Posting-Detection/core/report_generator.py):
$$\text{Risk Score} = \min(100, \max(0, \text{Base Score} + \text{Evidence Score}))$$

- **Base Score (Max 40 pts)**:
  $$\text{Base Score} = (\text{ML Fake Probability} \times 20) + (\text{Normalized Heuristic Score} \times 20)$$
- **Evidence Additions**: Points added for confirmed indicators (disposable email domain, fee demand, unreachable company domain).
- **Hard Caps**:
  - Financial exploitation evidence: capped at **45 points**.
  - Combined investigative evidence: capped at **75 points**.
- **Zero-Mitigation Rule**: Technical signals (HTTP 200 or active MX records) award **0.0 negative mitigation points** because having an active domain does not prove corporate legitimacy.

#### Risk Classification Thresholds:
- **0 – 30**: `Low Risk` — **LEGITIMATE**
- **31 – 70**: `Medium Risk` — **SUSPICIOUS**
- **71 – 100**: `High Risk` — **LIKELY FAKE**

---

## 💻 Technology Stack

- **Backend**: Python 3.10+, Flask 3.0, Werkzeug, Jinja2
- **Machine Learning**: Scikit-learn, NumPy, SciPy, Joblib
- **Agentic AI & LLM**: Groq Cloud API (`groq` Python SDK, `llama-3.3-70b-versatile`)
- **Networking & DNS**: `dnspython`, `urllib.request`, Python `ipaddress` and `socket`
- **Frontend**: Responsive HTML5, Vanilla CSS3 (modern glassmorphism design), Vanilla JavaScript (ES6 fetch API)
- **Testing**: Python `unittest`, `unittest.mock`

---

## 📁 Project Folder Structure

```
AI-Powered-Fake-Job-Posting-Detection/
├── app.py                      # Flask backend entrypoint & API endpoints
├── fake_job_model.pkl          # Pre-trained Logistic Regression model (SHA-256 preserved)
├── tfidf.pkl                   # Pre-fitted TF-IDF vectorizer (SHA-256 preserved)
├── job_train.csv               # Baseline training dataset (SHA-256 preserved)
├── fake_job_detection.ipynb    # Training notebook & exploratory data analysis
├── requirements.txt            # Python dependencies
├── .env.example                # Configuration template (safe to commit)
├── .gitignore                  # Git ignore rules for venv, .env, pycache
├── README.md                   # Complete project documentation
│
├── core/                       # Core system modules
│   ├── __init__.py
│   ├── ml_predictor.py         # ML text cleaner, vectorizer & classifier wrapper
│   ├── rule_screener.py        # Heuristic rules & regex pattern matcher
│   ├── agent.py                # Autonomous Groq investigation agent (ReAct loop)
│   ├── report_generator.py     # Multi-tier evidence aggregator & risk scorer
│   └── tools/                  # Verification tools called by the agent
│       ├── __init__.py
│       ├── website_verifier.py     # Website URL & SSRF verification tool
│       ├── email_verifier.py       # Email syntax & DNS MX record verification tool
│       ├── description_analyzer.py # Linguistic pattern analysis tool
│       └── payment_detector.py     # Advance fee & deposit detection tool
│
├── docs/                       # Technical documentation
│   ├── architecture.md         # Detailed architectural design & Mermaid workflow
│   └── demo_guide.md           # Step-by-step viva presentation & demo guide
│
├── static/                     # Frontend static assets
│   ├── css/
│   │   └── style.css           # Glassmorphic, modern responsive CSS
│   └── js/
│       └── main.js             # Form handler, UI animations, dashboard renderer
│
├── templates/
│   └── index.html              # Interactive single-page dashboard interface
│
└── tests/                      # Automated unittest test suites (86 tests)
    ├── test_phase2_app.py          # Phase 2: ML inference & API schema tests (10)
    ├── test_phase3_tools.py        # Phase 3: All 4 verification tools tests (26)
    ├── test_phase4_agent.py        # Phase 4: Autonomous Groq agent tests (12)
    ├── test_phase5_report.py       # Phase 5: Risk scoring & report generator tests (12)
    ├── test_phase6_backend.py      # Phase 6: Backend integration tests (3)
    ├── test_phase6_frontend.py     # Phase 6: Frontend DOM & asset tests (5)
    ├── test_phase7_validation.py   # Phase 7: Comprehensive scenario tests (13)
    └── test_phase7_input_limits.py # Phase 7: Field limits & payload security tests (5)
```

---

## 🚀 Step-by-Step Windows Setup Guide

Follow these instructions in **Windows PowerShell** or **Command Prompt**:

### 1. Open PowerShell and Navigate to the Project
```powershell
cd C:\Users\sathv\Desktop\MINI_PROJECT\AI-Powered-Fake-Job-Posting-Detection
```

### 2. Verify Python Installation
Ensure Python 3.10, 3.11, or 3.12 is installed:
```powershell
python --version
```

### 3. Create a Virtual Environment (if not already created)
```powershell
python -m venv venv
```

### 4. Activate the Virtual Environment
- **In PowerShell**:
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
  *(If PowerShell displays an `Execution_Policies` warning, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` once).*
- **In standard CMD**:
  ```cmd
  venv\Scripts\activate.bat
  ```

### 5. Install Dependencies
```powershell
pip install -r requirements.txt
```

---

## ⚙️ Configuration (.env)

The project includes a `.env.example` file. To enable the live Groq autonomous agent:

1. Create a `.env` file in the project root:
   ```powershell
   Copy-Item .env.example .env
   ```
2. Open `.env` in any text editor and supply your Groq API key:
   ```env
   GROQ_API_KEY=gsk_your_actual_key_here
   GROQ_MODEL=llama-3.3-70b-versatile
   ```

> [!NOTE]
> **A Groq API key is completely optional!**
> If you do not have an API key, the system automatically runs in **offline fallback mode**, leveraging the ML predictor and deterministic rule screener without crashing.

---

## 🖥️ Running the Application

Ensure your virtual environment is active, then execute:

```powershell
python app.py
```

Expected terminal startup:
```
2026-11-09 16:50:00,123 [INFO] InternGuardAI: ML model and TF-IDF vectorizer loaded successfully.
2026-11-09 16:50:00,125 [INFO] InternGuardAI: Rule screener initialized with 30+ regex patterns.
 * Serving Flask app 'app'
 * Running on http://127.0.0.1:5000
```

Open your browser and visit: **`http://127.0.0.1:5000/`**

---

## 🧪 Running the Test Suite

InternGuard AI features a comprehensive automated test suite consisting of **86 unit and integration tests** with 100% pass rate.

Run all tests using Python's standard `unittest` discovery:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

Expected terminal output:
```
----------------------------------------------------------------------
Ran 86 tests in ~4.2s

OK
```

### Test Suite Breakdown:
- **Phase 2 (`test_phase2_app.py`)**: 10 tests (endpoints, ML inference, error handling).
- **Phase 3 (`test_phase3_tools.py`)**: 26 tests (SSRF, redirects, MX queries, fee parsing).
- **Phase 4 (`test_phase4_agent.py`)**: 12 tests (ReAct loop, tool dispatch, error tolerance).
- **Phase 5 (`test_phase5_report.py`)**: 12 tests (evidence scoring, caps, neutrality).
- **Phase 6 Backend (`test_phase6_backend.py`)**: 3 tests (Groq configuration flow).
- **Phase 6 Frontend (`test_phase6_frontend.py`)**: 5 tests (DOM IDs, static assets, forms).
- **Phase 7 Validation (`test_phase7_validation.py`)**: 13 tests (end-to-end scenarios A–F).
- **Phase 7 Limits (`test_phase7_input_limits.py`)**: 5 tests (field lengths, 1MB limit).

---

## 📋 Example Usage & Sample Outputs

### Example 1: Web Interface Form Submission
1. Navigate to `http://127.0.0.1:5000/`.
2. Enter the internship details:
   - **Title**: `Software Development Intern`
   - **Company**: `Innovatech Labs`
   - **Recruiter Email**: `careers@innovatechlabs.com`
   - **Website**: `https://www.innovatechlabs.com`
   - **Stipend**: `₹25,000 / month`
   - **Description**: `Join our backend engineering team building Python microservices...`
3. Click **Analyze Internship**.
4. The dashboard renders the circular Risk Score meter, verdict badge, ML probability bar, agent telemetry, and actionable student safety checklist.

### Example 2: Direct API Call via cURL / PowerShell

```powershell
$headers = @{ "Content-Type" = "application/json" }
$body = @{
    title = "Data Science Intern"
    description = "Work on predictive modeling using Python and pandas."
    company_name = "Acme Analytics"
    contact_email = "hr@acmeanalytics.com"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:5000/predict" -Method Post -Headers $headers -Body $body
```

#### Sample JSON Response:
```json
{
  "report": {
    "verdict": "LEGITIMATE",
    "risk_level": "Low Risk",
    "risk_score": 12,
    "confidence_score": 85,
    "summary": "Internship posting displays standard corporate parameters with low risk indicators.",
    "ml_assessment": {
      "prediction": "Legitimate",
      "fake_probability": 0.082,
      "confidence": 85.0
    },
    "score_breakdown": {
      "ml_score": 1.64,
      "heuristic_score": 0.0,
      "base_score": 1.64,
      "uncapped_evidence_score": 0.0,
      "applied_evidence_cap": 75.0,
      "final_evidence_score": 0.0,
      "combined_raw_score": 1.64,
      "final_risk_score": 12
    },
    "recommendations": [
      "Review the formal offer letter prior to joining.",
      "Never share banking credentials or OTPs during an onboarding process."
    ]
  }
}
```

---

## 🔒 Security Protections

1. **Server-Side Request Forgery (SSRF) Defense**:
   All website URLs submitted by users are resolved to IP addresses and checked against private/reserved ranges before making network requests. Calls targeting `127.0.0.1`, RFC 1918 subnets (`10.x`, `172.16.x`, `192.168.x`), or cloud metadata services (`169.254.169.254`) are blocked.
2. **Payload Flooding Protection**:
   Incoming request bodies are limited to **1 MB** (`MAX_CONTENT_LENGTH`). Requests exceeding this size are rejected at the WSGI gateway with HTTP 413.
3. **Field Length Enforcement**:
   All eight input fields enforce server-side maximum character boundaries (e.g., Description: 20,000 characters; Title: 200 characters) to prevent memory exhaustion and large token consumption.
4. **Secret Isolation**:
   `GROQ_API_KEY` is loaded strictly through server-side environment variables and is never transmitted to the frontend or exposed in client responses.

---

## ⚠️ Limitations & Future Enhancements

### Current Limitations:
1. **Network Reachability vs. Authenticity**:
   A website returning an HTTP 200 response or an email domain possessing MX records indicates technical reachability, but does not prove the employer is authentic (fraudsters can register real domains or reference real corporate URLs). The system therefore awards zero mitigation points for reachable domains.
2. **Dataset Training Distribution**:
   The baseline ML model is trained on the EMSCAD dataset. While highly accurate on standard postings, highly specialized regional terminology relies primarily on the heuristic and agentic layers.
3. **Groq Cloud Rate Limits**:
   Live LLM agent analysis is subject to standard Groq API rate limits when high volumes of concurrent requests are processed.

### Planned Enhancements:
- **Transformer NLP Integration**: Fine-tuning a lightweight DistilBERT model for deeper semantic understanding of deceptive language.
- **Enterprise Verification APIs**: Integrating LinkedIn Company API and official registrar lookups (e.g., MCA/Companies House).
- **Domain Age Lookup**: Querying WHOIS registration age to detect freshly created fraudulent domains.

---

## 🎓 Viva & Project Evaluation Summary

| Viva Question | Concise Project Answer |
|---|---|
| **What makes this project different from basic fake job detectors?** | Traditional systems only run text through an ML classifier. InternGuard AI uses a **hybrid multi-tier approach** combining statistical ML, deterministic red-flag heuristics, and an **autonomous investigation agent** that actively checks domain DNS and web reachability. |
| **Why not let an LLM decide the final risk score directly?** | LLM scoring lacks mathematical determinism, varies between runs, and cannot be easily audited. In InternGuard AI, the LLM acts solely as an **investigator** collecting evidence, while a deterministic **ReportGenerator** computes the bounded score using transparent arithmetic. |
| **How does the system prevent SSRF attacks?** | The `CompanyWebsiteVerificationTool` resolves domain names to IP addresses via DNS and checks them against loopback (`127.0.0.1`), private RFC 1918 subnets, and cloud metadata IPs (`169.254.169.254`) before making any HTTP request. |
| **How does the system behave if the Groq API key is missing?** | It degrades gracefully. The backend catches the unconfigured state, skips the LLM investigation, marks external signals as `unverified`, and outputs a complete risk report using the ML model and heuristic screener. |
