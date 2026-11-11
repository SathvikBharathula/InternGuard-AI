# InternGuard AI — Demonstration & Viva Presentation Guide

This guide provides instructions and test scenarios for presenting **InternGuard AI** during project demonstrations, evaluations, and viva sessions.

---

## 1. Application Startup Instructions

### Step 1: Open PowerShell / Command Prompt
Navigate to the project root directory:
```powershell
cd C:\Users\sathv\Desktop\MINI_PROJECT\AI-Powered-Fake-Job-Posting-Detection
```

### Step 2: Activate the Virtual Environment
```powershell
.\venv\Scripts\Activate.ps1
```
*(On standard Command Prompt: `venv\Scripts\activate.bat`)*

### Step 3: Configure Environment Variables (Optional)
If you wish to demonstrate the autonomous agent with live LLM tool calling:
1. Ensure `.env` exists in the project root:
   ```env
   GROQ_API_KEY=gsk_your_actual_key_here
   GROQ_MODEL=llama-3.3-70b-versatile
   ```
2. If no Groq API key is configured, the application **automatically operates in offline fallback mode** without crashing.

### Step 4: Start the Flask Application
```powershell
python app.py
```
Expected terminal output:
```
 * Serving Flask app 'app'
 * Debug mode: off
 * Running on http://127.0.0.1:5000
```

### Step 5: Open the Web Interface
Open your web browser and navigate to:
```
http://127.0.0.1:5000/
```

---

## 2. Demonstration Scenarios

> [!NOTE]
> All sample outputs below are **illustrative benchmark expectations** demonstrating the scoring and classification rules of the system. Actual live Groq telemetry depends on API configuration.

---

### Scenario A: Plausible / Legitimate Internship Posting

#### Input Details:
- **Internship Title**: `Software Engineering Intern - Cloud Systems`
- **Location**: `Bengaluru, Karnataka, India (Hybrid)`
- **Company Name**: `Microsoft Corporation`
- **Recruiter Contact Email**: `recruiting-apac@microsoft.com`
- **Company Website URL**: `https://www.microsoft.com`
- **Stipend / Compensation**: `₹45,000 / month`
- **Internship Description**:
  ```text
  Microsoft is looking for motivated Software Engineering Interns to join our Cloud Engineering team for a 6-month duration. Interns will work alongside senior software engineers building scalable distributed systems on Azure. Responsibilities include writing maintainable code in Python and C#, participating in agile code reviews, and automating testing pipelines.
  ```
- **Requirements & Qualifications**:
  ```text
  Currently enrolled in a Bachelor's or Master's program in Computer Science or related engineering discipline. Basic understanding of data structures, algorithms, and object-oriented programming. Familiarity with Git and RESTful APIs is preferred.
  ```

#### Expected Evaluation Behavior:
- **ML Fake Probability**: Typically very low (< 15%).
- **Rule-Based Screening**: 0 red flags detected.
- **Investigative Agent (if active)**:
  - Verifies email domain syntax and active corporate MX records.
  - Verifies website reachability (`https://www.microsoft.com`).
  - Analyzes description for standard eligibility criteria and professional tone.
- **Expected Outcome**:
  - **Verdict**: `LEGITIMATE`
  - **Risk Level**: `Low Risk` (Score: 0 – 25 / 100)
  - **Verified Indicators**: "Recruiter email domain has valid DNS MX records", "Company website is technically reachable (HTTP 200)".
  - **Explanation to Viva Examiner**: Technical reachability does not grant negative risk discounts (0 mitigation points awarded), preventing malicious actors with real domains from cheating the system.

---

### Scenario B: Suspicious Internship with Red Flags (Telegram / Unrealistic Claims)

#### Input Details:
- **Internship Title**: `Online Part-Time Assistant / Data Operator`
- **Location**: `Work from Home (Global)`
- **Company Name**: `Global Fast Hiring Group`
- **Recruiter Contact Email**: `fastrecruiter2024@gmail.com`
- **Company Website URL**: `http://www.globalfasthiring-freejobs.xyz`
- **Stipend / Compensation**: `₹15,000 per day guaranteed`
- **Internship Description**:
  ```text
  Urgent opening! Guaranteed selection for all candidates today. Earn up to ₹15,000 per day working only 1-2 hours daily from your mobile phone. No interview, no resume, and no prior experience needed. Instant appointment letter issued upon contact. Contact the HR coordinator immediately on Telegram @fast_hiring_now to confirm your slot before vacancies expire.
  ```
- **Requirements & Qualifications**:
  ```text
  Anyone with a smartphone and internet access. Immediate joining required today.
  ```

#### Expected Evaluation Behavior:
- **ML Fake Probability**: Elevated (statistical correlation with common job scam text).
- **Rule-Based Screening**: Multiple flags triggered:
  - Urgent hiring / artificial scarcity claims.
  - Unrealistic stipend / guaranteed income pattern.
  - Telegram-only recruitment channel.
  - Public freemail recruiter address (`@gmail.com`).
- **Investigative Agent (if active)**:
  - Flags Telegram contact requirement as a high-risk evasive communication channel.
  - Identifies non-standard top-level domain (`.xyz`) and warns about lack of verifiable corporate presence.
- **Expected Outcome**:
  - **Verdict**: `SUSPICIOUS` or `LIKELY FAKE`
  - **Risk Level**: `Medium` to `High Risk` (Score: 50 – 85 / 100)
  - **Explanation to Viva Examiner**: Points out how multiple independent signals (urgent pressure, untraceable chat apps, inflated daily pay) compound in the evidence score breakdown.

---

### Scenario C: Advance-Fee Exploitation Scheme (Training / Security Fee)

#### Input Details:
- **Internship Title**: `Graduate Trainee - Python Web Developer`
- **Location**: `Hyderabad, India`
- **Company Name**: `Apex Tech Career Solutions`
- **Recruiter Contact Email**: `hr@apexcareersolutions.in`
- **Company Website URL**: `https://www.apexcareersolutions.in`
- **Stipend / Compensation**: `₹25,000 / month`
- **Internship Description**:
  ```text
  We are hiring fresher software developer interns. Candidates will undergo hands-on development on client projects with guaranteed job offer upon completion. Selected candidates must pay a mandatory refundable security deposit of ₹3,500 towards study materials, cloud infrastructure setup, and certification registration. The amount will be refunded in the first monthly stipend payout. Payments must be remitted via UPI before the orientation session.
  ```
- **Requirements & Qualifications**:
  ```text
  B.Tech / MCA freshers. Basic knowledge of Python. Must submit payment receipt to secure seat.
  ```

#### Expected Evaluation Behavior:
- **Rule-Based Screening**: Direct hit on advance-fee heuristic:
  - `advance_fee_requested`: "Mandatory refundable security deposit / registration fee detected."
- **Investigative Agent (if active)**:
  - `payment_detector` tool confirms upfront payment demand for materials/security deposit.
- **Risk Score Breakdown**:
  - Financial exploitation score: capped at **45 points**.
  - Total evidence capped at **75 points**.
- **Expected Outcome**:
  - **Verdict**: `LIKELY FAKE`
  - **Risk Level**: `High Risk` (Score: 70 – 95 / 100)
  - **Recommendation**: "CRITICAL WARNING: The posting explicitly requests advance payments (registration/security/training fee). Legitimate employers do not require candidates to pay for employment. Do not transfer funds or share payment credentials."
  - **Explanation to Viva Examiner**: Highlights that genuine employers never ask interns to pay for jobs. The system enforces a strict 45-point cap on financial exploitation and prioritizes actual fee demands over any potential disclaimer text.

---

## 3. Demonstrating Fallback Mode (Groq Unconfigured)

### Test Procedure:
1. Ensure the `GROQ_API_KEY` environment variable is unset or empty:
   ```powershell
   Remove-Item Env:\GROQ_API_KEY -ErrorAction SilentlyContinue
   ```
2. Submit any internship posting via the web interface.
3. Observe the result:
   - **No Crash / No Hang**: Flask returns HTTP 200 promptly.
   - **Agent Status Badge**: Displays `Unconfigured` (or `Agent Investigation Skipped`).
   - **Transparent Reporting**: The verification dashboard explicitly notes:
     *"Autonomous agent investigation was skipped because GROQ_API_KEY is not configured on the backend. Verification is operating using ML prediction and deterministic rule screening."*
   - **Score Breakdown**: Base ML score (0–20) and Rule screening score (0–20) are computed correctly, ensuring the system remains completely functional even in air-gapped or offline environments.

---

## 4. Key Talking Points for the College Viva / Examination

When explaining the project to professors and examiners, structure your answers around these architectural highlights:

1. **Why not use just an LLM or just an ML model?**
   - *Standalone ML* provides rapid classification but lacks explainability, context, and cannot browse websites or check DNS.
   - *Standalone LLMs* can hallucinate, cost significantly more per query, and may change opinions unpredictably.
   - *InternGuard AI's Hybrid Approach* uses ML for statistical baseline, heuristic rules for strict legal/financial boundaries, and an autonomous agent with concrete deterministic tools for verification.

2. **How does the autonomous agent avoid infinite loops or high costs?**
   - The agent operates in a ReAct loop with a hard round limit (`MAX_ROUNDS = 5`).
   - It maintains a call history to prevent duplicate tool queries with identical parameters.
   - Individual tool timeouts (5s) and error trapping ensure that network dropouts or invalid domains do not stall execution.

3. **What is SSRF protection and why is it critical in this application?**
   - A fake company could submit a website URL like `http://127.0.0.1:5000/admin` or `http://169.254.169.254/latest/meta-data/` to probe internal server resources.
   - InternGuard AI's `website_verifier` resolves the domain DNS and verifies that IP addresses do not belong to loopback (`127.0.0.0/8`), private networks (`RFC 1918`), or cloud metadata IPs before issuing any HTTP request.

4. **Why do working websites and valid emails award 0.0 mitigation points?**
   - In earlier prototypes, having an active website subtracted risk points. However, fraudsters frequently purchase cheap domains or link to real corporate homepages.
   - In the final scoring design, technical signals are reported as *technical observations* but never reduce the fraud score.
