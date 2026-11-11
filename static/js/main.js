// ═══════════════════════════════════════════════════════════════════════════
//  InternGuard AI — Immersive 3D Threat Intelligence & Verification JS
//  Cinematic Canvas 3D Particle Sphere + Multi-Tier Forensic Engine
// ═══════════════════════════════════════════════════════════════════════════

// ── Sample Internship Benchmark Scenarios ───────────────────────────────────
const SAMPLES = [
  {
    label: "fake",
    name: "Data Entry Internship Scam",
    desc: "Advance-fee training & registration deposit scheme",
    title: "Remote Data Entry Intern — Earn $5000/week (No Experience Needed)",
    location: "Remote / Online",
    company_name: "Apex Global Solutions",
    contact_email: "apex.hiring.team@gmail.com",
    company_url: "http://apex-jobs-portal.xyz",
    stipend: "$5,000 / week (Registration fee required)",
    description:
      "We are hiring data entry interns to work from home. No experience required. You will earn guaranteed income of $5000 per week. Send money via western union for your starter kit. Bitcoin payments accepted. Click here to apply now and start earning fast!",
    requirements:
      "Must be 18 or older. No skills needed. Just send $99 upfront fee for training materials and background check fee.",
  },
  {
    label: "legit",
    name: "Software Engineering Intern",
    desc: "Mentored backend developer role at verified company",
    title: "Software Engineering Intern — Backend (Python/Django)",
    location: "US, CA, San Francisco (Hybrid)",
    company_name: "DataPulse Analytics Inc.",
    contact_email: "careers@datapulse.io",
    company_url: "https://www.datapulse.io",
    stipend: "$4,500 / month + Mentorship",
    description:
      "We are looking for a passionate software engineering intern to join our growing platform team. You will assist in designing REST APIs, collaborate with senior mentors, and participate in code reviews. We offer competitive stipend, learning budget, and full mentorship.",
    requirements:
      "3+ years of coursework in Computer Science or equivalent. Familiarity with Python, Django, PostgreSQL and Git. Strong understanding of REST API design principles.",
  },
  {
    label: "fake",
    name: "Campus Brand Ambassador Scam",
    desc: "Wire transfer / fake check money-mule scam",
    title: "Student Brand Ambassador & Mystery Shopper Intern",
    location: "Remote / Campus",
    company_name: "Swift Retail Marketing",
    contact_email: "recruiting-swift@yahoo.com",
    company_url: "http://swift-rewards-portal.top",
    stipend: "$3,500 / week",
    description:
      "Earn up to $3500 per week as a student brand ambassador! We will send you an initial check. Cash it, keep your student stipend portion, and wire transfer the rest via western union or purchase gift cards. Guaranteed income with no experience required! Interviewing now!",
    requirements:
      "Must be 18 or older. No experience required. Training fee of $50 applies.",
  },
  {
    label: "legit",
    name: "Data Science & ML Intern",
    desc: "Structured research internship with supervisor",
    title: "Data Science & Machine Learning Intern",
    location: "London, UK (Hybrid)",
    company_name: "NeuroTech Labs",
    contact_email: "talent@neurotechlabs.ai",
    company_url: "https://neurotechlabs.ai",
    stipend: "£2,200 / month",
    description:
      "Join our analytics and machine learning team for a 6-month internship. You will build NLP pipelines, analyze structured tabular datasets, and collaborate with senior data scientists. Clear learning milestones and supervisor assigned.",
    requirements:
      "Pursuing degree in Computer Science, Statistics or Data Science. Proficient in SQL and Python (Pandas, Scikit-learn). Experience with data visualization and strong communication skills.",
  },
];

// ── DOM References (All 46 IDs preserved for tests) ──────────────────────────
const form            = document.getElementById("jobForm");
const btnAnalyze      = document.getElementById("btnAnalyze");
const btnText         = document.getElementById("btnText");
const spinner         = document.getElementById("spinner");
const resultPanel     = document.getElementById("resultPanel");
const samplesGrid     = document.getElementById("samplesGrid");
const toast           = document.getElementById("toast");
const toastMsg        = document.getElementById("toastMsg");

// Form inputs
const titleInput        = document.getElementById("titleInput");
const locationInput     = document.getElementById("locationInput");
const descriptionInput  = document.getElementById("descriptionInput");
const requirementsInput = document.getElementById("requirementsInput");
const companyInput      = document.getElementById("companyInput");
const emailInput        = document.getElementById("emailInput");
const websiteInput      = document.getElementById("websiteInput");
const stipendInput      = document.getElementById("stipendInput");

// Verdict & Score Banner
const verdictBanner   = document.getElementById("verdictBanner");
const verdictIcon     = document.getElementById("verdictIcon");
const verdictHeading  = document.getElementById("verdictHeading");
const verdictSub      = document.getElementById("verdictSub");
const riskBadge       = document.getElementById("riskBadge");
const riskScoreNum    = document.getElementById("riskScoreNum");
const riskScoreBar    = document.getElementById("riskScoreBar");
const gaugeCircle     = document.getElementById("gaugeCircle");

// Agent Telemetry
const agentStatusPill   = document.getElementById("agentStatusPill");
const agentStatusDesc   = document.getElementById("agentStatusDesc");
const toolsExecutedList = document.getElementById("toolsExecutedList");

// Machine Learning Card
const fakePct             = document.getElementById("fakePct");
const legitPct            = document.getElementById("legitPct");
const probBar             = document.getElementById("probBar");
const mlScoreContribution = document.getElementById("mlScoreContribution");
const mlModelArchitecture = document.getElementById("mlModelArchitecture");
const mlDisclaimer        = document.getElementById("mlDisclaimer");

// Deterministic Breakdown Card
const calcSummaryBox      = document.getElementById("calcSummaryBox");
const cappedSummaryRow    = document.getElementById("cappedSummaryRow");
const scoreIndicatorsList = document.getElementById("scoreIndicatorsList");

// Detailed Indicators Sections
const suspiciousCard      = document.getElementById("suspiciousCard");
const suspiciousList      = document.getElementById("suspiciousList");
const rulesCard           = document.getElementById("rulesCard");
const rulesList           = document.getElementById("rulesList");
const forensicCard        = document.getElementById("forensicCard");
const forensicList        = document.getElementById("forensicList");
const verifiedCard        = document.getElementById("verifiedCard");
const verifiedList        = document.getElementById("verifiedList");
const unverifiedCard      = document.getElementById("unverifiedCard");
const unverifiedList      = document.getElementById("unverifiedList");
const limitationsList     = document.getElementById("limitationsList");
const recommendationsSection = document.getElementById("recommendationsSection");
const recommendationsList = document.getElementById("recommendationsList");

// Loading Overlay
const scanLoadingPanel    = document.getElementById("scanLoadingPanel");
const scanPipelineStatus  = document.getElementById("scanPipelineStatus");
const analysisTimestamp   = document.getElementById("analysisTimestamp");

// Verification Module Elements
const modStatusEmail      = document.getElementById("modStatusEmail");
const modFindingsEmail    = document.getElementById("modFindingsEmail");
const modStatusPayment    = document.getElementById("modStatusPayment");
const modFindingsPayment  = document.getElementById("modFindingsPayment");
const modStatusDesc       = document.getElementById("modStatusDesc");
const modFindingsDesc     = document.getElementById("modFindingsDesc");
const modStatusWebsite    = document.getElementById("modStatusWebsite");
const modFindingsWebsite  = document.getElementById("modFindingsWebsite");


// ── Safe DOM Element Creation Helper (Required by tests) ─────────────────────
function createEl(tag, className, textContent) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (textContent !== undefined && textContent !== null) {
    el.textContent = textContent;
  }
  return el;
}


// ── 3D Particle Sphere Canvas Engine ─────────────────────────────────────────
class ParticleSphereEngine {
  constructor(canvasId, containerId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext("2d");
    this.container = document.getElementById(containerId);
    
    this.particles = [];
    this.numParticles = window.innerWidth < 768 ? 400 : 800;
    this.radius = 165;
    this.fov = 380;
    
    this.angleX = 0.2;
    this.angleY = 0;
    this.targetRotX = 0.15;
    this.targetRotY = 0;
    this.autoSpeedY = 0.0035;
    this.autoSpeedX = 0.0015;
    
    this.mouseX = 0;
    this.mouseY = 0;
    this.isHovering = false;
    this.isRunning = true;
    
    this.init();
  }

  init() {
    this.resize();
    this.buildSphere();
    this.bindEvents();
    this.animate(0);
  }

  resize() {
    const rect = this.canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    this.canvas.width = (rect.width || 440) * dpr;
    this.canvas.height = (rect.height || 440) * dpr;
    this.ctx.scale(dpr, dpr);
    this.width = rect.width || 440;
    this.height = rect.height || 440;
    this.centerX = this.width / 2;
    this.centerY = this.height / 2;
  }

  buildSphere() {
    this.particles = [];
    const phi = Math.PI * (3 - Math.sqrt(5)); // Golden angle

    for (let i = 0; i < this.numParticles; i++) {
      const y = 1 - (i / (this.numParticles - 1)) * 2;
      const radiusAtY = Math.sqrt(Math.max(0, 1 - y * y));
      const theta = phi * i;

      const x = Math.cos(theta) * radiusAtY;
      const z = Math.sin(theta) * radiusAtY;

      // 80% warm gold/white, 20% electric cyan/blue
      const isBlue = (i % 6 === 0);
      const isGold = (i % 3 === 0);
      const baseSize = isBlue ? 1.7 : (isGold ? 1.4 : 1.1);

      this.particles.push({
        origX: x * this.radius,
        origY: y * this.radius,
        origZ: z * this.radius,
        isBlue: isBlue,
        isGold: isGold,
        baseSize: baseSize,
        phase: Math.random() * Math.PI * 2,
        pulseSpeed: 0.002 + Math.random() * 0.003
      });
    }
  }

  bindEvents() {
    window.addEventListener("resize", () => this.resize());

    if (this.container) {
      this.container.addEventListener("mousemove", (e) => {
        const rect = this.container.getBoundingClientRect();
        const mx = e.clientX - rect.left - rect.width / 2;
        const my = e.clientY - rect.top - rect.height / 2;
        this.targetRotY = (mx / (rect.width / 2)) * 0.75;
        this.targetRotX = -(my / (rect.height / 2)) * 0.65;
        this.isHovering = true;
      });

      this.container.addEventListener("mouseleave", () => {
        this.isHovering = false;
        this.targetRotX = 0.15;
      });
    }

    // Pause when off-screen to save CPU/GPU cycles
    if ("IntersectionObserver" in window) {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          this.isRunning = entry.isIntersecting;
        });
      }, { threshold: 0.05 });
      observer.observe(this.canvas);
    }
  }

  animate(time) {
    requestAnimationFrame((t) => this.animate(t));
    if (!this.isRunning) return;

    // Smooth lerp rotation toward target
    this.angleY += this.autoSpeedY;
    this.angleX += (this.targetRotX - this.angleX) * 0.04;
    const currentRotY = this.angleY + this.targetRotY * 0.6;

    this.ctx.clearRect(0, 0, this.width, this.height);

    const cosY = Math.cos(currentRotY);
    const sinY = Math.sin(currentRotY);
    const cosX = Math.cos(this.angleX);
    const sinX = Math.sin(this.angleX);

    const projected = [];

    // Project each particle in 3D
    for (let i = 0; i < this.particles.length; i++) {
      const p = this.particles[i];

      // Subtle organic breathing pulsation
      const breathe = 1 + Math.sin(time * p.pulseSpeed + p.phase) * 0.04;
      const px = p.origX * breathe;
      const py = p.origY * breathe;
      const pz = p.origZ * breathe;

      // Rotate Y
      const x1 = px * cosY + pz * sinY;
      const z1 = -px * sinY + pz * cosY;
      const y1 = py;

      // Rotate X
      const y2 = y1 * cosX - z1 * sinX;
      const z2 = y1 * sinX + z1 * cosX;
      const x2 = x1;

      // Perspective projection
      const scale = this.fov / (this.fov + z2);
      const projX = this.centerX + x2 * scale;
      const projY = this.centerY + y2 * scale;

      // Depth alpha (front is bright, back is dim)
      const depthRatio = (z2 + this.radius) / (this.radius * 2);
      const alpha = Math.max(0.12, Math.min(1.0, 1.05 - depthRatio * 0.85));

      projected.push({
        x: projX,
        y: projY,
        z: z2,
        scale: scale,
        alpha: alpha,
        isBlue: p.isBlue,
        isGold: p.isGold,
        size: p.baseSize * scale * (z2 < 0 ? 1.3 : 0.8)
      });
    }

    // Sort by z-depth for correct painter order (back to front)
    projected.sort((a, b) => b.z - a.z);

    // Draw subtle constellation connections between nearest front particles
    const connectLimit = window.innerWidth < 768 ? 24 : 32;
    for (let i = 0; i < projected.length; i += 3) {
      const p1 = projected[i];
      if (p1.z > 20) continue; // Only front half

      for (let j = i + 1; j < Math.min(i + 12, projected.length); j++) {
        const p2 = projected[j];
        if (p2.z > 20) continue;

        const dx = p1.x - p2.x;
        const dy = p1.y - p2.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < connectLimit) {
          const lineAlpha = (1 - dist / connectLimit) * 0.22 * p1.alpha;
          this.ctx.beginPath();
          this.ctx.moveTo(p1.x, p1.y);
          this.ctx.lineTo(p2.x, p2.y);
          if (p1.isBlue || p2.isBlue) {
            this.ctx.strokeStyle = `rgba(0, 212, 255, ${lineAlpha * 1.3})`;
          } else {
            this.ctx.strokeStyle = `rgba(255, 215, 120, ${lineAlpha})`;
          }
          this.ctx.lineWidth = 0.75;
          this.ctx.stroke();
        }
      }
    }

    // Draw particle points
    for (let i = 0; i < projected.length; i++) {
      const p = projected[i];
      this.ctx.beginPath();
      this.ctx.arc(p.x, p.y, Math.max(0.5, p.size), 0, Math.PI * 2);

      if (p.isBlue) {
        this.ctx.fillStyle = `rgba(0, 220, 255, ${p.alpha * 1.1})`;
        if (p.z < -40) {
          this.ctx.shadowBlur = 8;
          this.ctx.shadowColor = "rgba(0, 212, 255, 0.7)";
        } else {
          this.ctx.shadowBlur = 0;
        }
      } else if (p.isGold) {
        this.ctx.fillStyle = `rgba(255, 215, 120, ${p.alpha})`;
        if (p.z < -40) {
          this.ctx.shadowBlur = 6;
          this.ctx.shadowColor = "rgba(255, 215, 120, 0.5)";
        } else {
          this.ctx.shadowBlur = 0;
        }
      } else {
        this.ctx.fillStyle = `rgba(255, 255, 255, ${p.alpha * 0.85})`;
        this.ctx.shadowBlur = 0;
      }

      this.ctx.fill();
    }
    this.ctx.shadowBlur = 0;
  }
}


// ── Build Sample Cards ───────────────────────────────────────────────────────
function buildSamples() {
  if (!samplesGrid) return;
  samplesGrid.innerHTML = "";
  SAMPLES.forEach((s, i) => {
    const card = createEl("div", "sample-card");
    card.id = `sampleCard${i}`;
    card.setAttribute("role", "button");
    card.setAttribute("tabindex", "0");
    card.setAttribute("aria-label", `Load benchmark scenario: ${s.name}`);

    const badge = createEl(
      "span",
      `sample-badge ${s.label}`,
      s.label === "fake" ? "⚠ SCAM VECTOR" : "✓ VERIFIED POSTING"
    );

    const info = createEl("div", "sample-info");
    const name = createEl("span", "sample-name", s.name);
    const desc = createEl("span", "sample-desc", s.desc);
    info.appendChild(name);
    info.appendChild(desc);

    card.appendChild(badge);
    card.appendChild(info);

    const loadAction = () => loadSample(s);
    card.addEventListener("click", loadAction);
    card.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        loadAction();
      }
    });

    samplesGrid.appendChild(card);
  });
}

function loadSample(s) {
  titleInput.value        = s.title || "";
  locationInput.value     = s.location || "";
  descriptionInput.value  = s.description || "";
  requirementsInput.value = s.requirements || "";
  companyInput.value      = s.company_name || "";
  emailInput.value        = s.contact_email || "";
  websiteInput.value      = s.company_url || "";
  stipendInput.value      = s.stipend || "";

  showToast(`✧ Loaded scenario: "${s.name}" — Click Start Investigation to test.`, "info");
  const scannerSection = document.getElementById("scanner");
  if (scannerSection) {
    scannerSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}


// ── Toast Notification ───────────────────────────────────────────────────────
let toastTimer = null;
function showToast(msg, type = "info") {
  if (!toast || !toastMsg) return;
  toastMsg.textContent = msg;
  toast.className = `toast ${type} show`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 4500);
}


// ── Animate Number Counter ───────────────────────────────────────────────────
function animateNumber(el, target, suffix = "%", duration = 850) {
  if (!el) return;
  const start = performance.now();
  const from  = parseFloat(el.textContent) || 0;
  function step(now) {
    const t = Math.min((now - start) / duration, 1);
    const eased = t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
    el.textContent = (from + (target - from) * eased).toFixed(suffix ? 1 : 0) + suffix;
    if (t < 1) requestAnimationFrame(step);
    else el.textContent = (suffix ? target.toFixed(1) : Math.round(target)) + suffix;
  }
  requestAnimationFrame(step);
}


// ── Update Circular SVG Gauge Meter ──────────────────────────────────────────
function updateGauge(score) {
  if (!gaugeCircle) return;
  const radius = 68;
  const circumference = 2 * Math.PI * radius; // ~427.26
  const offset = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;
  
  gaugeCircle.style.strokeDasharray = `${circumference}`;
  gaugeCircle.style.strokeDashoffset = `${offset}`;
  
  if (score >= 70) {
    gaugeCircle.style.stroke = "var(--accent-crimson)";
    gaugeCircle.style.filter = "drop-shadow(0 0 12px rgba(255, 51, 102, 0.6))";
  } else if (score >= 30) {
    gaugeCircle.style.stroke = "var(--accent-amber)";
    gaugeCircle.style.filter = "drop-shadow(0 0 12px rgba(245, 158, 11, 0.5))";
  } else {
    gaugeCircle.style.stroke = "var(--accent-gold)";
    gaugeCircle.style.filter = "drop-shadow(0 0 12px rgba(255, 215, 120, 0.6))";
  }
}


// ── Render Dedicated Forensic Verification Modules ───────────────────────────
function renderVerificationModules(data, report) {
  const toolsExecuted = data.tools_executed || [];
  const findings = report.investigation_findings || [];
  const verified = report.verified_indicators || [];
  const suspicious = report.suspicious_indicators || [];
  const ruleFindings = report.rule_based_findings || data.red_flags || [];

  const filterFindings = (kwList) => {
    return findings.filter((f) => {
      const txt = `${f.tool || ""} ${f.category || ""} ${f.message || ""}`.toLowerCase();
      return kwList.some((kw) => txt.includes(kw));
    });
  };

  // 1. Email Verification Module
  if (modStatusEmail && modFindingsEmail) {
    const hasEmail = Boolean(emailInput.value.trim());
    const isExecuted = toolsExecuted.includes("verify_email");
    const emailFindings = filterFindings(["email", "mx", "domain", "disposable"]);
    const emailSuspicious = suspicious.filter(s => s.toLowerCase().includes("email") || s.toLowerCase().includes("domain"));
    const emailVerified = verified.filter(v => v.toLowerCase().includes("email") || v.toLowerCase().includes("mx"));

    if (emailSuspicious.length > 0 || emailFindings.some(f => f.severity === "HIGH" || f.severity === "CRITICAL")) {
      modStatusEmail.textContent = "SUSPICIOUS";
      modStatusEmail.className = "tool-status-pill danger";
      modFindingsEmail.textContent = emailSuspicious[0] || emailFindings[0]?.message || "Suspicious or disposable domain detected.";
    } else if (emailVerified.length > 0) {
      modStatusEmail.textContent = "VERIFIED SIGNAL";
      modStatusEmail.className = "tool-status-pill verified";
      modFindingsEmail.textContent = emailVerified[0] || "Valid syntax; DNS MX records resolved.";
    } else if (isExecuted) {
      modStatusEmail.textContent = "INSPECTED";
      modStatusEmail.className = "tool-status-pill verified";
      modFindingsEmail.textContent = "Email syntax and domain checked by agent.";
    } else if (hasEmail) {
      modStatusEmail.textContent = "PARSED";
      modStatusEmail.className = "tool-status-pill warning";
      modFindingsEmail.textContent = "Recruiter email provided; live network check was offline/skipped.";
    } else {
      modStatusEmail.textContent = "UNPROVIDED";
      modStatusEmail.className = "tool-status-pill";
      modFindingsEmail.textContent = "No recruiter contact email provided in posting.";
    }
  }

  // 2. Payment Request Detection Module
  if (modStatusPayment && modFindingsPayment) {
    const isExecuted = toolsExecuted.includes("verify_payment_requests");
    const feeRules = ruleFindings.filter(r => r.toLowerCase().includes("fee") || r.toLowerCase().includes("deposit") || r.toLowerCase().includes("payment"));
    const feeSuspicious = suspicious.filter(s => s.toLowerCase().includes("fee") || s.toLowerCase().includes("deposit") || s.toLowerCase().includes("payment") || s.toLowerCase().includes("advance"));

    if (feeSuspicious.length > 0 || feeRules.length > 0) {
      modStatusPayment.textContent = "FEE DEMAND DETECTED";
      modStatusPayment.className = "tool-status-pill danger";
      modFindingsPayment.textContent = feeSuspicious[0] || feeRules[0] || "Upfront fee or security deposit detected.";
    } else if (isExecuted) {
      modStatusPayment.textContent = "CLEARED";
      modStatusPayment.className = "tool-status-pill verified";
      modFindingsPayment.textContent = "Payment detector tool confirmed no upfront fee or deposit demands.";
    } else {
      modStatusPayment.textContent = "NO DEMAND FOUND";
      modStatusPayment.className = "tool-status-pill verified";
      modFindingsPayment.textContent = "No advance fee requests detected in job text.";
    }
  }

  // 3. Description Linguistic Analysis Module
  if (modStatusDesc && modFindingsDesc) {
    const isExecuted = toolsExecuted.includes("analyze_internship_description");
    const descFindings = filterFindings(["urgency", "unrealistic", "earnings", "vague", "guaranteed"]);
    const descRules = ruleFindings.filter(r => r.toLowerCase().includes("urgent") || r.toLowerCase().includes("guaranteed") || r.toLowerCase().includes("stipend") || r.toLowerCase().includes("telegram"));

    if (descRules.length > 0 || descFindings.length > 0) {
      modStatusDesc.textContent = "RED FLAGS DETECTED";
      modStatusDesc.className = "tool-status-pill danger";
      modFindingsDesc.textContent = descRules[0] || descFindings[0]?.message || "High-pressure tactics or unusual recruitment channels.";
    } else if (isExecuted) {
      modStatusDesc.textContent = "STANDARD TONE";
      modStatusDesc.className = "tool-status-pill verified";
      modFindingsDesc.textContent = "Description reflects standard professional responsibilities.";
    } else {
      modStatusDesc.textContent = "STANDARD VOCABULARY";
      modStatusDesc.className = "tool-status-pill verified";
      modFindingsDesc.textContent = "Corpus exhibits normal recruiting language without pressure tactics.";
    }
  }

  // 4. Company Website & SSRF Verification Module
  if (modStatusWebsite && modFindingsWebsite) {
    const hasWebsite = Boolean(websiteInput.value.trim());
    const isExecuted = toolsExecuted.includes("verify_company_website");
    const webVerified = verified.filter(v => v.toLowerCase().includes("website") || v.toLowerCase().includes("http"));
    const webSuspicious = suspicious.filter(s => s.toLowerCase().includes("website") || s.toLowerCase().includes("url") || s.toLowerCase().includes("ssrf"));

    if (webSuspicious.length > 0) {
      modStatusWebsite.textContent = "DOMAIN ISSUE";
      modStatusWebsite.className = "tool-status-pill danger";
      modFindingsWebsite.textContent = webSuspicious[0] || "Website unreachable or blocked by SSRF filter.";
    } else if (webVerified.length > 0) {
      modStatusWebsite.textContent = "REACHABLE (HTTP 200)";
      modStatusWebsite.className = "tool-status-pill verified";
      modFindingsWebsite.textContent = webVerified[0] || "Website is technically reachable (0 mitigation points).";
    } else if (isExecuted) {
      modStatusWebsite.textContent = "INSPECTED";
      modStatusWebsite.className = "tool-status-pill verified";
      modFindingsWebsite.textContent = "URL syntax and reachability verified with SSRF protection.";
    } else if (hasWebsite) {
      modStatusWebsite.textContent = "PARSED";
      modStatusWebsite.className = "tool-status-pill warning";
      modFindingsWebsite.textContent = "Company URL provided; live network check was offline/skipped.";
    } else {
      modStatusWebsite.textContent = "UNPROVIDED";
      modStatusWebsite.className = "tool-status-pill";
      modFindingsWebsite.textContent = "No company website URL provided in submission.";
    }
  }
}


// ── Render Investigation & Verification Results (Required by tests) ──────────
function renderResult(data) {
  const report = data.report || {};

  // 1. Authoritative Assessment (ReportGenerator takes precedence over ML alone)
  const score = (typeof report.risk_score === "number")
    ? report.risk_score
    : (data.is_fake ? 85 : 15);

  const verdict = report.verdict || (
    score >= 70 ? "HIGH RISK" : (score >= 30 ? "SUSPICIOUS" : "LIKELY LEGITIMATE")
  );
  const riskLevel = report.risk_level || verdict;
  const summary = report.summary || "Investigation and multi-tier verification assessment completed.";

  // 2. Verdict Banner & Risk Badge Styling
  if (score >= 70 || riskLevel === "HIGH RISK" || riskLevel === "High Risk") {
    verdictBanner.className = "verdict-banner fake";
    verdictIcon.textContent = "🚨";
    verdictHeading.textContent = "⚠️ High Fraud Risk Opportunity Detected";
    riskBadge.textContent = "HIGH RISK";
    riskBadge.className = "risk-badge HIGH";
    riskScoreBar.style.background = "linear-gradient(90deg, #ffd166, #ff3366)";
  } else if (score >= 30 || riskLevel === "SUSPICIOUS" || riskLevel === "Medium Risk") {
    verdictBanner.className = "verdict-banner suspicious";
    verdictIcon.textContent = "⚠️";
    verdictHeading.textContent = "⚠️ Suspicious Internship Posting";
    riskBadge.textContent = "SUSPICIOUS";
    riskBadge.className = "risk-badge MEDIUM";
    riskScoreBar.style.background = "linear-gradient(90deg, #f59e0b, #d97706)";
  } else {
    verdictBanner.className = "verdict-banner legit";
    verdictIcon.textContent = "🛡️";
    verdictHeading.textContent = "✓ Likely Legitimate Opportunity";
    riskBadge.textContent = "LIKELY LEGITIMATE";
    riskBadge.className = "risk-badge LOW";
    riskScoreBar.style.background = "linear-gradient(90deg, #10b981, #ffd166)";
  }
  verdictSub.textContent = summary;

  // 3. Animate Risk Score Meter (0 to 100) & Circular Gauge
  animateNumber(riskScoreNum, score, "", 900);
  updateGauge(score);
  setTimeout(() => {
    riskScoreBar.style.width = Math.min(100, Math.max(0, score)) + "%";
  }, 50);

  // 4. Agent Telemetry & Tools Executed
  const agentStatus = data.agent_status || "unconfigured";
  if (agentStatus === "completed") {
    agentStatusPill.textContent = "Agent: Active & Completed";
    agentStatusPill.className = "agent-pill active";
    agentStatusDesc.textContent =
      "Autonomous Groq agent investigated posting details and executed targeted forensic tools.";
  } else if (agentStatus === "unconfigured") {
    agentStatusPill.textContent = "Agent: Offline (ML + Rules Active)";
    agentStatusPill.className = "agent-pill unconfigured";
    agentStatusDesc.textContent =
      "Groq API key not configured in environment. Verification completed using ML classifier and deterministic rule screener.";
  } else {
    agentStatusPill.textContent = "Agent: Technical Error";
    agentStatusPill.className = "agent-pill error";
    agentStatusDesc.textContent =
      "Agent experienced a technical error or timeout. Verification completed using ML classifier and heuristic screener.";
  }

  // Tools Executed Chips
  toolsExecutedList.innerHTML = "";
  if (data.tools_executed && data.tools_executed.length > 0) {
    const toolNameMap = {
      verify_email: "✉️ Email Verifier",
      verify_payment_requests: "💳 Payment Verifier",
      analyze_internship_description: "📄 Description Analyzer",
      verify_company_website: "🌐 Website Verifier",
    };
    data.tools_executed.forEach((tool) => {
      const label = toolNameMap[tool] || `🔧 ${tool}`;
      toolsExecutedList.appendChild(createEl("span", "tool-chip", label));
    });
  } else {
    toolsExecutedList.appendChild(
      createEl("span", "tool-chip muted", "No tools executed (Agent offline or not required)")
    );
  }

  // 5. Machine Learning Assessment
  const mlAssessment = report.ml_assessment || {};
  const fakeProb = typeof mlAssessment.fake_probability === "number"
    ? mlAssessment.fake_probability
    : (typeof data.fake_prob === "number" ? data.fake_prob : 0.0);
  const legitProb = typeof mlAssessment.legit_probability === "number"
    ? mlAssessment.legit_probability
    : (typeof data.legit_prob === "number" ? data.legit_prob : 100.0 - fakeProb);

  animateNumber(fakePct, fakeProb);
  animateNumber(legitPct, legitProb);
  setTimeout(() => {
    probBar.style.width = fakeProb + "%";
  }, 50);

  const mlPts = mlAssessment.score_contribution !== undefined
    ? Number(mlAssessment.score_contribution).toFixed(1)
    : (fakeProb * 0.2).toFixed(1);
  mlScoreContribution.textContent = `${mlPts} / 20.0 pts`;
  mlModelArchitecture.textContent = mlAssessment.model_type || "TF-IDF (5,000 features) + Balanced Logistic Regression";
  mlDisclaimer.textContent = mlAssessment.disclaimer ||
    "Statistical inference on vocabulary patterns. Does not constitute verified technical proof.";

  // 6. Score Breakdown & Reconciliation
  const breakdown = report.score_breakdown || {};
  calcSummaryBox.textContent = breakdown.calculation_summary ||
    "Score calculated from ML assessment and deterministic risk indicators.";

  // Evidence summary badges
  cappedSummaryRow.innerHTML = "";
  const evSummary = breakdown.evidence_summary || {};
  if (typeof evSummary.uncapped_evidence_total === "number") {
    cappedSummaryRow.appendChild(
      createEl("span", "capped-badge", `Uncapped Evidence: ${evSummary.uncapped_evidence_total.toFixed(1)} pts`)
    );
    cappedSummaryRow.appendChild(
      createEl(
        "span",
        `capped-badge ${evSummary.evidence_cap_applied ? "warn" : ""}`,
        `Evidence Cap: ${evSummary.evidence_cap || 75} pts max${evSummary.evidence_cap_applied ? " (Cap Applied)" : ""}`
      )
    );
    if (evSummary.financial_exploitation_capped) {
      cappedSummaryRow.appendChild(
        createEl("span", "capped-badge warn", "Financial Exploitation Capped (45 pts max)")
      );
    }
  }

  // Scored risk indicators list
  scoreIndicatorsList.innerHTML = "";
  const riskIndicators = breakdown.risk_indicators || [];
  if (riskIndicators.length > 0) {
    riskIndicators.forEach((item) => {
      const card = createEl("div", "indicator-item-card");
      const top  = createEl("div", "indicator-item-top");
      const name = createEl("span", "indicator-name", (item.indicator || "Indicator").replace(/_/g, " "));
      const pts  = createEl("span", "indicator-pts", `+${Number(item.points || 0).toFixed(1)} pts`);
      top.appendChild(name);
      top.appendChild(pts);

      const desc = createEl("span", "indicator-desc", item.explanation || "");
      card.appendChild(top);
      card.appendChild(desc);
      scoreIndicatorsList.appendChild(card);
    });
  } else {
    scoreIndicatorsList.appendChild(
      createEl("div", "indicator-desc", "No positive fraud risk points triggered by evidence.")
    );
  }

  // 7. Dedicated 4 Modules
  renderVerificationModules(data, report);

  // 8. Suspicious Indicators & Red Flags
  suspiciousList.innerHTML = "";
  const suspiciousIndicators = report.suspicious_indicators || [];
  if (suspiciousIndicators.length > 0) {
    suspiciousCard.style.display = "block";
    suspiciousIndicators.forEach((s) => {
      const item = createEl("div", "detail-item");
      const icon = createEl("span", "item-icon", "🚩");
      const text = createEl("span", "item-text", s);
      item.appendChild(icon);
      item.appendChild(text);
      suspiciousList.appendChild(item);
    });
  } else {
    suspiciousCard.style.display = "none";
  }

  // 9. Rule-Based Heuristic Findings
  rulesList.innerHTML = "";
  const ruleFindings = report.rule_based_findings || data.red_flags || [];
  if (ruleFindings.length > 0) {
    rulesCard.style.display = "block";
    ruleFindings.forEach((r) => {
      const item = createEl("div", "detail-item");
      const icon = createEl("span", "item-icon", "⚠️");
      const text = createEl("span", "item-text", r);
      item.appendChild(icon);
      item.appendChild(text);
      rulesList.appendChild(item);
    });
  } else {
    rulesCard.style.display = "none";
  }

  // 10. Forensic Tool Findings
  forensicList.innerHTML = "";
  const toolFindings = report.investigation_findings || [];
  if (toolFindings.length > 0) {
    forensicCard.style.display = "block";
    toolFindings.forEach((f) => {
      const item = createEl("div", "detail-item");
      const icon = createEl("span", "item-icon", "🔬");
      const label = f.tool ? `[${f.tool}] ` : "";
      const text = createEl("span", "item-text", `${label}${f.message || f.category || "Forensic finding detected"}`);
      item.appendChild(icon);
      item.appendChild(text);
      forensicList.appendChild(item);
    });
  } else {
    forensicCard.style.display = "none";
  }

  // 11. Verified Technical Observations
  verifiedList.innerHTML = "";
  const verifiedIndicators = report.verified_indicators || [];
  if (verifiedIndicators.length > 0) {
    verifiedCard.style.display = "block";
    verifiedIndicators.forEach((v) => {
      const item = createEl("div", "detail-item");
      const icon = createEl("span", "item-icon", "✓");
      const text = createEl("span", "item-text", v);
      item.appendChild(icon);
      item.appendChild(text);
      verifiedList.appendChild(item);
    });
  } else {
    verifiedCard.style.display = "none";
  }

  // 12. Unverified Items & Limitations
  unverifiedList.innerHTML = "";
  const unverifiedItems = report.unverified_items || [];
  if (unverifiedItems.length > 0) {
    unverifiedItems.forEach((u) => {
      unverifiedList.appendChild(createEl("li", "", u));
    });
  } else {
    unverifiedList.appendChild(createEl("li", "", "All expected posting fields were provided in submission."));
  }

  limitationsList.innerHTML = "";
  const limitations = report.limitations || [];
  if (limitations.length > 0) {
    limitations.forEach((l) => {
      limitationsList.appendChild(createEl("li", "", l));
    });
  } else {
    limitationsList.appendChild(
      createEl("li", "", "Automated assessment relies on reachable internet endpoints and heuristic boundaries.")
    );
  }

  // 13. Actionable Safety Recommendations
  recommendationsList.innerHTML = "";
  const recommendations = report.recommendations || [];
  if (recommendations.length > 0) {
    recommendations.forEach((rec) => {
      const item  = createEl("div", "rec-item");
      const check = createEl("span", "rec-check", "✓");
      const text  = createEl("span", "rec-text", rec);
      item.appendChild(check);
      item.appendChild(text);
      recommendationsList.appendChild(item);
    });
  } else {
    const defaultTips = [
      "Legitimate employers never demand upfront registration, training, or equipment fees.",
      "Be wary of recruiters contacting only via Telegram, WhatsApp, or free Gmail addresses.",
      "Verify the employer independently through official career portals or LinkedIn staff profiles.",
    ];
    defaultTips.forEach((tip) => {
      const item  = createEl("div", "rec-item");
      const check = createEl("span", "rec-check", "✓");
      const text  = createEl("span", "rec-text", tip);
      item.appendChild(check);
      item.appendChild(text);
      recommendationsList.appendChild(item);
    });
  }

  // 14. Timestamp update
  if (analysisTimestamp) {
    const now = new Date();
    analysisTimestamp.textContent = `AUDIT TIMESTAMP // ${now.toLocaleTimeString()}`;
  }

  // 15. Reveal Result Panel and Smooth Scroll
  if (scanLoadingPanel) scanLoadingPanel.style.display = "none";
  resultPanel.style.display = "block";
  setTimeout(() => {
    resultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
  }, 100);
}


// ── Form Submit Handler with Loading Animation ───────────────────────────────
async function handleSubmit(e) {
  e.preventDefault();

  const title         = titleInput.value.trim();
  const location      = locationInput.value.trim();
  const description   = descriptionInput.value.trim();
  const requirements  = requirementsInput.value.trim();
  const company_name  = companyInput.value.trim();
  const contact_email = emailInput.value.trim();
  const company_url   = websiteInput.value.trim();
  const stipend       = stipendInput.value.trim();

  // Validate non-empty primary input
  if (!title && !description) {
    showToast("⚠️ Please enter at least an Internship Title or Description.", "error");
    titleInput.focus();
    return;
  }

  // Set Loading State
  btnAnalyze.disabled = true;
  btnAnalyze.classList.add("loading");
  btnText.textContent = "ACTIVATING INTELLIGENCE PIPELINE...";
  resultPanel.style.display = "none";

  if (scanLoadingPanel) {
    scanLoadingPanel.style.display = "block";
    scanLoadingPanel.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  // Stepper highlights
  const stepNodes = [
    document.getElementById("stepNode1"),
    document.getElementById("stepNode2"),
    document.getElementById("stepNode3"),
    document.getElementById("stepNode4"),
    document.getElementById("stepNode5"),
  ];
  const stepMessages = [
    "Ingesting and sanitizing submitted internship corpus...",
    "Computing TF-IDF vector weights & running ML inference...",
    "Executing deterministic fraud & advance-fee heuristics...",
    "Dispatching Groq agent to evaluate verification tools...",
    "Reconciling evidence and synthesizing forensic risk report...",
  ];

  let currentStep = 0;
  stepNodes.forEach((node, idx) => {
    if (node) node.classList.toggle("active", idx === 0);
  });
  if (scanPipelineStatus) scanPipelineStatus.textContent = stepMessages[0];

  const stepInterval = setInterval(() => {
    currentStep++;
    if (currentStep < stepNodes.length - 1) {
      stepNodes.forEach((node, idx) => {
        if (node) node.classList.toggle("active", idx <= currentStep);
      });
      if (scanPipelineStatus) scanPipelineStatus.textContent = stepMessages[currentStep];
    }
  }, 350);

  try {
    const res = await fetch("/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title,
        location,
        description,
        requirements,
        company_name,
        contact_email,
        company_url,
        stipend,
      }),
    });

    const data = await res.json();
    clearInterval(stepInterval);

    stepNodes.forEach(node => { if (node) node.classList.add("active"); });
    if (scanPipelineStatus) scanPipelineStatus.textContent = stepMessages[4];

    if (!res.ok) {
      throw new Error(data.error || `Server error (HTTP ${res.status})`);
    }

    setTimeout(() => {
      renderResult(data);
      const isHighOrSuspicious = (data.report?.risk_score >= 30) || data.is_fake;
      showToast(
        isHighOrSuspicious
          ? "⚠️ Investigation complete: Suspicious or high risk signals detected."
          : "✓ Investigation complete: Posting assessed as likely legitimate.",
        isHighOrSuspicious ? "error" : "success"
      );
    }, 250);

  } catch (err) {
    clearInterval(stepInterval);
    if (scanLoadingPanel) scanLoadingPanel.style.display = "none";
    showToast(`❌ ${err.message || "Error connecting to server. Is Flask running?"}`, "error");
    console.error("Investigation request error:", err);
  } finally {
    btnAnalyze.disabled = false;
    btnAnalyze.classList.remove("loading");
    btnText.innerHTML = '<span class="btn-sparkle">✦</span> START INVESTIGATION';
  }
}


// ── Reset Form & Result Dashboard ────────────────────────────────────────────
function resetAll() {
  form.reset();
  if (scanLoadingPanel) scanLoadingPanel.style.display = "none";
  resultPanel.style.display = "none";
  probBar.style.width = "0%";
  riskScoreBar.style.width = "0%";
  riskScoreNum.textContent = "0";
  fakePct.textContent = "0.0%";
  legitPct.textContent = "0.0%";
  updateGauge(0);
  showToast("↺ Form and intelligence dashboard cleared.", "info");
}


// ── Initialization ───────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  // Initialize 3D particle sphere engine
  new ParticleSphereEngine("particleSphereCanvas", "sphereViewport");

  buildSamples();
  form.addEventListener("submit", handleSubmit);
  document.getElementById("btnReset").addEventListener("click", resetAll);
});
