// ═══════════════════════════════════════════════════════════════════════════
//  Fake Job Detection — Main JavaScript
// ═══════════════════════════════════════════════════════════════════════════

// ── Sample job data ─────────────────────────────────────────────────────────
const SAMPLES = [
  {
    label: "fake",
    name: "Work-From-Home Scam",
    desc: "Classic advance-fee / data-entry fraud",
    title: "Earn $5000/week from Home — No Experience Needed!",
    location: "US, Remote",
    description:
      "We are hiring data entry specialists to work from home. No experience required. You will earn guaranteed income of $5000 per week. Send money via western union for your starter kit. Bitcoin payments accepted. Click here to apply now and start earning fast!",
    requirements:
      "Must be 18 or older. No skills needed. Just send $99 upfront fee for training materials and background check fee.",
  },
  {
    label: "legit",
    name: "Software Engineer",
    desc: "Mid-level backend role at a tech company",
    title: "Software Engineer — Backend (Python/Django)",
    location: "US, CA, San Francisco",
    description:
      "We are looking for a passionate software engineer to join our growing engineering team. You will design and implement scalable REST APIs, collaborate with product managers, and participate in code reviews. We offer a competitive salary, health benefits, and equity.",
    requirements:
      "3+ years of experience with Python and Django. Familiarity with PostgreSQL and Redis. Strong understanding of REST API design principles. Bachelor's degree in Computer Science or equivalent.",
  },
  {
    label: "fake",
    name: "Mystery Shopper",
    desc: "Gift card / wire transfer money mule scam",
    title: "Mystery Shopper — Immediate Start, High Pay",
    location: "US, TX, Remote",
    description:
      "Earn up to $3500 per week as a mystery shopper! We will send you a check. Cash it, keep your portion, and wire transfer the rest via western union. Guaranteed income with no experience required! Interviewing now, limited positions available!",
    requirements:
      "Must be 18 or older. No experience required. Training fee of $50 applies.",
  },
  {
    label: "legit",
    name: "Data Analyst",
    desc: "Analytics role with real responsibilities",
    title: "Data Analyst — Marketing Analytics",
    location: "GB, London",
    description:
      "Join our analytics team to drive data-driven decisions across our marketing channels. You will build dashboards in Tableau, write SQL queries, and present insights to senior stakeholders. This is a hybrid role with 2 days in our central London office.",
    requirements:
      "2+ years of experience in data analysis. Proficient in SQL and Python (Pandas). Experience with Tableau or Power BI. Strong communication skills.",
  },
];

// ── DOM references ───────────────────────────────────────────────────────────
const form           = document.getElementById("jobForm");
const btnAnalyze     = document.getElementById("btnAnalyze");
const btnText        = document.getElementById("btnText");
const spinner        = document.getElementById("spinner");
const resultPanel    = document.getElementById("resultPanel");
const verdictBanner  = document.getElementById("verdictBanner");
const verdictIcon    = document.getElementById("verdictIcon");
const verdictHeading = document.getElementById("verdictHeading");
const verdictSub     = document.getElementById("verdictSub");
const fakePct        = document.getElementById("fakePct");
const legitPct       = document.getElementById("legitPct");
const probBar        = document.getElementById("probBar");
const riskBadge      = document.getElementById("riskBadge");
const redFlagsSection = document.getElementById("redFlagsSection");
const redFlagsList   = document.getElementById("redFlagsList");
const samplesGrid    = document.getElementById("samplesGrid");
const toast          = document.getElementById("toast");
const toastMsg       = document.getElementById("toastMsg");

// ── Build sample cards ───────────────────────────────────────────────────────
function buildSamples() {
  SAMPLES.forEach((s, i) => {
    const card = document.createElement("div");
    card.className = "sample-card";
    card.id = `sampleCard${i}`;
    card.innerHTML = `
      <span class="sample-badge ${s.label}">${s.label === "fake" ? "⚠ FAKE" : "✓ LEGIT"}</span>
      <div class="sample-info">
        <span class="sample-name">${s.name}</span>
        <span class="sample-desc">${s.desc}</span>
      </div>`;
    card.addEventListener("click", () => loadSample(s));
    samplesGrid.appendChild(card);
  });
}

function loadSample(s) {
  document.getElementById("titleInput").value       = s.title;
  document.getElementById("locationInput").value    = s.location;
  document.getElementById("descriptionInput").value = s.description;
  document.getElementById("requirementsInput").value = s.requirements;
  showToast("✅ Sample loaded — click Analyze to detect!", "success");
  document.getElementById("titleInput").scrollIntoView({ behavior: "smooth", block: "center" });
}

// ── Toast ────────────────────────────────────────────────────────────────────
let toastTimer = null;
function showToast(msg, type = "info") {
  toastMsg.textContent = msg;
  toast.className = `toast ${type} show`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 3800);
}

// ── Animate number counter ───────────────────────────────────────────────────
function animateNumber(el, target, suffix = "%", duration = 900) {
  const start = performance.now();
  const from  = parseFloat(el.textContent) || 0;
  function step(now) {
    const t = Math.min((now - start) / duration, 1);
    const eased = t < 0.5 ? 2*t*t : -1+(4-2*t)*t;
    el.textContent = (from + (target - from) * eased).toFixed(1) + suffix;
    if (t < 1) requestAnimationFrame(step);
    else el.textContent = target + suffix;
  }
  requestAnimationFrame(step);
}

// ── Render result ────────────────────────────────────────────────────────────
function renderResult(data) {
  // Verdict banner
  const isFake = data.is_fake;
  verdictBanner.className = `verdict-banner ${isFake ? "fake" : "legit"}`;
  verdictIcon.textContent  = isFake ? "🚨" : "✅";
  verdictHeading.textContent = isFake
    ? "⚠️  This job posting appears FAKE"
    : "✅  This job posting appears LEGITIMATE";
  verdictSub.textContent = isFake
    ? `Our AI detected ${data.fake_prob}% probability of fraud. Exercise extreme caution.`
    : `Our AI detected ${data.legit_prob}% probability of a genuine posting. Still verify independently.`;

  // Probability bar
  probBar.className = `prob-bar-inner ${isFake ? "fake" : "legit"}`;
  setTimeout(() => { probBar.style.width = data.fake_prob + "%"; }, 50);
  animateNumber(fakePct,  data.fake_prob);
  animateNumber(legitPct, data.legit_prob);

  // Risk badge
  riskBadge.textContent = data.risk + " RISK";
  riskBadge.className   = `risk-badge ${data.risk}`;

  // Red flags
  redFlagsList.innerHTML = "";
  if (data.red_flags && data.red_flags.length > 0) {
    redFlagsSection.style.display = "block";
    data.red_flags.forEach((flag, i) => {
      const item = document.createElement("div");
      item.className = "flag-item";
      item.style.animationDelay = `${i * 0.07}s`;
      item.innerHTML = `<div class="flag-dot"></div><span>${flag}</span>`;
      redFlagsList.appendChild(item);
    });
  } else {
    redFlagsSection.style.display = "none";
  }

  // Show panel
  resultPanel.style.display = "block";
  setTimeout(() => resultPanel.scrollIntoView({ behavior: "smooth", block: "nearest" }), 100);
}

// ── Form submit ──────────────────────────────────────────────────────────────
async function handleSubmit(e) {
  e.preventDefault();

  const title        = document.getElementById("titleInput").value.trim();
  const location     = document.getElementById("locationInput").value.trim();
  const description  = document.getElementById("descriptionInput").value.trim();
  const requirements = document.getElementById("requirementsInput").value.trim();

  if (!title && !description) {
    showToast("⚠️ Please enter at least a Job Title or Description.", "error");
    return;
  }

  // Loading state
  btnAnalyze.disabled = true;
  btnAnalyze.classList.add("loading");
  resultPanel.style.display = "none";

  try {
    const res = await fetch("/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title, location, description, requirements }),
    });

    if (!res.ok) throw new Error(`Server error: ${res.status}`);
    const data = await res.json();
    renderResult(data);
    showToast(
      data.is_fake ? "🚨 Fraud detected!" : "✅ Posting looks legitimate",
      data.is_fake ? "error" : "success"
    );
  } catch (err) {
    showToast("❌ Error connecting to the server. Is Flask running?", "error");
    console.error(err);
  } finally {
    btnAnalyze.disabled = false;
    btnAnalyze.classList.remove("loading");
  }
}

// ── Reset ────────────────────────────────────────────────────────────────────
function resetAll() {
  form.reset();
  resultPanel.style.display = "none";
  probBar.style.width = "0%";
  showToast("🔄 Form cleared.", "info");
}

// ── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  buildSamples();
  form.addEventListener("submit", handleSubmit);
  document.getElementById("btnReset").addEventListener("click", resetAll);
});
