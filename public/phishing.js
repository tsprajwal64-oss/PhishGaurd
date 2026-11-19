const HISTORY_KEY = "phishguard_v2_history";
const $ = id => document.getElementById(id);
let selectedImage = null;
let previewUrl = null;

function setTheme(dark) {
  document.body.classList.toggle("dark", dark);
  $("themeIcon").textContent = dark ? "☀" : "☾";
  $("themeLabel").textContent = dark ? "Light mode" : "Dark mode";
  $("themeToggle").setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
  localStorage.setItem("phishguard_theme", dark ? "dark" : "light");
  drawChart();
}
setTheme(localStorage.getItem("phishguard_theme") === "dark");
$("themeToggle").addEventListener("click", () => setTheme(!document.body.classList.contains("dark")));

document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => {
      const active = t === tab;
      t.classList.toggle("active", active);
      t.setAttribute("aria-selected", String(active));
    });
    document.querySelectorAll(".tab-pane").forEach(p => {
      const active = p.id === `pane${tab.dataset.tab[0].toUpperCase()}${tab.dataset.tab.slice(1)}`;
      p.hidden = !active;
      p.classList.toggle("active", active);
    });
    $("resultPanel").hidden = true;
    clearRiskTheme();
  });
});

function clearRiskTheme() {
  document.body.classList.remove("risk-safe","risk-low","risk-medium","risk-high","risk-critical");
}

async function analyseText(text, source) {
  const response = await fetch("/api/analyze", {
    method: "POST",
    headers: {"Content-Type": "text/plain; charset=UTF-8"},
    body: text
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Analysis request failed.");
  showResult(data);
  saveScan({status:data.status, score:data.score, source, preview:text.slice(0,110)});
}

function riskBand(score) {
  if (score <= 20) return {key:"safe",label:"LOW RISK",caption:"Low risk detected",heading:"No major warning indicators",summary:"No major threats detected",advice:"The configured checks found few or no warning indicators. Still verify unexpected requests independently.",color:"#16a34a"};
  if (score <= 40) return {key:"low",label:"GUARDED",caption:"Some caution advised",heading:"A few warning indicators",summary:"Review this message carefully",advice:"Some indicators deserve attention. Check the sender address and destination of every link.",color:"#65a30d"};
  if (score <= 60) return {key:"medium",label:"MODERATE RISK",caption:"Moderate risk detected",heading:"Several warning indicators",summary:"Proceed with caution",advice:"Do not share credentials or payment information until the message is independently verified.",color:"#d97706"};
  if (score <= 80) return {key:"high",label:"HIGH RISK",caption:"High risk detected",heading:"Strong warning indicators",summary:"Avoid interacting with this email",advice:"Avoid opening links or attachments. Verify the request through the organisation's official website or phone number.",color:"#ea580c"};
  return {key:"critical",label:"CRITICAL RISK",caption:"Critical risk detected",heading:"Multiple serious warning indicators",summary:"Potential phishing threat",advice:"Do not click links, open attachments or reply. Report the message through your organisation's security process.",color:"#b91c1c"};
}

function animateNumber(element, target) {
  const duration = 950;
  const start = performance.now();
  function frame(now) {
    const progress = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - progress, 3);
    element.textContent = String(Math.round(target * eased));
    if (progress < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

function showResult(data, options = {}) {
  const panel = $("resultPanel");
  const informational = options.informational === true;
  const error = options.error === true;
  const score = Math.max(0, Math.min(100, Number(data.score) || 0));
  const band = riskBand(score);

  clearRiskTheme();
  panel.hidden = false;
  panel.className = `result-panel ${informational ? "info" : error ? "error" : band.key}`;
  $("resultTitle").textContent = data.status || (error ? "Analysis unavailable" : "Analysis complete");
  $("resultMessage").textContent = options.message || (informational
    ? "Public domain registration information is shown below. This lookup does not establish whether the email sender is genuine."
    : error
      ? "PhishGuard could not complete this request."
      : score <= 20
        ? "The configured checks found few or no warning indicators. A low score is not a guarantee that an email is legitimate."
        : score <= 60
          ? "Some warning indicators were detected. Review the findings and verify the sender independently."
          : "Multiple warning indicators were detected. Avoid interacting with the message until you verify it independently.");

  $("resultIndicator").textContent = informational ? "DOMAIN LOOKUP" : error ? "REQUEST ERROR" : "SCAN COMPLETE";
  $("riskVisual").hidden = informational || error;
  $("riskHeading").textContent = informational ? "Sender domain information" : error ? "Request status" : band.heading;
  $("riskLevel").textContent = informational ? "Informational" : error ? "Unavailable" : band.label;
  $("riskCaption").textContent = informational ? "Not a risk score" : error ? "No score available" : band.caption;
  $("resultSummary").textContent = informational ? "Registration lookup returned" : error ? "Unable to analyse" : band.summary;
  $("resultAdvice").textContent = informational
    ? "Domain registration data does not authenticate the sender or verify SPF, DKIM or DMARC."
    : error ? "Check the server, internet connection and try again." : band.advice;
  $("messageIcon").textContent = informational ? "i" : error ? "!" : score <= 20 ? "✓" : "!";
  $("riskValue").textContent = "0";
  $("riskCircle").style.strokeDashoffset = "477.52";
  $("riskFill").style.width = "0%";

  if (!informational && !error) {
    document.body.classList.add(`risk-${band.key}`);
    $("riskCircle").style.stroke = band.color;
    $("riskFill").style.background = band.color;
    requestAnimationFrame(() => {
      $("riskCircle").style.strokeDashoffset = String(477.52 * (1 - score / 100));
      $("riskFill").style.width = `${score}%`;
      animateNumber($("riskValue"), score);
    });
  } else {
    $("riskCircle").style.stroke = "var(--blue)";
    $("riskFill").style.background = "var(--blue)";
  }

  const list = $("findingList");
  list.replaceChildren();
  const findings = Array.isArray(data.findings) && data.findings.length
    ? data.findings
    : [informational ? "No additional registration details were supplied." : error ? "No analysis result was returned." : "No configured warning indicators were detected."];
  findings.forEach(value => {
    const li = document.createElement("li");
    li.textContent = String(value);
    list.append(li);
  });

  panel.scrollIntoView({behavior:"smooth", block:"nearest"});
}

function showFailure(error) {
  showResult({status:"Request failed", score:0, findings:[error.message || String(error)]}, {error:true});
}

$("pasteForm").addEventListener("submit", async event => {
  event.preventDefault();
  const text = $("emailText").value.trim();
  if (!text) return;
  const button = $("pasteSubmit");
  button.disabled = true;
  button.innerHTML = "Analysing…";
  try { await analyseText(text, "Pasted email"); }
  catch (e) { showFailure(e); }
  finally { button.disabled = false; button.innerHTML = 'Analyse email <b>→</b>'; }
});

$("senderForm").addEventListener("submit", async event => {
  event.preventDefault();
  const email = $("senderEmail").value.trim();
  const button = $("senderSubmit");
  button.disabled = true;
  button.innerHTML = "Investigating…";
  try {
    const response = await fetch("/api/investigate", {
      method:"POST", headers:{"Content-Type":"text/plain; charset=UTF-8"}, body:email
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Sender lookup failed.");
    const lines = [
      `Domain: ${data.domain}`,
      `Lookup: ${data.lookupStatus}`,
      `Registration date: ${data.createdDate || "Not supplied by registry"}`,
      data.note || "Public registration information only."
    ];
    showResult({status:"Sender investigation", score:0, findings:lines}, {informational:true});
    saveScan({status:"Sender check", score:null, source:"Sender investigation", preview:email});
  } catch (e) { showFailure(e); }
  finally { button.disabled = false; button.innerHTML = 'Investigate sender <b>→</b>'; }
});

$("imageFile").addEventListener("change", event => {
  const file = event.target.files[0];
  if (!file) return;
  if (!["image/png","image/jpeg","image/webp"].includes(file.type) || file.size > 8*1024*1024) {
    $("ocrStatus").textContent = "Choose a PNG, JPG or WEBP image smaller than 8 MB.";
    event.target.value = "";
    return;
  }
  selectedImage = file;
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = URL.createObjectURL(file);
  $("imagePreview").src = previewUrl;
  $("imagePreviewWrap").hidden = false;
  $("imageSubmit").disabled = false;
  $("ocrStatus").textContent = `${file.name} selected.`;
});

$("removeImage").addEventListener("click", () => {
  selectedImage = null;
  $("imageFile").value = "";
  $("imagePreview").removeAttribute("src");
  $("imagePreviewWrap").hidden = true;
  $("imageSubmit").disabled = true;
  $("ocrStatus").textContent = "Choose a screenshot to begin.";
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = null;
});

$("imageSubmit").addEventListener("click", async () => {
  if (!selectedImage) return;
  $("imageSubmit").disabled = true;
  $("ocrStatus").textContent = "Extracting text from screenshot… Keep this page open.";
  try {
    if (!window.Tesseract) throw new Error("OCR library did not load. Check your internet connection and refresh.");
    const result = await Tesseract.recognize(selectedImage, "eng", {
      logger: message => {
        if (message.status === "recognizing text") $("ocrStatus").textContent = `Reading screenshot: ${Math.round((message.progress || 0)*100)}%`;
      }
    });
    $("ocrText").value = result.data.text.trim();
    $("analyseOcr").disabled = !$("ocrText").value.trim();
    $("ocrStatus").textContent = "Text extraction complete. Review the text, then analyse it.";
  } catch (e) { $("ocrStatus").textContent = e.message; }
  finally { $("imageSubmit").disabled = !selectedImage; }
});

$("ocrText").addEventListener("input", () => $("analyseOcr").disabled = !$("ocrText").value.trim());
$("analyseOcr").addEventListener("click", async () => {
  const text = $("ocrText").value.trim();
  if (!text) return;
  $("analyseOcr").disabled = true;
  try { await analyseText(text, "Screenshot OCR"); }
  catch (e) { showFailure(e); }
  finally { $("analyseOcr").disabled = false; }
});

function getHistory() {
  try {
    const value = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(value) ? value.slice(0,10) : [];
  } catch { return []; }
}
function saveScan(scan) {
  const history = [{...scan, time:new Date().toLocaleString()}, ...getHistory()].slice(0,10);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  renderHistory();
}
function renderHistory() {
  const history = getHistory();
  const list = $("historyList");
  list.replaceChildren();
  if (!history.length) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = "No scans yet. Run your first investigation.";
    list.append(p);
  } else history.forEach(item => {
    const row = document.createElement("div");
    row.className = "history-item";
    const left = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("small");
    title.textContent = `${item.source} · ${item.preview}`;
    detail.textContent = `${item.time} · ${item.score === null ? "Domain lookup" : `Risk ${item.score}/100`}`;
    left.append(title, detail);
    const pill = document.createElement("span");
    const statusClass = item.status === "Safe" ? "safe" : item.status === "Phishing" ? "phishing" : item.status === "Suspicious" ? "suspicious" : "sender";
    pill.className = `pill ${statusClass}`;
    pill.textContent = item.status;
    row.append(left, pill);
    list.append(row);
  });
  $("totalScans").textContent = history.length;
  $("threatScans").textContent = history.filter(x => ["Suspicious","Phishing"].includes(x.status)).length;
  $("safeScans").textContent = history.filter(x => x.status === "Safe").length;
  drawChart();
}
$("clearHistory").addEventListener("click", () => {
  if (!confirm("Clear the last 10 scan records from this browser?")) return;
  localStorage.removeItem(HISTORY_KEY);
  renderHistory();
});

function drawChart() {
  const canvas = $("trendChart");
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  if (!rect.width) return;
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.floor(rect.width * ratio);
  canvas.height = 220 * ratio;
  const ctx = canvas.getContext("2d");
  ctx.setTransform(ratio,0,0,ratio,0,0);
  const dark = document.body.classList.contains("dark");
  const muted = dark ? "#9ba8ba" : "#667085";
  const grid = dark ? "#263242" : "#d7dee7";
  const history = getHistory().slice().reverse().filter(x => x.score !== null && x.source !== "Sender investigation");
  const w = rect.width, h = 220, left = 30, right = 10, top = 12, bottom = 34;
  ctx.clearRect(0,0,w,h);
  ctx.font = "10px DM Sans, sans-serif";
  ctx.fillStyle = muted;
  ctx.strokeStyle = grid;
  ctx.lineWidth = 1;
  [0,25,50,75,100].forEach(v => {
    const y = top + (100-v)*(h-top-bottom)/100;
    ctx.beginPath(); ctx.moveTo(left,y); ctx.lineTo(w-right,y); ctx.stroke();
    ctx.fillText(String(v), 3, y+4);
  });
  if (!history.length) {
    ctx.fillStyle=muted; ctx.textAlign="center";
    ctx.fillText("Your email risk scores will appear here",w/2,h/2);
    return;
  }
  const plotW = w-left-right, slot = plotW/history.length, bw = Math.min(34,slot*.62);
  history.forEach((item,i) => {
    const value = Math.max(0,Math.min(100,Number(item.score)||0));
    const bh = value*(h-top-bottom)/100;
    const x=left+i*slot+(slot-bw)/2, y=h-bottom-bh;
    ctx.fillStyle = value <= 20 ? (dark?"#4ade80":"#16a34a") : value <= 40 ? "#65a30d" : value <= 60 ? "#d97706" : value <= 80 ? "#ea580c" : "#b91c1c";
    ctx.beginPath();
    if (ctx.roundRect) ctx.roundRect(x,y,bw,Math.max(2,bh),4);
    else ctx.rect(x,y,bw,Math.max(2,bh));
    ctx.fill();
    ctx.fillStyle=muted; ctx.textAlign="center";
    ctx.fillText(String(i+1),x+bw/2,h-12);
  });
}
window.addEventListener("resize", drawChart);
renderHistory();
