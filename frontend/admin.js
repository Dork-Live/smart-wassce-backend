// admin.js — frontend admin for Smart WASSCE (JWT)
const BASE = "http://localhost:4000";
const $ = (s) => document.querySelector(s);

let TOKEN = localStorage.getItem("ADMIN_TOKEN") || "";

// ui elements
const loginCard = $("#loginCard");
const dashboard = $("#dashboard");
const adminEmailSpan = $("#adminEmail");
const errorBox = $("#errorBox");
const outBox = $("#out");
let lastVouchers = [];
let lastHistory = [];

function log(msg) {
  const ts = new Date().toLocaleString();
  if (errorBox) errorBox.textContent = `${ts} — ${msg}\n` + errorBox.textContent;
}

// API wrapper
async function api(path, opt = {}) {
  const url = BASE + path;
  const options = {
    method: opt.method || "GET",
    headers: { Accept: "application/json", ...(TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}) },
    body: null,
  };

  if (opt.body instanceof FormData) {
    options.body = opt.body;
  } else if (opt.body) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(opt.body);
  }

  const res = await fetch(url, options);
  if (res.status === 401) {
    handleUnauthorized();
    throw new Error("Unauthorized");
  }
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch (e) {
    return { raw: text, status: res.status };
  }
}

function showLogin() {
  if (loginCard) loginCard.style.display = "block";
  if (dashboard) dashboard.style.display = "none";
  if (adminEmailSpan) adminEmailSpan.textContent = "";
}

function showDashboard(email = "Admin") {
  if (loginCard) loginCard.style.display = "none";
  if (dashboard) dashboard.style.display = "block";
  if (adminEmailSpan) adminEmailSpan.textContent = "Logged in: " + email;
}

function handleUnauthorized() {
  log("Unauthorized: token invalid or expired");
  TOKEN = "";
  localStorage.removeItem("ADMIN_TOKEN");
  showLogin();
  alert("Session expired — please log in again.");
}

async function refreshAll() {
  await Promise.allSettled([loadVouchers(), loadHistory()]);
}

// login
document.addEventListener("click", (ev) => {
  if (ev.target && ev.target.id === "loginBtn") (async () => {
    const email = $("#loginEmail").value.trim();
    const password = $("#loginPassword").value.trim();
    if (!email || !password) return alert("Enter credentials");
    try {
      const r = await api("/api/admin/login", { method: "POST", body: { email, password } });
      if (!r.success) return alert(r.error || "Login failed");
      TOKEN = r.token;
      localStorage.setItem("ADMIN_TOKEN", TOKEN);
      log("Logged in");
      showDashboard(email);
      await refreshAll();
    } catch (e) {
      log("Login error: " + e.message);
      alert("Login failed. Check network or credentials.");
    }
  })();
});

// logout
document.addEventListener("click", (ev) => {
  if (ev.target && ev.target.id === "logoutBtn") (async () => {
    if (!confirm("Logout now?")) return;
    await api("/api/admin/logout", { method: "POST" }).catch(()=>{});
    TOKEN = "";
    localStorage.removeItem("ADMIN_TOKEN");
    showLogin();
    log("Logged out");
  })();
});

// upload
document.addEventListener("click", (ev) => {
  if (ev.target && ev.target.id === "uploadBtn") (async () => {
    const files = $("#files").files;
    if (!files || files.length === 0) return alert("Select files");
    const fd = new FormData();
    for (const f of files) fd.append("vouchers", f);
    outBox.textContent = "Uploading...";
    try {
      const r = await api("/api/upload-vouchers", { method: "POST", body: fd });
      if (!r.success) throw new Error(r.error || "Upload failed");
      outBox.textContent = `Uploaded ${r.added.length} voucher(s)`;
      $("#files").value = "";
      log("Upload success");
      await refreshAll();
    } catch (e) {
      outBox.textContent = "Upload error";
      log("Upload error: " + e.message);
      alert("Upload failed: " + e.message);
    }
  })();
});

// delete used
document.addEventListener("click", (ev) => {
  if (ev.target && ev.target.id === "deleteUsed") (async () => {
    if (!confirm("Delete ALL used vouchers?")) return;
    try {
      const r = await api("/api/vouchers/used", { method: "DELETE" });
      alert(r.message || "Deleted");
      log(r.message || "Deleted used vouchers");
      await refreshAll();
    } catch (e) {
      log("Delete error: " + e.message);
      alert("Delete failed");
    }
  })();
});

// exports (Excel / PDF)
document.addEventListener("click", (ev) => {
  if (ev.target && ev.target.id === "exportExcel") {
    if (!lastHistory.length) return alert("No data");
    const rows = lastHistory.map(h => ({ Reference: h.reference || "", Filename: h.filename || "", User: h.usedBy || "", Email: h.usedByEmail || "", Date: h.dateUsed ? new Date(h.dateUsed).toLocaleString() : "" }));
    const ws = XLSX.utils.json_to_sheet(rows);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "History");
    XLSX.writeFile(wb, "SmartWASSCE_History.xlsx");
    log("Exported Excel");
  } else if (ev.target && ev.target.id === "exportPDF") {
    if (!lastHistory.length) return alert("No data");
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ orientation: "landscape" });
    doc.setFontSize(14); doc.text("Smart WASSCE — Voucher History", 10, 14); doc.setFontSize(10);
    let y = 26;
    lastHistory.slice(0, 200).forEach((h, i) => {
      const line = `${i + 1}. Ref:${h.reference || '-'} | ${h.usedBy || '-'} | ${h.usedByEmail || '-'} | ${h.filename || '-'} | ${h.dateUsed ? new Date(h.dateUsed).toLocaleString() : ''}`;
      doc.text(line, 10, y);
      y += 6;
      if (y > 190) { doc.addPage(); y = 20; }
    });
    doc.save("SmartWASSCE_History.pdf");
    log("Exported PDF");
  }
});

// search box filtering
document.addEventListener("input", (ev) => {
  if (ev.target && ev.target.id === "searchBox") renderHistory();
});

// load vouchers
async function loadVouchers() {
  try {
    const r = await api("/api/vouchers/all");
    if (!r.success) throw new Error(r.error || "Load failed");
    lastVouchers = r.vouchers || [];
    renderVouchers();
    updateStats();
  } catch (e) {
    log("Load vouchers error: " + e.message);
  }
}
function renderVouchers() {
  const tbody = $("#voucherTable tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  lastVouchers.forEach(v => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${v.cardId || v.id || ""}</td><td><img src="${BASE}/uploads/${v.filename}" /></td><td style="color:${v.status === "used" ? "red" : "green"}">${v.status}</td><td>${v.uploadedAt ? new Date(v.uploadedAt).toLocaleString() : ""}</td>`;
    tbody.appendChild(tr);
  });
}

// load history
async function loadHistory() {
  try {
    const r = await api("/api/history");
    if (!r.success) throw new Error(r.error || "Load failed");
    lastHistory = r.history || [];
    renderHistory();
    updateStats();
  } catch (e) {
    log("Load history error: " + e.message);
  }
}
function renderHistory() {
  const tbody = $("#historyTable tbody");
  if (!tbody) return;
  const q = ($("#searchBox").value || "").toLowerCase();
  tbody.innerHTML = "";
  (lastHistory || []).filter(h => {
    if (!q) return true;
    return (h.reference || "").toLowerCase().includes(q) || (h.usedBy || "").toLowerCase().includes(q) || (h.usedByEmail || "").toLowerCase().includes(q) || (h.filename || "").toLowerCase().includes(q);
  }).forEach(h => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${h.reference || "-"}</td><td>${h.filename || "-"}</td><td>${h.usedBy || "-"}</td><td>${h.usedByEmail || "-"}</td><td>${h.dateUsed ? new Date(h.dateUsed).toLocaleString() : "-"}</td>`;
    tbody.appendChild(tr);
  });
}

function updateStats() {
  const total = (lastVouchers || []).length;
  const used = (lastVouchers || []).filter(v => v.status === "used").length;
  const unused = total - used;
  const hist = (lastHistory || []).length;
  const st = $("#statsTotal"); if (st) st.textContent = `${total} vouchers`;
  const st2 = $("#statsText"); if (st2) st2.textContent = `${unused} unused • ${used} used • ${hist} history entries`;
}

// try auto-login and initialize
(async function init() {
  if (!TOKEN) return showLogin();
  try {
    await refreshAll();
    showDashboard("Admin");
  } catch (e) {
    log("Auto-auth failed");
    showLogin();
  }
})();