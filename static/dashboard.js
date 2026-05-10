const state = { userId: "" };

const setUserButton = document.getElementById("set-user");
const seedButton = document.getElementById("seed-data");
const userStatus = document.getElementById("user-status");

const backupsOutput = document.getElementById("backups-output");
const accessLogOutput = document.getElementById("access-log-output");
const auditLogOutput = document.getElementById("audit-log-output");
const anomaliesOutput = document.getElementById("anomalies-output");
const restoreOutput = document.getElementById("restore-output");
const chatOutput = document.getElementById("chat-output");

function setUser() {
  const userIdInput = document.getElementById("user-id").value.trim();
  state.userId = userIdInput;
  userStatus.textContent = state.userId
    ? `Active user: ${state.userId}`
    : "No user selected.";
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.message || "Request failed");
  }
  return data;
}

function renderTable(container, data) {
  if (!Array.isArray(data) || data.length === 0) {
    container.textContent = "No data available.";
    return;
  }
  const table = document.createElement("table");
  const header = document.createElement("tr");
  Object.keys(data[0]).forEach((key) => {
    const th = document.createElement("th");
    th.textContent = key;
    header.appendChild(th);
  });
  table.appendChild(header);

  data.slice(0, 50).forEach((row) => {
    const tr = document.createElement("tr");
    Object.values(row).forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value ?? "";
      tr.appendChild(td);
    });
    table.appendChild(tr);
  });
  container.innerHTML = "";
  container.appendChild(table);
}

function renderJson(container, data) {
  container.textContent = JSON.stringify(data, null, 2);
}

async function loadBackups() {
  if (!state.userId) return;
  try {
    const catalog = await fetchJson(`/api/backups/catalog?user_id=${state.userId}`);
    renderTable(backupsOutput, catalog);
  } catch (error) {
    backupsOutput.textContent = error.message;
  }
}

async function loadAccessLog() {
  if (!state.userId) return;
  try {
    const log = await fetchJson(`/api/access-log?user_id=${state.userId}`);
    renderTable(accessLogOutput, log);
  } catch (error) {
    accessLogOutput.textContent = error.message;
  }
}

async function loadAuditLog() {
  if (!state.userId) return;
  try {
    const log = await fetchJson(`/api/audit-log?user_id=${state.userId}`);
    renderTable(auditLogOutput, log);
  } catch (error) {
    auditLogOutput.textContent = error.message;
  }
}

async function loadAnomalies() {
  if (!state.userId) return;
  try {
    const data = await fetchJson(`/api/anomalies?user_id=${state.userId}`);
    renderTable(anomaliesOutput, data);
  } catch (error) {
    anomaliesOutput.textContent = error.message;
  }
}

async function restoreBackup() {
  if (!state.userId) return;
  const backupId = document.getElementById("restore-id").value.trim();
  if (!backupId) return;
  try {
    const result = await fetchJson("/api/restore", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: state.userId, backup_id: backupId }),
    });
    renderJson(restoreOutput, result);
  } catch (error) {
    restoreOutput.textContent = error.message;
  }
}

async function sendChat() {
  if (!state.userId) return;
  const message = document.getElementById("chat-message").value.trim();
  if (!message) return;
  try {
    const result = await fetchJson("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: state.userId, message }),
    });
    renderJson(chatOutput, result);
  } catch (error) {
    chatOutput.textContent = error.message;
  }
}

async function seedData() {
  try {
    await fetchJson("/api/init-data", { method: "POST" });
  } catch (error) {
    userStatus.textContent = error.message;
  }
}

setUserButton.addEventListener("click", setUser);
seedButton.addEventListener("click", seedData);
document.getElementById("load-backups").addEventListener("click", loadBackups);
document
  .getElementById("load-access-log")
  .addEventListener("click", loadAccessLog);
document
  .getElementById("load-audit-log")
  .addEventListener("click", loadAuditLog);
document
  .getElementById("load-anomalies")
  .addEventListener("click", loadAnomalies);
document
  .getElementById("restore-backup")
  .addEventListener("click", restoreBackup);
document.getElementById("send-chat").addEventListener("click", sendChat);
