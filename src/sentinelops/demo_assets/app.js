"use strict";

const byId = (id) => document.getElementById(id);
const checkNames = {
  expected_root_cause: "根因匹配",
  evidence_scope: "证据引用有效",
  audit_chain: "审计链完整",
  result_persisted: "结果已落盘",
  run_completed: "运行已完成",
};
let currentRunId = null;
let selectedIncidentId = null;
let assistantEnabled = false;

function node(tag, className, value) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (value !== undefined) element.textContent = String(value);
  return element;
}

function replaceChildren(id, children) {
  byId(id).replaceChildren(...children);
}

function setNotice(message, kind = "") {
  const target = byId("notice");
  target.textContent = message;
  target.className = `notice ${kind}`.trim();
}

function displayCase(item) {
  selectedIncidentId = item.incident_id;
  resetAssistantAnswer();
  updateAssistantControls();
  byId("detail-placeholder").hidden = true;
  byId("detail-content").hidden = false;
  byId("trace-id").textContent = item.trace_id;
  const status = byId("detail-status");
  status.textContent = item.passed ? "全部检查通过" : "检查未通过";
  status.className = `badge ${item.passed ? "" : "fail"}`.trim();

  const meta = [
    `预期 ${item.expected_code}`,
    `实际 ${item.actual_code || "无确定根因"}`,
    `路由 ${item.requested_mode} → ${item.selected_mode}`,
    `查询 ${item.tool_queries} 次`,
    `耗时 ${item.duration_ms} ms`,
    ...Object.entries(item.checks).map(([key, ok]) => `${ok ? "✓" : "✕"} ${checkNames[key] || key}`),
  ];
  replaceChildren("detail-meta", meta.map((text) => node("span", "", text)));

  byId("assignment-count").textContent = `${item.assignments.length} 项`;
  const assignments = item.assignments.map((assignment) => {
    const card = node("div", "node");
    card.append(node("strong", "", assignment.actor), node("small", "", `${assignment.source} · ${assignment.state}`));
    return card;
  });
  replaceChildren("assignments", assignments.length ? assignments : [node("div", "node", "此模式未创建专项 Worker 派工")]);

  byId("evidence-count").textContent = `${item.evidence.filter((entry) => entry.used).length} / ${item.evidence.length} 条引用`;
  replaceChildren("evidence", item.evidence.map((entry) => {
    const card = node("div", `evidence-item ${entry.used ? "used" : ""}`);
    card.append(node("strong", "", `${entry.source.toUpperCase()} · ${entry.id}`));
    card.append(node("span", "", entry.summary));
    return card;
  }));

  byId("trace-count").textContent = `${item.trace.length} 步`;
  replaceChildren("trace", item.trace.map((step) => {
    const line = node("div", "timeline-item");
    line.append(node("strong", "", `${step.step}. ${step.actor} · ${step.action} · ${step.status}`));
    line.append(node("div", "", step.rationale));
    if (step.evidence_ids.length) line.append(node("code", "", `证据：${step.evidence_ids.join(", ")}`));
    return line;
  }));

  byId("audit-count").textContent = `${item.audit.event_count} 条 · ${item.audit.valid ? "校验通过" : "校验失败"}`;
  replaceChildren("audit-events", item.audit_events.map((event) => {
    const line = node("div", "timeline-item");
    line.append(node("strong", "", `#${event.sequence} ${event.actor} · ${event.action} · ${event.status}`));
    line.append(node("div", "", `${event.resource} · ${JSON.stringify(event.details)}`));
    line.append(node("code", "", `hash ${event.event_hash.slice(0, 16)}… ← ${event.previous_hash.slice(0, 16)}…`));
    return line;
  }));
}

function displayReport(report) {
  currentRunId = report.run_id || null;
  byId("metric-pass").textContent = `${report.passed_count} / ${report.case_count}`;
  byId("metric-pass-sub").textContent = report.all_passed ? "五项检查全部通过" : "请检查失败案例";
  byId("metric-correct").textContent = `${report.correct_count} / ${report.case_count}`;
  byId("metric-mode").textContent = report.requested_mode.toUpperCase();
  setNotice(report.all_passed
    ? "离线闭环通过：根因、证据、审计、结果持久化与运行终态均已核验。"
    : "离线闭环未通过：点击失败案例查看具体检查项。", report.all_passed ? "good" : "error");

  const buttons = report.results.map((item, index) => {
    const button = node("button", `case-row ${index === 0 ? "active" : ""}`);
    button.type = "button";
    const left = node("div", "");
    left.append(node("strong", "", `${item.service} · ${item.incident_id}`));
    left.append(node("small", "", `${item.expected_code} → ${item.actual_code || "needs_human"} · ${item.selected_mode} · ${item.duration_ms} ms`));
    button.append(left, node("span", `badge ${item.passed ? "" : "fail"}`, item.passed ? "PASS" : "FAIL"));
    button.addEventListener("click", () => {
      buttons.forEach((other) => other.classList.remove("active"));
      button.classList.add("active");
      displayCase(item);
    });
    return button;
  });
  const target = byId("case-results");
  target.className = "case-results";
  target.replaceChildren(...buttons);
  displayCase(report.results[0]);
}

async function loadCases() {
  try {
    const response = await fetch("/api/cases", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    const select = byId("case-select");
    const options = [new Option(`全部案例（${payload.cases.length} 条）`, "all")];
    for (const item of payload.cases) options.push(new Option(`${item.service} · ${item.incident_id}`, item.incident_id));
    select.replaceChildren(...options);
    select.disabled = false;
    byId("run-button").disabled = false;
    byId("version").textContent = `v${payload.version}`;
    byId("case-note").textContent = `${payload.cases.length} 条合成案例 · 每次运行均重新调查`;
  } catch (error) {
    setNotice(`无法读取本地案例：${error.message}`, "error");
  }
}

function updateAssistantControls() {
  const ready = assistantEnabled && currentRunId && selectedIncidentId;
  byId("assistant-question").disabled = !ready;
  byId("assistant-button").disabled = !ready;
}

function resetAssistantAnswer() {
  const target = byId("assistant-answer");
  target.className = "assistant-answer empty-state";
  target.textContent = "当前案例尚未提问；回答只用于解释，不会改变上方的调查结论。";
}

async function loadAssistantStatus() {
  try {
    const response = await fetch("/api/assistant/status", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    assistantEnabled = payload.enabled === true;
    byId("assistant-status").textContent = assistantEnabled
      ? "本机 Ollama 助手已配置 · 只读辅助解释（模型可用性在提问时检查）"
      : "助手默认关闭；按文档显式开启后重启验证台即可使用。";
  } catch (error) {
    byId("assistant-status").textContent = `助手状态不可用：${error.message}`;
  }
  updateAssistantControls();
}

async function askAssistant(event) {
  event.preventDefault();
  const question = byId("assistant-question").value.trim();
  if (!assistantEnabled || !currentRunId || !selectedIncidentId || question.length < 3) return;
  const button = byId("assistant-button");
  const target = byId("assistant-answer");
  const requestedIncident = selectedIncidentId;
  const requestedRun = currentRunId;
  button.disabled = true;
  target.className = "assistant-answer empty-state";
  target.textContent = "正在请求本机模型，只解释当前已引用证据…";
  try {
    const response = await fetch("/api/assistant", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ run_id: requestedRun, incident_id: requestedIncident, question }),
    });
    const payload = await response.json();
    if (requestedIncident !== selectedIncidentId || requestedRun !== currentRunId) return;
    if (!response.ok) throw new Error(payload.detail || `HTTP ${response.status}`);
    if (payload.status !== "advisory") throw new Error(`模型暂不可用（${payload.reason_code || "unknown"}）`);
    target.className = "assistant-answer";
    const title = node("strong", "", "AI 辅助解释 · 不改变规则裁决");
    const answer = node("p", "", payload.reply.answer);
    const refs = node("small", "", `引用证据：${payload.reply.evidence_refs.join("、")}`);
    const uncertainty = node("small", "", `不确定性：${payload.reply.uncertainty}`);
    target.replaceChildren(title, answer, refs, uncertainty);
  } catch (error) {
    if (requestedIncident === selectedIncidentId && requestedRun === currentRunId) {
      target.className = "assistant-answer assistant-error";
      target.textContent = `辅助解释未完成：${error.message}。原调查结论保持不变。`;
    }
  } finally {
    updateAssistantControls();
  }
}

async function runDemo() {
  const button = byId("run-button");
  button.disabled = true;
  currentRunId = null;
  selectedIncidentId = null;
  resetAssistantAnswer();
  updateAssistantControls();
  setNotice("正在运行只读夹具调查并校验审计链，请稍候…");
  try {
    const mode = document.querySelector('input[name="mode"]:checked').value;
    const response = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ case_id: byId("case-select").value, mode }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || `HTTP ${response.status}`);
    displayReport(payload);
  } catch (error) {
    setNotice(`运行失败：${error.message}`, "error");
  } finally {
    button.disabled = false;
  }
}

byId("run-button").addEventListener("click", runDemo);
byId("assistant-form").addEventListener("submit", askAssistant);
loadCases();
loadAssistantStatus();
