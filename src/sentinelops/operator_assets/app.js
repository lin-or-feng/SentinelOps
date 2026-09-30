"use strict";

const byId = (id) => document.getElementById(id);
let token = "";
let checkedTask = null;
let busy = false;
const sourceFailureLabels = {
  authorization_denied: "凭据无权访问",
  rate_limited: "来源限流",
  timeout: "来源超时",
  response_too_large: "响应超过大小限制",
  invalid_response: "响应格式或状态无效",
  source_not_allowed: "来源未授权",
  network_or_server_error: "网络或来源服务故障",
  unexpected_provider_error: "来源异常，请核查服务端类别",
};

function entry(primary, secondary = "", className = "entry") {
  const item = document.createElement("div");
  item.className = className;
  item.textContent = String(primary);
  if (secondary) {
    const detail = document.createElement("small");
    detail.textContent = String(secondary);
    item.append(detail);
  }
  return item;
}

function notice(text, kind = "") {
  byId("notice").textContent = text;
  byId("notice").className = `notice ${kind}`.trim();
}

function updateButtons() {
  byId("check").disabled = !token || busy;
  byId("recover").disabled = !token || busy;
  byId("confirm").disabled = !checkedTask || busy;
  byId("run").disabled = !checkedTask || !byId("confirm").checked || busy;
}

function invalidateCheck() {
  checkedTask = null;
  byId("confirm").checked = false;
  byId("result").hidden = true;
  updateButtons();
}

function taskFromForm() {
  const when = byId("started-at").value;
  const date = new Date(when);
  if (!when || Number.isNaN(date.getTime())) throw new Error("请输入有效的事故起点时间");
  const symptoms = byId("symptoms").value.split(/\r?\n/).map((part) => part.trim()).filter(Boolean);
  if (symptoms.length < 1 || symptoms.length > 20) throw new Error("症状应为 1–20 行");
  return {
    incident_id: byId("incident-id").value.trim(),
    tenant_id: byId("tenant-id").value.trim(),
    service: byId("service").value.trim(),
    started_at: date.toISOString(),
    symptoms,
    deadline_seconds: Number(byId("deadline").value),
    query_budget: Number(byId("budget").value),
  };
}

async function api(path, payload) {
  const headers = { Authorization: `Bearer ${token}` };
  const options = { headers, cache: "no-store" };
  if (payload !== undefined) {
    options.method = "POST";
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(`${data.detail || "request_failed"} (HTTP ${response.status})`);
    error.status = response.status;
    throw error;
  }
  return data;
}

byId("connect").addEventListener("click", async () => {
  token = byId("token").value;
  byId("token").value = "";
  invalidateCheck();
  if (!token) return notice("请输入 API Token。", "error");
  try {
    const state = await api("/api/status");
    byId("status").textContent = `模式：真实只读 · 数据库：${state.ready ? "就绪" : "不可用"} · 来源：${state.sources.join("、")}`;
    if (!state.ready) throw new Error("本机数据库未就绪");
    notice("连接成功。请填写获批事故，先执行来源预检。", "good");
  } catch (error) {
    token = "";
    byId("status").textContent = "连接失败；检查本机服务、Token 和配置。";
    notice(`连接失败：${error.message}`, "error");
  }
  updateButtons();
});

byId("task-form").addEventListener("input", invalidateCheck);
byId("confirm").addEventListener("change", updateButtons);
byId("task-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  invalidateCheck();
  let task;
  try { task = taskFromForm(); } catch (error) { return notice(error.message, "error"); }
  busy = true;
  updateButtons();
  notice("正在对每个来源进行一次受限的真实只读查询…");
  byId("checks").replaceChildren();
  try {
    const data = await api("/api/provider-check", task);
    byId("checks").replaceChildren(...data.checks.map((check) =>
      entry(check.source, check.status === "ok"
        ? `可读取 · ${check.evidence_count} 条（不代表相关）`
        : `读取失败 · ${sourceFailureLabels[check.reason_code] || check.reason_code} (${check.reason_code})`,
      `entry check ${check.status}`)));
    if (data.all_reachable && JSON.stringify(taskFromForm()) === JSON.stringify(task)) {
      checkedTask = task;
      notice("所有配置来源均可读取。核对任务后可显式发起调查；预检不是诊断。", "good");
    } else if (data.all_reachable) {
      notice("检查期间任务发生变化，请重新检查来源。", "error");
    } else {
      notice("有来源不可达；本次不能从页面发起调查。请核对权限、地址和时间窗。", "error");
    }
  } catch (error) { notice(`来源检查失败：${error.message}`, "error"); }
  finally { busy = false; updateButtons(); }
});

function showResult(data) {
  const result = data.result;
  const report = result.report;
  const labels = [
    `状态 ${report.status}`,
    `根因 ${report.selected_code || "未确定，需人工"}`,
    `查询 ${report.tool_queries} 次`,
    `编排 ${result.orchestration_mode}`,
    `Trace ${result.trace_id}`,
    `审计 ${data.audit.valid ? "完整" : "未通过"} · ${data.audit.event_count} 条`,
  ];
  byId("result-meta").replaceChildren(...labels.map((label) => {
    const pill = document.createElement("span"); pill.className = "pill"; pill.textContent = label; return pill;
  }));
  const refs = report.evidence_ids || [];
  byId("evidence-ids").replaceChildren(...(refs.length ? refs.map((id) => entry(id)) : [entry("没有可引用证据")]));
  const questions = report.unresolved_questions || [];
  byId("unresolved").replaceChildren(...(questions.length ? questions.map((q) => entry(q)) : [entry("无")]));
  byId("trace").replaceChildren(...result.trace.map((step) =>
    entry(`${step.step}. ${step.actor} · ${step.action} · ${step.status}`,
      `${step.source || "-"} · ${step.rationale} · 引用 ${(step.evidence_ids || []).join(", ") || "无"}`)));
  byId("audit").replaceChildren(...data.audit_events.map((event) =>
    entry(`#${event.sequence} ${event.actor} · ${event.action} · ${event.status}`,
      `${event.resource} · ${JSON.stringify(event.details)}`)));
  byId("result").hidden = false;
  byId("result").scrollIntoView({ behavior: "smooth" });
}

byId("run").addEventListener("click", async () => {
  if (!checkedTask || !byId("confirm").checked) return;
  const task = checkedTask;
  invalidateCheck();
  busy = true;
  updateButtons();
  notice("正在执行真实只读调查；请勿关闭此页或重复提交…");
  try {
    const data = await api("/api/investigate", { task, confirmed: true });
    showResult(data);
    notice(data.audit.valid
      ? "调查完成且审计链校验通过。请人工核对证据引用与最终结论。"
      : "调查已返回，但审计链校验失败；不得采信结论。", data.audit.valid ? "good" : "error");
  } catch (error) {
    notice(`调查未完成：${error.message}。请检查服务日志及事故预留状态，勿直接重复提交。`, "error");
  } finally { busy = false; updateButtons(); }
});

byId("recover").addEventListener("click", async () => {
  const incidentId = byId("incident-id").value.trim();
  if (incidentId.length < 3) return notice("先填写要找回的事故 ID。", "error");
  busy = true;
  updateButtons();
  notice("正在从本机数据库读取已完成结果；不会查询监控来源…");
  try {
    const data = await api("/api/recover", { incident_id: incidentId });
    showResult(data);
    notice(data.audit.valid
      ? "已找回结果，审计链校验通过；请核对原监控证据。"
      : "已找回结果，但审计链校验失败；不得采信结论。", data.audit.valid ? "good" : "error");
  } catch (error) {
    if (error.status !== 404) {
      notice(`找回失败：${error.message}。若审计校验失败，请停止采信结果并人工核查。`, "error");
    } else {
      try {
        const state = await api("/api/run-state", { incident_id: incidentId });
        const meanings = {
          not_found: "当前数据库没有该事故的运行预留；这不能证明其他数据库或旧进程从未查询来源。",
          running: "有运行预留，但尚无已保存结果。可能仍在执行，也可能在中断后遗留；请人工核查进程和审计。",
          abandoned: "该事故运行已失败并保留预留；禁止直接用同一 ID 重跑，请人工核查审计与来源。",
          completed: "运行记为完成，但没有找到可展示的结果；请人工核查数据库与审计。",
        };
        notice(state.result_saved
          ? "结果已保存，但本次找回未取得；请重新找回，若仍失败则人工核查。"
          : (meanings[state.state] || "运行状态未知；请人工核查。"), "error");
      } catch (stateError) {
        notice(`找回与状态查询均失败：${stateError.message}。请人工核查，勿重复提交。`, "error");
      }
    }
  } finally { busy = false; updateButtons(); }
});
