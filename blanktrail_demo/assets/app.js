"use strict";

const $ = (id) => document.getElementById(id);
const radio = (name) => document.querySelector(`input[name="${name}"]:checked`).value;

let controller = null;

// Raw dumps arrive BEFORE the result they belong to, so they are buffered here and
// attached once the card exists. Appending them on arrival put every dump on the
// PREVIOUS target's card and left the last target with none.
let pendingRaw = [];

function collect() {
  return {
    targets: $("targets").value,
    lane_a: radio("lane_a"),
    lane_a_upstream: $("lane_a_upstream").value,
    lane_b: radio("lane_b"),
    preset_urls: $("preset_urls").value,
    api_base: $("api_base").value,
    api_key: $("api_key").value,
    port: Number($("port").value),
    protocol_b: $("protocol_b").value,
    mode: $("mode").value,
    browser: $("browser").value,
    os: $("os").value,
    upstream: $("upstream").value,
    js_solver: $("js_solver").checked,
    keep_sessions: $("keep_sessions").checked,
    auto_rotate: $("auto_rotate").checked,
    h2_spoofing: $("h2_spoofing").checked,
    spoof_user_agent: $("spoof_user_agent").checked,
    close_when_done: $("close_when_done").checked,
    trust_source: radio("trust_source"),
    ca_path: $("ca_path").value,
    tls_disabled: $("tls_disabled").checked,
    protocol: $("protocol").value,
    timeout: Number($("timeout").value),
    delay_min: Number($("delay_min").value),
    delay_max: Number($("delay_max").value),
  };
}

function syncPanels() {
  const apiMode = radio("lane_b") === "api";
  $("panel_api").hidden = !apiMode;
  $("panel_preset").hidden = apiMode;
  $("lane_a_upstream_field").hidden = radio("lane_a") !== "upstream";
  $("ca_path_field").hidden = radio("trust_source") !== "file";
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function laneLine(label, brief) {
  if (!brief) return el("div", "lane", `${label}: —`);
  const bits = [
    brief.status === null ? "—" : `HTTP ${brief.status}`,
    brief.state,
    brief.vendor || "",
    brief.proto || "",
    brief.ms === null ? "" : `${brief.ms} ms`,
  ].filter(Boolean);
  return el("div", "lane", `${label}: ${bits.join("  ·  ")} — ${brief.reason}`);
}

function renderMeta(event) {
  const box = $("warnings");
  box.textContent = "";
  const summary = el("div", "hint",
    `${event.targets} target(s) · baseline: ${event.lane_a} · BlankTrail: ${event.lane_b.mode}` +
    (event.lane_b.profile ? ` (${event.lane_b.profile})` : "") +
    ` · ${event.protocol} · TLS: ${event.tls}`);
  box.appendChild(summary);
  (event.warnings || []).forEach((text) => box.appendChild(el("div", "warn", text)));
}

function renderResult(event) {
  const item = el("div", "item");
  item.appendChild(el("h3", null, `${event.n}. ${event.url}`));
  const badge = el("span", `badge ${event.verdict}${event.no_baseline ? " faded" : ""}`,
                   event.verdict);
  const head = el("div", "row");
  head.appendChild(badge);
  if (event.no_baseline) head.appendChild(el("span", "hint", "no baseline lane"));
  item.appendChild(head);
  if (!event.no_baseline) item.appendChild(laneLine("baseline", event.a));
  item.appendChild(laneLine("BlankTrail", event.b));
  item.appendChild(el("p", "why", event.why));
  pendingRaw.forEach((entry) => item.appendChild(rawDetails(entry)));
  pendingRaw = [];
  $("log").appendChild(item);
  item.scrollIntoView({ block: "nearest" });
}

function rawDetails(entry) {
  const details = document.createElement("details");
  details.appendChild(el("summary", null,
    `raw dump — lane ${entry.lane} (${entry.kb} KB)`));
  const pre = document.createElement("pre");
  pre.textContent = entry.raw;
  details.appendChild(pre);
  return details;
}

function renderRaw(entry) {
  if (!entry.raw) return;
  pendingRaw.push(entry);
}

function renderStats(event) {
  $("counters").textContent =
    `PASS ${event.passed} · FAIL ${event.failed} · VOID ${event.void} · ` +
    `ERROR ${event.err} · ${event.done} done · ${event.elapsed}s · ${event.rpm} rpm`;
}

function handle(event) {
  if (event.type === "meta") return renderMeta(event);
  if (event.type === "target") {
    pendingRaw = [];
    $("log").appendChild(el("div", "status", `→ ${event.n}/${event.total} ${event.url}`));
    return;
  }
  if (event.type === "status") {
    $("log").appendChild(el("div", "status", event.text));
    return;
  }
  if (event.type === "log") return renderRaw(event.entry);
  if (event.type === "result") return renderResult(event);
  if (event.type === "stats") return renderStats(event);
  if (event.type === "error") {
    const box = el("div", "item");
    box.appendChild(el("span", "badge ERROR", "ERROR"));
    box.appendChild(el("p", "why", event.text));
    $("log").appendChild(box);
  }
}

async function start() {
  $("log").textContent = "";
  pendingRaw = [];
  $("counters").textContent = "";
  $("btn_run").disabled = true;
  $("btn_stop").disabled = false;
  controller = new AbortController();
  try {
    const response = await fetch("/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(collect()),
      signal: controller.signal,
    });
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop();
      for (const line of lines) {
        if (line.trim()) handle(JSON.parse(line));
      }
    }
  } catch (error) {
    if (error.name !== "AbortError") {
      $("log").appendChild(el("div", "warn", String(error)));
    }
  } finally {
    $("btn_run").disabled = false;
    $("btn_stop").disabled = true;
    controller = null;
  }
}

async function probeApi() {
  $("probe_out").textContent = "checking…";
  const response = await fetch("/api/probe", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      api_base: $("api_base").value,
      api_key: $("api_key").value,
      want_ca: radio("trust_source") === "api",
    }),
  });
  const data = await response.json();
  $("probe_out").textContent = data.ok
    ? `ok — ${data.total_open}/${data.max_ports} ports open` +
      (data.ca ? ", CA reachable" : "")
    : `failed — ${data.error}`;
}

document.querySelectorAll('input[name="lane_a"], input[name="lane_b"], input[name="trust_source"]')
  .forEach((node) => node.addEventListener("change", syncPanels));
$("btn_run").addEventListener("click", start);
$("btn_stop").addEventListener("click", () => controller && controller.abort());
$("btn_probe").addEventListener("click", probeApi);
syncPanels();
