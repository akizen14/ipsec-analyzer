import {
  address, el, renderEvidence, renderFindings, renderMetrics, renderReports,
  renderWarnings, sessionButton, suiteText,
} from "./assessment.js";
import { createTunnel } from "./motion.js";

const byId = (id) => document.getElementById(id);
const intake = byId("intake");
const assessment = byId("assessment");
const upload = byId("capture-file");
const dropZone = byId("drop-zone");
const choose = byId("choose-file");
const submit = byId("submit-capture");
const clear = byId("clear-file");
const cancel = byId("cancel-analysis");
const progress = byId("progress-message");
const errorNotice = byId("workspace-error");
const examples = byId("examples");
const sessionList = byId("session-list");
const tabs = [...byId("detail-tabs").querySelectorAll("[role=tab]")];
const showTunnel = createTunnel(byId("tunnel"), byId("tunnel-chassis"), byId("tunnel-signal"));

let file = null;
let maxBytes = 0;
let running = null;
let result = null;

function message(text = "") {
  errorNotice.textContent = text;
  errorNotice.hidden = !text;
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function updateControls() {
  const busy = Boolean(running);
  choose.disabled = busy || !maxBytes;
  submit.disabled = busy || !file;
  clear.hidden = busy || !file;
  cancel.hidden = !busy;
  dropZone.setAttribute("aria-busy", String(busy));
  for (const example of examples.querySelectorAll("button")) example.disabled = busy;
  byId("selected-name").textContent = file?.name ?? "Drop a capture here";
  byId("selected-meta").textContent = file ? formatSize(file.size) : "PCAP or PCAPNG";
}

function chooseFile(selected) {
  file = null;
  progress.textContent = "";
  if (selected.length > 1) message("Choose one capture per analysis.");
  else if (!selected.length) message();
  else if (!/\.pcap(?:ng)?$/i.test(selected[0].name)) message("Choose a .pcap or .pcapng file.");
  else if (!selected[0].size) message("The selected capture is empty.");
  else if (selected[0].size > maxBytes) message("This capture exceeds the upload limit.");
  else {
    file = selected[0];
    message();
  }
  updateControls();
}

function selectTab(tab, focus = false) {
  for (const item of tabs) {
    const selected = item === tab;
    item.setAttribute("aria-selected", String(selected));
    item.tabIndex = selected ? 0 : -1;
    byId(item.getAttribute("aria-controls")).hidden = !selected;
  }
  if (focus) tab.focus();
}

function renderSession(index) {
  const session = result.sessions[index];
  const { record } = session;
  [...sessionList.children].forEach((button, position) => {
    button.setAttribute("aria-pressed", String(position === index));
  });
  byId("session-title").textContent = address(record);
  byId("session-suite").textContent = suiteText(record);
  renderMetrics(byId("session-metrics"), record);
  const notes = (record.warnings ?? []).filter((warning) => !result.capture.warnings.includes(warning));
  renderWarnings(byId("session-warnings"), "Session caveats", [...new Set(notes)]);
  const rows = renderEvidence(byId("evidence"), record);
  renderFindings(byId("findings"), record, (pointer) => {
    selectTab(byId("evidence-tab"));
    (rows.get(pointer) ?? byId("evidence")).focus();
  });
  renderReports(byId("reports"), session);
}

function showAssessment(data) {
  result = data;
  byId("capture-caption").textContent = data.capture.name;
  byId("capture-summary").textContent = data.capture.summary;
  byId("session-count").textContent = String(data.sessions.length);
  const partial = data.sessions.some(({ record }) => record.source.truncated);
  const warnings = [...data.capture.warnings];
  if (partial && !warnings.length) warnings.push("At least one session contains incomplete packet data.");
  renderWarnings(byId("capture-warnings"), partial ? "Partial capture" : "Capture caveats", warnings, partial);
  sessionList.replaceChildren(...data.sessions.map(({ record }, index) => {
    const button = sessionButton(record, index);
    button.addEventListener("click", () => renderSession(index));
    return button;
  }));
  selectTab(tabs[0]);
  renderSession(0);
  intake.hidden = true;
  assessment.hidden = false;
  byId("results-title").focus();
  window.scrollTo(0, 0);
}

async function runAnalysis(path, request, name, returnFocus) {
  if (running) return;
  const controller = new AbortController();
  running = { controller, returnFocus };
  message();
  updateControls();
  progress.textContent = `Analyzing ${name}…`;
  showTunnel("running");
  cancel.focus({ preventScroll: true });
  try {
    const response = await fetch(path, { method: "POST", ...request, signal: controller.signal });
    const data = await response.json().catch(() => null);
    if (running?.controller !== controller) return;
    if (!response.ok) throw new Error(typeof data?.detail === "string" ? data.detail : "Analysis failed. Please retry.");
    if (data?.version !== 1 || !data.sessions?.length) throw new Error("The dashboard received an incomplete analysis.");
    showAssessment(data);
  } catch (error) {
    if (running?.controller !== controller) return;
    message(error instanceof TypeError ? "The local dashboard could not finish the request. Please retry." : error.message);
  } finally {
    if (running?.controller === controller) {
      running = null;
      progress.textContent = "";
      showTunnel("ready");
      updateControls();
      if (!intake.hidden) returnFocus.focus({ preventScroll: true });
    }
  }
}

function renderExamples(items) {
  examples.replaceChildren(...items.map((example) => {
    const button = el("button", "example");
    button.type = "button";
    const mark = el("span", `example-mark risk ${example.id === "healthy" ? "low" : "high"}`, "[·]");
    mark.setAttribute("aria-hidden", "true");
    const copy = el("span");
    copy.append(el("span", "example-title", example.title), el("span", "example-description", example.description));
    const arrow = el("span", "example-arrow", "→");
    arrow.setAttribute("aria-hidden", "true");
    button.append(mark, copy, arrow);
    button.addEventListener("click", () => runAnalysis(
      `/api/examples/${encodeURIComponent(example.id)}`, {}, example.title, button,
    ));
    return button;
  }));
}

choose.addEventListener("click", () => upload.click());
upload.addEventListener("change", () => {
  if (!running && maxBytes && upload.files.length) chooseFile(upload.files);
  upload.value = "";
});
clear.addEventListener("click", () => {
  chooseFile([]);
  choose.focus();
});
for (const name of ["dragenter", "dragover", "dragleave", "drop"]) {
  dropZone.addEventListener(name, (event) => {
    event.preventDefault();
    const over = name === "dragenter" || name === "dragover";
    dropZone.classList.toggle("is-over", Boolean(over && !running && maxBytes));
    if (name === "drop" && !running && maxBytes) chooseFile(event.dataTransfer.files);
  });
}

byId("capture-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (!file) return;
  runAnalysis("/api/captures", {
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Capture-Name": encodeURIComponent(file.name),
    },
    body: file,
  }, file.name, submit);
});

cancel.addEventListener("click", () => {
  const request = running;
  if (!request) return;
  running = null;
  request.controller.abort();
  progress.textContent = "Analysis cancelled.";
  showTunnel("ready");
  updateControls();
  request.returnFocus.focus({ preventScroll: true });
});

byId("new-capture").addEventListener("click", () => {
  result = null;
  for (const id of ["session-list", "findings", "evidence", "reports", "session-metrics",
    "capture-warnings", "session-warnings", "capture-caption", "capture-summary", "session-title", "session-suite"]) {
    byId(id).replaceChildren();
  }
  assessment.hidden = true;
  intake.hidden = false;
  chooseFile([]);
  showTunnel("ready");
  byId("intake-title").focus();
  window.scrollTo(0, 0);
});

for (const [index, tab] of tabs.entries()) {
  tab.addEventListener("click", () => selectTab(tab));
  tab.addEventListener("keydown", (event) => {
    const destinations = {
      ArrowLeft: (index + tabs.length - 1) % tabs.length,
      ArrowRight: (index + 1) % tabs.length,
      Home: 0,
      End: tabs.length - 1,
    };
    if (!Object.hasOwn(destinations, event.key)) return;
    event.preventDefault();
    selectTab(tabs[destinations[event.key]], true);
  });
}

async function init() {
  updateControls();
  try {
    const response = await fetch("/api/workspace");
    if (!response.ok) throw new Error();
    const data = await response.json();
    maxBytes = data.max_capture_bytes;
    byId("file-limit").textContent = `${maxBytes / (1024 * 1024)} MiB limit`;
    byId("app-version").textContent = `Version ${data.version}`;
    renderExamples(data.examples);
    updateControls();
  } catch {
    message("The local dashboard service could not be reached. Reload the page to retry.");
  }
}

init();
