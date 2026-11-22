import {
  address, el, renderEvidence, renderFindings, renderMetrics, renderReports,
  renderWarnings, sessionButton, suiteText,
} from "./assessment.js";
import { createLibrary } from "./library.js";

const byId = (id) => document.getElementById(id);
const intake = byId("intake");
const assessment = byId("assessment");
const reportsLibrary = byId("reports-library");
const upload = byId("capture-file");
const dropZone = byId("drop-zone");
const choose = byId("choose-file");
const submit = byId("submit-capture");
const clear = byId("clear-file");
const cancel = byId("cancel-analysis");
const progress = byId("progress-message");
const processing = byId("processing");
const estimate = byId("time-estimate");
const errorNotice = byId("workspace-error");
const examples = byId("examples");
const sessionList = byId("session-list");
const tabs = [...byId("detail-tabs").querySelectorAll("[role=tab]")];
const library = createLibrary(reportsLibrary, showAssessment);
const mebibyte = 1024 * 1024;

let file = null;
let maxBytes = 0;
let supported = [];
let running = null;
let result = null;

function message(text = "") {
  errorNotice.textContent = text;
  errorNotice.hidden = !text;
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < mebibyte) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / mebibyte).toFixed(1)} MiB`;
}

function estimateTime(bytes) {
  const size = bytes / mebibyte;
  if (size <= 1) return "usually under 5 seconds";
  const low = Math.max(1, Math.ceil(size * 0.35));
  const high = Math.ceil(size * 5);
  return `about ${low}–${high} seconds`;
}

function showView(view, active = "ingestion") {
  for (const panel of [intake, assessment, reportsLibrary]) panel.hidden = panel !== view;
  if (view !== reportsLibrary) library.abort();
  for (const name of ["ingestion", "library"]) {
    const nav = byId(`nav-${name}`);
    if (name === active) nav.setAttribute("aria-current", "page");
    else nav.removeAttribute("aria-current");
  }
  byId(view.getAttribute("aria-labelledby")).focus();
  window.scrollTo(0, 0);
}

function updateControls() {
  const busy = Boolean(running);
  choose.disabled = busy || !maxBytes;
  submit.disabled = busy || !file;
  clear.hidden = busy || !file;
  cancel.hidden = !busy;
  processing.hidden = !busy;
  dropZone.setAttribute("aria-busy", String(busy));
  for (const example of examples.querySelectorAll("button")) example.disabled = busy;
  byId("selected-name").textContent = file?.name ?? "Drop a capture here";
  byId("selected-meta").textContent = file ? formatSize(file.size) : "Select one PCAP or PCAPNG file.";
  estimate.hidden = !file;
  estimate.textContent = file
    ? `Estimated processing time: ${estimateTime(file.size)}. Packet count and hardware affect timing.`
    : "";
}

function chooseFile(selected) {
  file = null;
  progress.textContent = "";
  const name = selected[0]?.name.toLowerCase() ?? "";
  const extension = name.lastIndexOf(".");
  if (selected.length > 1) message("Choose one capture per analysis.");
  else if (!selected.length) message();
  else if (extension < 1 || !supported.includes(name.slice(extension))) message("Choose a .pcap or .pcapng file.");
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
  renderReports(byId("reports"), session, result.id, index);
}

function showAssessment(data, active = "ingestion") {
  if (data?.version !== 1 || !data.id || !data.sessions?.length) {
    throw new Error("The dashboard received an incomplete analysis.");
  }
  result = data;
  byId("capture-caption").textContent = data.capture.name;
  const measured = data.processing_seconds === null ? "" : ` · Processed in ${data.processing_seconds.toFixed(1)} s`;
  byId("capture-summary").textContent = data.capture.summary + measured;
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
  showView(assessment, active);
}

async function runAnalysis(path, request, name, returnFocus) {
  if (running) return;
  const controller = new AbortController();
  const started = performance.now();
  const elapsed = byId("elapsed-time");
  const updateElapsed = () => {
    elapsed.textContent = `Elapsed time: ${Math.floor((performance.now() - started) / 1000)} s`;
  };
  updateElapsed();
  running = { controller, returnFocus, timer: setInterval(updateElapsed, 1000) };
  message();
  updateControls();
  progress.textContent = `Analyzing ${name}…`;
  cancel.focus({ preventScroll: true });
  try {
    const response = await fetch(path, { method: "POST", ...request, signal: controller.signal });
    const data = await response.json().catch(() => null);
    if (running?.controller !== controller) return;
    if (!response.ok) throw new Error(typeof data?.detail === "string" ? data.detail : "Analysis failed. Please retry.");
    if (!intake.hidden) showAssessment(data);
    else if (!reportsLibrary.hidden) library.refresh();
  } catch (error) {
    if (running?.controller !== controller) return;
    message(error instanceof TypeError ? "The local dashboard could not finish the request. Please retry." : error.message);
  } finally {
    if (running?.controller === controller) {
      clearInterval(running.timer);
      running = null;
      progress.textContent = "";
      updateControls();
      if (!intake.hidden) returnFocus.focus({ preventScroll: true });
    }
  }
}

function renderExamples(items) {
  examples.replaceChildren(...items.map((example) => {
    const button = el("button", "example");
    button.type = "button";
    const copy = el("span");
    copy.append(el("span", "example-title", example.title), el("span", "example-description", example.description));
    button.append(copy, el("span", "example-action", "Analyze"));
    button.addEventListener("click", () => runAnalysis(
      `/api/v1/examples/${encodeURIComponent(example.id)}`, {}, example.title, button,
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
  runAnalysis("/api/v1/captures", {
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
  clearInterval(request.timer);
  request.controller.abort();
  progress.textContent = "Stopped waiting. A completed analysis may appear in Saved reports.";
  updateControls();
  request.returnFocus.focus({ preventScroll: true });
});

function openIngestion(reset = false) {
  if (reset && !running) chooseFile([]);
  showView(intake);
}

byId("new-capture").addEventListener("click", () => openIngestion(true));
byId("library-new").addEventListener("click", () => openIngestion(true));
byId("nav-ingestion").addEventListener("click", () => openIngestion());
byId("nav-library").addEventListener("click", () => {
  showView(reportsLibrary, "library");
  library.refresh();
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
    const response = await fetch("/api/v1/workspace");
    if (!response.ok) throw new Error();
    const data = await response.json();
    maxBytes = data.max_capture_bytes;
    supported = data.capture_formats.map(({ extension }) => extension);
    upload.accept = supported.join(",");
    byId("file-limit").textContent = `${maxBytes / mebibyte} MiB limit`;
    byId("analysis-limits").textContent = `Up to ${data.max_packets.toLocaleString()} packets and ${data.max_sessions} sessions per analysis.`;
    byId("app-version").textContent = `Version ${data.version}`;
    byId("formats").replaceChildren(...data.capture_formats.map(({ extension, name, description }) => {
      const item = el("div");
      item.append(el("dt", "", name), el("dd", "extension", extension), el("dd", "subtle", description));
      return item;
    }));
    renderExamples(data.examples);
    updateControls();
  } catch {
    message("The local dashboard service could not be reached. Reload the page to retry.");
  }
}

init();
