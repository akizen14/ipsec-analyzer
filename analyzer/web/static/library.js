import { el, riskClass, sentence } from "./assessment.js";

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const sourceNames = { capture: "Uploaded capture", example: "Example capture", cli: "CLI report" };

export function createLibrary(page, showAssessment) {
  const search = page.querySelector("#report-search");
  const list = page.querySelector("#saved-list");
  const status = page.querySelector("#library-status");
  const empty = page.querySelector("#library-empty");
  const columns = page.querySelector("#report-columns");
  const notice = page.querySelector("#library-error");
  const retry = page.querySelector("#retry-library");
  let reports = [];
  let request = null;
  let ready = false;

  function showError(text = "") {
    notice.textContent = text;
    notice.hidden = !text;
  }

  function render() {
    if (!ready) return;
    const query = search.value.trim().toLocaleLowerCase();
    const matching = reports.filter(({ name }) => name.toLocaleLowerCase().includes(query));
    const total = query ? `${matching.length} of ${reports.length}` : String(reports.length);
    status.textContent = `${total} saved ${reports.length === 1 ? "report" : "reports"}`;
    columns.hidden = !matching.length;
    empty.hidden = Boolean(matching.length);
    empty.textContent = query ? "No reports match this filename." : "Analyze a capture to save your first report.";
    list.replaceChildren();
    for (const report of matching) {
      const item = el("li", "saved-row");
      const capture = el("div", "saved-capture");
      capture.append(el("strong", "", report.name));
      capture.append(el("p", "subtle", sourceNames[report.source] + (report.partial ? " · Partial analysis" : "")));
      const date = new Date(report.saved_at);
      const analyzed = el("time", "saved-date subtle", Number.isNaN(date.valueOf()) ? "Unknown date" : dateFormat.format(date));
      analyzed.dateTime = report.saved_at;
      const open = el("button", "button outline", "Open report");
      open.type = "button";
      open.addEventListener("click", () => openReport(report, open));
      open.setAttribute("aria-label", `Open report for ${report.name}`);
      item.append(
        capture,
        el("span", riskClass(report.worst_risk), `${sentence(report.worst_risk)} risk`),
        el("span", "saved-count", `${report.session_count} ${report.session_count === 1 ? "session" : "sessions"}`),
        analyzed,
        open,
      );
      list.append(item);
    }
  }

  async function read(path, signal) {
    const response = await fetch(path, { signal });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail);
    return data;
  }

  async function refresh() {
    request?.abort();
    const controller = new AbortController();
    request = controller;
    ready = false;
    search.disabled = true;
    list.replaceChildren();
    columns.hidden = true;
    empty.hidden = true;
    retry.hidden = true;
    showError();
    status.textContent = "Loading saved reports…";
    try {
      const data = await read("/api/reports", controller.signal);
      if (controller.signal.aborted) return;
      reports = data.reports;
      ready = true;
      search.disabled = false;
      render();
      if (data.unreadable) showError(`${data.unreadable} saved ${data.unreadable === 1 ? "record could" : "records could"} not be read.`);
    } catch {
      if (controller.signal.aborted) return;
      status.textContent = "Report history unavailable";
      showError("The local report library could not be loaded.");
      retry.hidden = false;
    }
  }

  async function openReport(report, button) {
    request?.abort();
    const controller = new AbortController();
    request = controller;
    button.setAttribute("aria-busy", "true");
    button.textContent = "Opening…";
    showError();
    try {
      const data = await read(`/api/reports/${report.id}`, controller.signal);
      if (!controller.signal.aborted) showAssessment(data, "library");
    } catch (error) {
      if (!controller.signal.aborted) showError(error instanceof TypeError ? "The local report could not be opened." : error.message);
    } finally {
      button.removeAttribute("aria-busy");
      button.textContent = "Open report";
    }
  }

  search.addEventListener("input", render);
  retry.addEventListener("click", refresh);
  return { refresh, abort: () => request?.abort() };
}
