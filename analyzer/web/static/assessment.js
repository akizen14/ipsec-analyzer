const labels = {
  nat_t: "NAT traversal",
  version: "IKE version",
  exchange_mode: "Exchange mode",
  encr: "Encryption",
  encr_key_bits: "IKE key length",
  prf: "Pseudorandom function",
  integ: "Integrity",
  dh_group: "DH group",
  auth_method: "Authentication",
  peer_identity: "Peer identity",
  sa_lifetime_s: "SA lifetime",
  fragmentation_used: "Fragmentation",
  selected_proposal: "Selected proposal",
  offered_proposals: "Offered proposals",
  notifications: "Notifications",
  vendor_ids: "Vendor IDs",
  protocol: "Protocol",
  cipher_family: "Cipher family",
  icv_bytes: "ICV length",
  block_size_bytes: "Block size",
  key_length: "ESP key length",
  mode: "Mode",
  pfs_on_rekey: "PFS on rekey",
  rekey_interval_s: "Observed SPI interval",
  traffic_type: "Traffic type",
  udp_encapsulated: "UDP encapsulation",
  replay_evidence: "Sequence observations",
};
const severities = new Set(["low", "medium", "high", "critical", "informational"]);
const levels = new Set(["observed", "inferred", "assisted", "unknown"]);

export function el(tag, className = "", text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function sentence(value) {
  const words = String(value ?? "").replaceAll("_", " ");
  return words ? words[0].toUpperCase() + words.slice(1) : "Unknown";
}

function riskClass(value) {
  return severities.has(value) ? `risk ${value}` : "risk";
}

function percentage(value) {
  return `${Math.round(value * 100)}%`;
}

export function address(record) {
  return `${record.endpoints.initiator} → ${record.endpoints.responder}`;
}

export function sessionButton(record, index) {
  const button = el("button", "session-button");
  button.type = "button";
  const cipher = record.ike.encr?.value?.replace(/^ENCR_/, "");
  button.append(
    el("span", "session-label", `Session ${index + 1}${cipher ? ` · ${cipher}` : ""}`),
    el("span", "address", address(record)),
    el("span", riskClass(record.score.risk_level), `${sentence(record.score.risk_level)} risk · ${record.score.value}/100`),
  );
  return button;
}

export function renderMetrics(target, record) {
  const items = [
    ["Risk", sentence(record.score.risk_level), "", riskClass(record.score.risk_level)],
    ["Security score", `${record.score.value}/100`, "", ""],
    ["Evidence coverage", percentage(record.coverage.fraction), `${record.coverage.determinable} / ${record.coverage.total} attributes`, ""],
    ["Findings", record.findings.length, "", ""],
  ];
  target.replaceChildren(...items.map(([name, value, note, className]) => {
    const entry = el("div", "metric");
    entry.append(el("dt", "", name), el("dd", className, value));
    if (note) entry.append(el("dd", "metric-note", note));
    return entry;
  }));
}

export function suiteText(record) {
  const ike = record.ike;
  const suite = [ike.version?.value, ike.encr?.value?.replace(/^ENCR_/, "")];
  if (ike.encr_key_bits?.value) suite.push(`${ike.encr_key_bits.value}-bit key`);
  if (ike.dh_group?.value) suite.push(`DH group ${ike.dh_group.value}`);
  return suite.filter(Boolean).join(" · ") || "No IKE suite could be established from this capture.";
}

export function renderWarnings(target, title, values, expanded = false) {
  target.replaceChildren();
  if (!values.length) return;
  const block = el("details", "notice");
  block.open = expanded;
  block.append(el("summary", "", `${title} (${values.length})`));
  const list = el("ul");
  list.append(...values.map((warning) => el("li", "", warning)));
  block.append(list);
  target.append(block);
}

export function renderFindings(target, record, seeEvidence) {
  target.replaceChildren();
  if (!record.findings.length) {
    target.append(el("h3", "", "No findings in the analyzed evidence"), el(
      "p", "subtle", "Review coverage and Unknown attributes before drawing conclusions.",
    ));
  }
  for (const [index, finding] of record.findings.entries()) {
    const entry = el("details", "finding");
    entry.open = index === 0;
    const summary = el("summary");
    summary.append(
      el("span", riskClass(finding.severity), sentence(finding.severity)),
      el("span", "finding-id", finding.rule_id),
      el("span", "", finding.title),
    );
    entry.append(summary);
    const body = el("dl", "finding-body");
    const fields = [
      ["Details", finding.detail],
      ["Recommendation", finding.remediation],
      ["Basis", finding.standard],
      ["Finding confidence", percentage(finding.confidence)],
    ];
    for (const [label, value] of fields) {
      if (!value) continue;
      const row = el("div");
      row.append(el("dt", "", label), el("dd", "", value));
      body.append(row);
    }
    if (finding.evidence?.length) {
      const row = el("div");
      const reference = el("dd");
      for (const pointer of finding.evidence) {
        const button = el("button", "button text-button evidence-link", `View ${labels[pointer.split("/").at(-1)] ?? pointer}`);
        button.type = "button";
        button.addEventListener("click", () => seeEvidence(pointer));
        reference.append(button);
      }
      row.append(el("dt", "", "Evidence"), reference);
      body.append(row);
    }
    entry.append(body);
    target.append(entry);
  }
  if (record.threat_matrix?.length) {
    const section = el("section", "matrix");
    const list = el("ul");
    list.append(...record.threat_matrix.map((row) => el(
      "li", "", `${row.threat} · ${sentence(row.rating)} risk`,
    )));
    section.append(el("h3", "", "Threat matrix"), list);
    target.append(section);
  }
}

function evidenceNotes(attribute) {
  const notes = [];
  if (attribute.packets?.length) notes.push(`Packets ${attribute.packets.join(", ")}`);
  if (attribute.evidence === "inferred") {
    notes.push(`${percentage(attribute.confidence)} confidence${attribute.calibrated ? "" : " (uncalibrated)"}`);
  }
  for (const part of [attribute.method, attribute.source_detail || attribute.source, attribute.reason, attribute.note]) {
    if (part) notes.push(part);
  }
  return notes.join(" · ");
}

function displayValue(value) {
  if (value == null) return "Unknown";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}

function evidenceRow(label, value, tag, type, notes) {
  const row = el("div", "evidence-row");
  row.tabIndex = -1;
  const output = el("dd");
  output.append(
    el("span", `evidence-tag ${type}`, tag),
    el("span", "evidence-value", value),
  );
  for (const note of notes.filter(Boolean)) output.append(el("p", "evidence-detail", note));
  row.append(el("dt", "", label), output);
  return row;
}

function packetNote(entry) {
  return entry.packet ? `Packet ${entry.packet}` : "";
}

function proposalText(proposal) {
  return [
    proposal.encr, proposal.encr_key_bits && `${proposal.encr_key_bits}-bit`,
    proposal.integ, proposal.prf, proposal.dh_group && `DH${proposal.dh_group}`,
    packetNote(proposal),
  ].filter(Boolean).join(" · ");
}

function structuredNotes(base, data) {
  if (base === "/ike") return [
    ["selected_proposal", data.selected_proposal ? [proposalText(data.selected_proposal)] : []],
    ["offered_proposals", (data.offered_proposals ?? []).map(proposalText)],
    ["notifications", (data.notifications ?? []).map((entry) => (
      [entry.name ?? `Type ${entry.type}`, packetNote(entry)].filter(Boolean).join(" · ")
    ))],
    ["vendor_ids", (data.vendor_ids ?? []).map((entry) => (
      [entry.interpreted || entry.raw, packetNote(entry)].filter(Boolean).join(" · ")
    ))],
  ];
  const replay = data.replay_evidence;
  if (replay) return [[
    "replay_evidence",
    [`${replay.duplicate_seqs} duplicates · ${replay.reordered_seqs} reordered · ${replay.gaps} gaps`],
  ]];
  return [];
}

export function renderEvidence(target, record) {
  const indexed = new Map();
  const referenced = new Set(record.findings.flatMap((finding) => finding.evidence ?? []));
  target.replaceChildren();
  const groups = [
    ["Peer evidence", "/endpoints", record.endpoints],
    ["IKE security association", "/ike", record.ike],
    ...record.child_sas.map((sa, index) => [
      `Child SA ${sa.spi}`, `/child_sas/${index}`, sa,
    ]),
  ];
  for (const [heading, base, attributes] of groups) {
    const rows = el("dl");
    for (const [key, attribute] of Object.entries(attributes)) {
      if (!levels.has(attribute?.evidence)) continue;
      const row = evidenceRow(
        labels[key] ?? sentence(key), displayValue(attribute.value),
        sentence(attribute.evidence), attribute.evidence, [evidenceNotes(attribute)],
      );
      rows.append(row);
      indexed.set(`${base}/${key}`, row);
    }
    for (const [key, notes] of structuredNotes(base, attributes)) {
      const pointer = `${base}/${key}`;
      if (!notes.length && !referenced.has(pointer)) continue;
      const row = evidenceRow(
        labels[key], notes.length ? "" : "None recorded in visible packets",
        "Packet metadata", "", notes,
      );
      rows.append(row);
      indexed.set(pointer, row);
    }
    if (rows.childElementCount) {
      const group = el("section", "evidence-group");
      group.append(el("h3", "", heading), rows);
      target.append(group);
    }
  }
  if (!indexed.size) target.append(el("p", "subtle", "This session has no configuration evidence."));
  return indexed;
}

export function renderReports(target, { record, reports }) {
  target.replaceChildren(el("h3", "", "Download assessment"));
  const options = el("div", "report-options");
  const downloads = [
    ["Executive report", "Risk, coverage, and recommended actions", "executive.html", "text/html", reports.executive],
    ["Technical report", "Configuration, findings, and supporting evidence", "technical.html", "text/html", reports.technical],
    ["Session record", "Structured assessment and evidence", "json", "application/json", JSON.stringify(record, null, 2)],
  ];
  for (const [title, description, filename, type, contents] of downloads) {
    const option = el("div", "report-option");
    const label = el("div");
    label.append(el("strong", "", title), el("p", "", description));
    const button = el("button", "button outline", "Download");
    button.type = "button";
    button.setAttribute("aria-label", `Download ${title.toLowerCase()}`);
    button.addEventListener("click", () => {
      const url = URL.createObjectURL(new Blob([contents], { type }));
      const anchor = el("a");
      anchor.href = url;
      anchor.download = `${record.session_id}${filename === "json" ? "." : "-"}${filename}`;
      anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 1_000);
    });
    option.append(label, button);
    options.append(option);
  }
  target.append(options);
}
