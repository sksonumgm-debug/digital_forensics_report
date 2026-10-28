(() => {
  "use strict";

  const root = document.documentElement;
  const themeButtons = document.querySelectorAll("[data-theme-toggle]");
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (form instanceof HTMLFormElement && form.dataset.confirm
        && !window.confirm(form.dataset.confirm)) {
      event.preventDefault();
    }
  });
  try {
    const savedTheme = localStorage.getItem("ai-dfir-theme");
    if (savedTheme === "light" || savedTheme === "dark") root.dataset.theme = savedTheme;
  } catch (error) {
    // Theme selection remains usable when browser storage is disabled.
  }
  const updateThemeButtons = () => {
    const nextTheme = root.dataset.theme === "dark" ? "light" : "dark";
    themeButtons.forEach((button) => {
      button.setAttribute("aria-label", `Switch to ${nextTheme} theme`);
      button.innerHTML = `${nextTheme === "light" ? "☼" : "☾"} <span>${nextTheme === "light" ? "Light" : "Dark"} mode</span>`;
    });
  };
  updateThemeButtons();
  themeButtons.forEach((button) => button.addEventListener("click", () => {
    root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
    try {
      localStorage.setItem("ai-dfir-theme", root.dataset.theme);
    } catch (error) {
      // The selected theme still applies for this page view.
    }
    updateThemeButtons();
    window.dispatchEvent(new Event("ai-dfir-theme-change"));
  }));

  document.querySelectorAll("[data-table-search]").forEach((input) => {
    if (!(input instanceof HTMLInputElement)) return;
    const rows = [...document.querySelectorAll(input.dataset.tableSearch || "")];
    const emptyRow = input.dataset.emptyRow
      ? document.querySelector(input.dataset.emptyRow)
      : null;
    const status = input.getAttribute("aria-describedby")
      ? document.getElementById(input.getAttribute("aria-describedby"))
      : null;
    input.addEventListener("input", () => {
      const query = input.value.trim().toLocaleLowerCase();
      let matches = 0;
      rows.forEach((row) => {
        const visible = !query || (row.textContent || "").toLocaleLowerCase().includes(query);
        row.hidden = !visible;
        if (visible) matches += 1;
      });
      if (emptyRow) emptyRow.hidden = matches !== 0;
      if (status) {
        status.textContent = query
          ? `${matches} matching record${matches === 1 ? "" : "s"}.`
          : "";
      }
    });
  });

  const dataElement = document.getElementById("case-data");
  if (!dataElement) return;
  const caseData = JSON.parse(dataElement.textContent || "{}");
  const baseUrl = `/api/cases/${caseData.caseId}`;
  const timestampOrder = (value) => {
    const parsed = Date.parse(value || "");
    return Number.isFinite(parsed) ? parsed : Number.POSITIVE_INFINITY;
  };
  const events = [...(caseData.events || []), ...(caseData.networkEvents || [])]
    .sort((left, right) => timestampOrder(left.timestamp) - timestampOrder(right.timestamp));
  const evidence = caseData.evidence || [];
  const diskImages = caseData.diskImages || [];
  const captures = caseData.packetCaptures || [];
  const notes = caseData.notes || [];
  const charts = [];
  const chartColors = () => {
    const styles = getComputedStyle(root);
    return {
      text: styles.getPropertyValue("--muted").trim(),
      grid: styles.getPropertyValue("--line").trim(),
      accent: styles.getPropertyValue("--blue").trim()
    };
  };
  const updateChartTheme = () => {
    const colors = chartColors();
    charts.forEach((chart) => {
      chart.options.plugins.legend.labels.color = colors.text;
      if (chart.config.type === "bar") {
        chart.data.datasets.forEach((dataset) => { dataset.backgroundColor = colors.accent; });
      }
      if (chart.options.scales) {
        chart.options.scales.x.ticks.color = colors.text;
        chart.options.scales.x.grid.color = colors.grid;
        chart.options.scales.y.ticks.color = colors.text;
      }
      chart.update();
    });
  };
  window.addEventListener("ai-dfir-theme-change", updateChartTheme);

  const addText = (parent, tag, text, className) => {
    const element = document.createElement(tag);
    element.textContent = text == null ? "" : String(text);
    if (className) element.className = className;
    parent.append(element);
    return element;
  };

  const parseDetails = (event) => {
    if (!event.details) return {};
    if (typeof event.details === "object") return event.details;
    try {
      return JSON.parse(event.details);
    } catch (error) {
      return { parse_error: true };
    }
  };

  const requestJson = async (url, options = {}) => {
    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": document.querySelector('meta[name="csrf-token"]')?.content || "",
        ...(options.headers || {})
      }
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
    return data;
  };

  const displayMetrics = (metrics) => {
    const metricsGrid = document.getElementById("evaluation");
    if (!metricsGrid) return;
    const values = {
      "rule-flagged-count": metrics.rule_flagged,
      "model-flag-count": metrics.model_flagged,
      "precision-value": metrics.precision,
      "recall-value": metrics.recall,
      "false-positive-rate-value": metrics.false_positive_rate,
      "labeled-count-value": metrics.labeled_count
    };
    Object.entries(values).forEach(([id, value]) => {
      const element = document.getElementById(id);
      if (!element) return;
      if (id.endsWith("-value") && id !== "labeled-count-value") {
        element.textContent = value == null ? "Not measured" : `${(value * 100).toFixed(1)}%`;
      } else {
        element.textContent = String(value ?? 0);
      }
    });
    const precisionRatio = document.getElementById("precision-value");
    const recallRatio = document.getElementById("recall-value");
    const falsePositiveRatio = document.getElementById("false-positive-rate-value");
    if (precisionRatio?.nextElementSibling) {
      precisionRatio.nextElementSibling.textContent = `${metrics.true_positive} TP / ${metrics.false_positive} FP`;
    }
    if (recallRatio?.nextElementSibling) {
      recallRatio.nextElementSibling.textContent = `${metrics.true_positive} TP / ${metrics.false_negative} FN`;
    }
    if (falsePositiveRatio?.nextElementSibling) {
      falsePositiveRatio.nextElementSibling.textContent = `${metrics.false_positive} FP / ${metrics.true_negative} TN`;
    }
  };

  const renderExplanation = (row, record) => {
    const content = row.querySelector(".explanation-content");
    if (!content) return;
    const details = parseDetails(record);
    if (details.parse_error) {
      addText(content, "p", "The saved explanation could not be read. Review the original evidence directly.");
    } else if (Array.isArray(details.reasons) && details.reasons.length) {
      const list = document.createElement("ul");
      details.reasons.forEach((reason) => addText(list, "li", reason));
      content.append(list);
    } else {
      addText(content, "p", "No detection explanation was retained for this record.");
    }
    if (details.model) {
      const model = details.model;
      addText(content, "p",
        `Isolation Forest anomaly score: ${Number(model.anomaly_score).toFixed(4)}; threshold: ${Number(model.threshold).toFixed(4)}. ` +
        `Input features: ${JSON.stringify(model.features)}. Feature contributions are counterfactual score changes; positive values raised the anomaly score.`,
        "model-note");
      if (model.feature_contributions) {
        const contributionList = document.createElement("ul");
        Object.entries(model.feature_contributions).forEach(([feature, amount]) => {
          addText(contributionList, "li", `${feature}: ${Number(amount).toFixed(4)} score contribution`);
        });
        content.append(contributionList);
      }
    } else if (details.model_flagged) {
      addText(content, "p", "Model flag recorded, but score and feature explanation were not retained.", "model-note");
    }
    if (details.original_message) {
      const original = document.createElement("details");
      addText(original, "summary", "View parsed source text");
      addText(original, "p", details.original_message);
      content.append(original);
    }
  };

  const severityCounts = { info: 0, low: 0, medium: 0, high: 0 };
  const typeCounts = {};
  events.forEach((event) => {
    const severity = (event.severity || "info").toLowerCase();
    severityCounts[severity] = (severityCounts[severity] || 0) + 1;
    const type = event.event_type || "unknown";
    typeCounts[type] = (typeCounts[type] || 0) + 1;
  });
  if (window.Chart && events.length) {
    const severityCanvas = document.getElementById("severityChart");
    if (severityCanvas) charts.push(new Chart(severityCanvas, {
      type: "doughnut",
      data: {
        labels: Object.keys(severityCounts),
        datasets: [{
          data: Object.values(severityCounts),
          backgroundColor: ["#536f82", "#2795af", "#e7a758", "#ef6874"],
          borderWidth: 0
        }]
      },
      options: {
        maintainAspectRatio: false,
        plugins: { legend: { position: "bottom", labels: { color: chartColors().text, usePointStyle: true } } }
      }
    }));
    const typeCanvas = document.getElementById("typeChart");
    if (typeCanvas) charts.push(new Chart(typeCanvas, {
      type: "bar",
      data: {
        labels: Object.keys(typeCounts).slice(0, 8),
        datasets: [{
          label: "Records",
          data: Object.values(typeCounts).slice(0, 8),
          backgroundColor: chartColors().accent,
          borderRadius: 4
        }]
      },
      options: {
        indexAxis: "y",
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { beginAtZero: true, ticks: { color: chartColors().text, precision: 0 }, grid: { color: chartColors().grid } },
          y: { ticks: { color: chartColors().text }, grid: { display: false } }
        }
      }
    }));
  }

  const rows = events.map((record) => document.getElementById(`event-${record.record_key}`)).filter(Boolean);
  const timelineBody = document.querySelector(".timeline-table tbody");
  rows.forEach((row, index) => {
    row.dataset.eventIndex = String(index);
    timelineBody?.append(row);
  });
  const recordsBySource = new Map();
  events.forEach((record, index) => {
    const source = (record.source_ip || "").trim();
    const timestamp = Date.parse(record.timestamp || "");
    if (!source || !Number.isFinite(timestamp)) return;
    const group = recordsBySource.get(source) || [];
    group.push({ index, timestamp });
    recordsBySource.set(source, group);
  });
  recordsBySource.forEach((records) => {
    let sequence = [];
    records.forEach((record) => {
      if (sequence.length && record.timestamp - sequence[sequence.length - 1].timestamp > 10 * 60 * 1000) {
        markSequence(sequence);
        sequence = [];
      }
      sequence.push(record);
    });
    markSequence(sequence);
  });
  function markSequence(sequence) {
    if (sequence.length < 2) return;
    sequence.forEach(({ index }) => {
      const indicator = rows[index]?.querySelector(".sequence-indicator");
      if (indicator) indicator.textContent = `Related activity sequence · ${sequence.length} records within 10 minutes`;
    });
  }
  rows.forEach((row, index) => {
    const record = events[index];
    if (!record) return;
    renderExplanation(row, record);
    const review = row.querySelector(".feedback-form");
    review?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = review.querySelector("button");
      const select = review.elements.decision;
      if (!select.value) return;
      button.disabled = true;
      try {
        const result = await requestJson(
          `${baseUrl}/feedback/${review.dataset.recordType}/${review.dataset.recordId}`,
          {
            method: "POST",
            body: JSON.stringify({ decision: select.value, note: review.elements.note.value })
          }
        );
        const summary = review.closest("details")?.querySelector("summary");
        if (summary) summary.textContent = select.selectedOptions[0].textContent;
        displayMetrics(result.metrics);
        const status = document.getElementById("feedback-status");
        if (status) status.textContent = "Review outcome saved to this case.";
      } catch (error) {
        const status = document.getElementById("feedback-status");
        if (status) status.textContent = error.message;
      } finally {
        button.disabled = false;
      }
    });
  });

  const drawFlowGraph = (container, flows) => {
    container.replaceChildren();
    if (!flows.length) {
      addText(container, "p", "No IP communications were found in this capture.", "empty-inline");
      return;
    }
    const flowRows = flows.slice(0, 12);
    const svgNamespace = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNamespace, "svg");
    svg.setAttribute("viewBox", `0 0 760 ${Math.max(125, flowRows.length * 38 + 24)}`);
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", `Network communication graph with ${flowRows.length} flow records`);
    svg.classList.add("flow-graph");
    flowRows.forEach((flow, index) => {
      const y = 24 + index * 38;
      const line = document.createElementNS(svgNamespace, "line");
      line.setAttribute("x1", "172");
      line.setAttribute("x2", "584");
      line.setAttribute("y1", String(y));
      line.setAttribute("y2", String(y));
      line.setAttribute("class", flow.severity === "high" ? "flow-line high" : "flow-line");
      svg.append(line);
      [[130, flow.source_ip, "source"], [626, flow.destination_ip, "destination"]].forEach(([x, ip, role]) => {
        const circle = document.createElementNS(svgNamespace, "circle");
        circle.setAttribute("cx", String(x));
        circle.setAttribute("cy", String(y));
        circle.setAttribute("r", "5");
        circle.setAttribute("class", `flow-node ${role}`);
        svg.append(circle);
        const label = document.createElementNS(svgNamespace, "text");
        label.setAttribute("x", String(role === "source" ? 10 : 646));
        label.setAttribute("y", String(y + 4));
        label.setAttribute("class", "flow-label");
        label.textContent = String(ip || "unknown");
        svg.append(label);
      });
      const detail = document.createElementNS(svgNamespace, "text");
      detail.setAttribute("x", "380");
      detail.setAttribute("y", String(y - 5));
      detail.setAttribute("text-anchor", "middle");
      detail.setAttribute("class", "flow-detail");
      detail.textContent = `${flow.protocol.toUpperCase()} :${flow.destination_port} · ${flow.packets} packets · ${flow.bytes.toLocaleString()} bytes`;
      svg.append(detail);
    });
    container.append(svg);
    if (flows.length > flowRows.length) {
      addText(container, "p", `Showing ${flowRows.length} of ${flows.length} largest flows.`, "hint");
    }
  };

  document.querySelectorAll(".capture-network-visual").forEach((visual) => {
    const capture = captures.find((item) => String(item.id) === visual.dataset.captureId);
    drawFlowGraph(visual, capture?.summary?.flows || []);
  });

  const hashIndicators = evidence.map((item) => ({
    name: item.original_name,
    indicator: item.sha256,
    indicator_type: "sha256",
    displayType: "SHA-256"
  }));
  const captureHashIndicators = captures.map((item) => ({
    name: item.original_name,
    indicator: item.sha256,
    indicator_type: "sha256",
    displayType: "SHA-256"
  }));
  const ipIndicators = events.flatMap((event) => [event.source_ip, event.destination_ip])
    .filter(Boolean)
    .map((indicator) => ({ name: "Observed network IP", indicator, indicator_type: "ip", displayType: "IP address" }));
  const imageIndicators = [...document.querySelectorAll(".custody-register tbody tr")]
    .filter((row) => row.cells[0]?.textContent.trim().startsWith("IMG-"))
    .map((row) => ({
      name: row.cells[1]?.textContent.trim() || "Disk image",
      indicator: row.cells[2]?.textContent.trim() || "",
      indicator_type: "sha256",
      displayType: "SHA-256"
    }));
  const indicatorList = document.getElementById("indicator-list");
  if (indicatorList) {
    indicatorList.replaceChildren();
    const indicators = [...new Map([...hashIndicators, ...captureHashIndicators, ...imageIndicators, ...ipIndicators]
      .filter((item) => item.indicator)
      .map((item) => [item.indicator, item])).values()];
    if (!indicators.length) addText(indicatorList, "p", "No IP addresses or file hashes are available for lookup.", "empty-inline");
    indicators.forEach((indicator) => {
      const row = document.createElement("div");
      row.className = "indicator-row";
      const text = document.createElement("div");
      addText(text, "small", indicator.displayType);
      addText(text, "b", indicator.name);
      addText(text, "code", indicator.indicator);
      const action = document.createElement("button");
      action.type = "button";
      action.className = "button secondary lookup-link";
      action.textContent = "Check VirusTotal";
      const result = document.createElement("div");
      result.className = "indicator-result";
      result.setAttribute("aria-live", "polite");
      action.addEventListener("click", async () => {
        action.disabled = true;
        result.textContent = "Querying VirusTotal…";
        try {
          const lookup = await requestJson(`${baseUrl}/indicators`, {
            method: "POST",
            body: JSON.stringify({ indicator: indicator.indicator, indicator_type: indicator.indicator_type })
          });
          result.replaceChildren();
          addText(result, "b", `${lookup.verdict} · ${lookup.cached ? "cached" : "retrieved"} ${lookup.retrieved_at}`);
          const stats = lookup.attributes?.last_analysis_stats;
          if (stats) addText(result, "small", `Malicious: ${stats.malicious || 0} · Suspicious: ${stats.suspicious || 0} · Harmless: ${stats.harmless || 0} · Undetected: ${stats.undetected || 0}`);
          const source = document.createElement("a");
          source.href = lookup.source_url;
          source.target = "_blank";
          source.rel = "noopener noreferrer";
          source.textContent = "Open provider report ↗";
          result.append(source);
        } catch (error) {
          result.textContent = error.message;
        } finally {
          action.disabled = false;
        }
      });
      row.append(text, action, result);
      indicatorList.append(row);
    });
  }

  const fromInput = document.getElementById("filter-from");
  const toInput = document.getElementById("filter-to");
  const severityInput = document.getElementById("filter-severity");
  const sourceInput = document.getElementById("filter-source");
  const typeInput = document.getElementById("filter-type");
  const findingSearch = document.querySelector('[data-table-search=".timeline-row"]');
  const findingSearchStatus = document.getElementById("case-search-status");
  const countElement = document.getElementById("timeline-count");
  if (typeInput) {
    [...new Set(events.map((event) => event.event_type || "unknown"))].sort().forEach((type) => {
      const option = document.createElement("option");
      option.value = type;
      option.textContent = type;
      typeInput.append(option);
    });
  }
  const filteredEvents = () => events.filter((event) => {
    const timestamp = (event.timestamp || "").slice(0, 10);
    if (fromInput?.value && (!timestamp || timestamp < fromInput.value)) return false;
    if (toInput?.value && (!timestamp || timestamp > toInput.value)) return false;
    if (severityInput?.value && (event.severity || "info").toLowerCase() !== severityInput.value) return false;
    const sourceValue = `${event.source_ip || ""} ${event.destination_ip || ""}`.toLowerCase();
    if (sourceInput?.value && !sourceValue.includes(sourceInput.value.toLowerCase())) return false;
    if (typeInput?.value && (event.event_type || "unknown") !== typeInput.value) return false;
    if (findingSearch?.value) {
      const searchable = [
        event.record_key, event.timestamp, event.severity, event.event_type,
        event.summary, event.source_ip, event.destination_ip, event.evidence_name
      ].join(" ").toLocaleLowerCase();
      if (!searchable.includes(findingSearch.value.trim().toLocaleLowerCase())) return false;
    }
    return true;
  });
  const refreshTimeline = () => {
    const selectedEvents = filteredEvents();
    rows.forEach((row, index) => {
      row.hidden = !selectedEvents.includes(events[index]);
    });
    if (countElement) countElement.textContent = `Showing ${selectedEvents.length} of ${events.length} records`;
    if (findingSearchStatus) {
      const query = findingSearch?.value.trim();
      findingSearchStatus.textContent = query
        ? `${selectedEvents.length} matching record${selectedEvents.length === 1 ? "" : "s"}.`
        : "";
    }
    return selectedEvents;
  };
  [fromInput, toInput, severityInput, sourceInput, typeInput, findingSearch].forEach((control) => {
    control?.addEventListener("input", refreshTimeline);
    control?.addEventListener("change", refreshTimeline);
  });

  const downloadCsv = (records, filename) => {
    const columns = [
      "record_key", "timestamp", "severity", "event_type", "summary",
      "source_ip", "destination_ip", "destination_port", "evidence_name", "details",
      "feedback_decision", "feedback_note"
    ];
    const escapeCell = (value) => {
      let text = String(value ?? "");
      if (/^[\t\r ]*[=+\-@]/.test(text)) text = `'${text}`;
      return `"${text.replaceAll('"', '""')}"`;
    };
    const lines = [columns.map(escapeCell).join(",")];
    records.forEach((record) => lines.push(columns.map((column) => escapeCell(
      column === "details" ? JSON.stringify(parseDetails(record)) : record[column]
    )).join(",")));
    const blob = new Blob(["\uFEFF", lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    URL.revokeObjectURL(link.href);
  };
  document.getElementById("export-timeline")?.addEventListener("click", () => {
    downloadCsv(refreshTimeline(), `case-${caseData.caseId}-filtered-timeline.csv`);
  });
  refreshTimeline();

  const answerElement = document.getElementById("assistant-answer");
  const questionInput = document.getElementById("assistant-question");
  const formatReference = (reference) => {
    const event = events.find((record) =>
      reference === `EVT-${record.id}` && record.record_key?.startsWith("evt-")
      || reference === `NET-${record.id}` && record.record_key?.startsWith("net-")
    );
    if (event) return `${reference} · ${event.timestamp || "timestamp unavailable"} · ${event.summary}`;
    const file = evidence.find((item) => reference === `EV-${item.id}`);
    if (file) return `${reference} · ${file.original_name}`;
    const image = diskImages.find((item) => reference === `IMG-${item.id}`);
    if (image) return `${reference} · ${image.original_name} · ${image.analysis_status}`;
    const capture = captures.find((item) => reference === `PCAP-${item.id}`);
    if (capture) return `${reference} · ${capture.original_name} · ${capture.packet_count} packets`;
    const note = notes.find((item) => reference === `NOTE-${item.id}`);
    return note ? `${reference} · ${note.note}` : reference;
  };
  const answerQuestion = async (question) => {
    if (!answerElement) return;
    answerElement.replaceChildren();
    addText(answerElement, "span", "i", "assistant-mark");
    const body = document.createElement("div");
    addText(body, "p", "Reviewing case records with the configured assistant…");
    answerElement.append(body);
    document.querySelectorAll("[data-question]").forEach((button) => { button.disabled = true; });
    const submit = document.querySelector("#assistant-form button[type='submit']");
    if (submit) submit.disabled = true;
    try {
      const result = await requestJson(`${baseUrl}/assistant`, {
        method: "POST",
        body: JSON.stringify({ question })
      });
      body.replaceChildren();
      addText(body, "p", result.answer || "The assistant returned no explanation.");
      if (result.citations?.length) {
        addText(body, "b", "Cited case records");
        const list = document.createElement("ul");
        result.citations.forEach((reference) => {
          const item = document.createElement("li");
          const link = document.createElement("a");
          const record = events.find((candidate) => reference === `EVT-${candidate.id}` && candidate.record_key?.startsWith("evt-")
            || reference === `NET-${candidate.id}` && candidate.record_key?.startsWith("net-"));
          const file = evidence.find((candidate) => reference === `EV-${candidate.id}`);
          const image = diskImages.find((candidate) => reference === `IMG-${candidate.id}`);
          const capture = captures.find((candidate) => reference === `PCAP-${candidate.id}`);
          const note = notes.find((candidate) => reference === `NOTE-${candidate.id}`);
          link.href = record ? `#event-${record.record_key}`
            : file ? `#evidence-EV-${file.id}`
              : image ? `#image-${image.id}`
                : capture ? `#pcap-${capture.id}`
                  : note ? "#case-notes" : "#evidence";
          link.textContent = formatReference(reference);
          item.append(link);
          list.append(item);
        });
        body.append(list);
      }
      addText(body, "small", `OpenAI ${result.model} · Record-grounded explanation; not proof.`, "answer-disclaimer");
    } catch (error) {
      body.replaceChildren();
      addText(body, "p", error.message);
      addText(body, "small", "The assistant request did not complete; no answer has been fabricated.", "answer-disclaimer");
    } finally {
      document.querySelectorAll("[data-question]").forEach((button) => { button.disabled = false; });
      if (submit) submit.disabled = false;
    }
  };
  document.getElementById("assistant-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    const question = questionInput?.value.trim() || "";
    if (question) answerQuestion(question);
    else questionInput?.focus();
  });
  document.querySelectorAll("[data-question]").forEach((button) => {
    button.addEventListener("click", () => {
      const question = button.dataset.question || "";
      if (questionInput) questionInput.value = question;
      answerQuestion(question);
    });
  });

  let metadataTimer;
  const metadataFields = [...document.querySelectorAll("[data-case-field]")];
  const saveStatus = document.getElementById("case-save-status");
  const persistMetadata = async () => {
    const values = Object.fromEntries(metadataFields.map((field) => [field.dataset.caseField, field.value]));
    if (saveStatus) saveStatus.textContent = "Saving case details…";
    try {
      await requestJson(`${baseUrl}/metadata`, { method: "POST", body: JSON.stringify(values) });
      if (saveStatus) saveStatus.textContent = "Case details saved.";
    } catch (error) {
      if (saveStatus) saveStatus.textContent = `Case details were not saved: ${error.message}`;
    }
  };
  metadataFields.forEach((field) => {
    field.addEventListener(field.tagName === "SELECT" ? "change" : "input", () => {
      window.clearTimeout(metadataTimer);
      metadataTimer = window.setTimeout(persistMetadata, 450);
    });
    field.addEventListener("change", () => {
      window.clearTimeout(metadataTimer);
      persistMetadata();
    });
  });

  const notesList = document.getElementById("case-notes-list");
  document.getElementById("case-note-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = document.getElementById("case-note");
    const note = input.value.trim();
    if (!note) return;
    try {
      const result = await requestJson(`${baseUrl}/notes`, { method: "POST", body: JSON.stringify({ note }) });
      notesList.replaceChildren();
      result.notes.forEach((item) => {
        const card = document.createElement("article");
        addText(card, "p", item.note);
        addText(card, "small", `${item.created_at} · ${item.actor}`);
        notesList.append(card);
      });
      input.value = "";
    } catch (error) {
      input.setCustomValidity(error.message);
      input.reportValidity();
      input.setCustomValidity("");
    }
  });

  document.querySelectorAll(".transfer-form").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = form.querySelector("button");
      button.disabled = true;
      try {
        await requestJson(`${baseUrl}/custody/transfer`, {
          method: "POST",
          body: JSON.stringify({
            evidence_type: form.dataset.evidenceType,
            evidence_id: form.dataset.evidenceId,
            to_actor: form.elements.to_actor.value,
            details: form.elements.details.value
          })
        });
        const status = document.getElementById("transfer-status");
        if (status) status.textContent = "Transfer recorded in the custody history.";
        window.location.reload();
      } catch (error) {
        const status = document.getElementById("transfer-status");
        if (status) status.textContent = error.message;
      } finally {
        button.disabled = false;
      }
    });
  });

  const sectionLinks = [...document.querySelectorAll(".case-sidebar .side-link[href^='#']")];
  if ("IntersectionObserver" in window && sectionLinks.length) {
    const sections = sectionLinks.map((link) => document.querySelector(link.getAttribute("href"))).filter(Boolean);
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        sectionLinks.forEach((link) => link.classList.toggle("active", link.hash === `#${entry.target.id}`));
      });
    }, { rootMargin: "-20% 0px -65% 0px" });
    sections.forEach((section) => observer.observe(section));
  }
})();
