"use strict";

// Every string that comes from the input or the report is placed with textContent.
// Nothing here parses HTML: no innerHTML, no insertAdjacentHTML, no document.write, no eval.

(function () {
  const byId = (id) => document.getElementById(id);
  const EVIDENCE_ID = /^S[0-9]{1,3}$/;
  const CITATION = /\[(S[0-9]{1,3})\]/g;
  // Controls, format characters (bidi, zero-width), separators and other invisible code points.
  const INVISIBLE = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Cs}\p{Zl}\p{Zp}\u{034F}\u{115F}\u{1160}\u{17B4}\u{17B5}\u{180B}-\u{180F}\u{2800}\u{3164}\u{FFA0}]/gu;
  let samples = {};

  // The alert id is the one raw input string the page shows; make hidden characters visible.
  function visible(text) {
    return String(text).replace(INVISIBLE, (ch) => "\\u{" + ch.codePointAt(0).toString(16) + "}");
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function block(title) {
    const section = el("section", "block");
    section.append(el("h3", null, title));
    return section;
  }

  function list(items) {
    const ul = el("ul", "plain");
    for (const item of items) ul.append(el("li", null, item));
    return ul;
  }

  function setStatus(text) {
    byId("status").textContent = text;
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    const toggle = byId("theme-toggle");
    toggle.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
    toggle.textContent = theme === "dark" ? "Light theme" : "Dark theme";
  }

  function initialTheme() {
    let stored = null;
    try { stored = window.localStorage.getItem("sealed-theme"); } catch (error) { stored = null; }
    if (stored === "dark" || stored === "light") return stored;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function toggleTheme() {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    applyTheme(next);
    try { window.localStorage.setItem("sealed-theme", next); } catch (error) { /* private mode */ }
  }

  async function loadSamples() {
    const response = await fetch("/api/samples");
    if (response.ok) samples = await response.json();
  }

  function useSample(name) {
    if (!Object.prototype.hasOwnProperty.call(samples, name)) return;
    let text = samples[name];
    try { text = JSON.stringify(JSON.parse(text), null, 2); } catch (error) { /* show it as it is */ }
    byId("alert-json").value = text;
    explain();
  }

  async function explain() {
    setStatus("Explaining...");
    let data;
    try {
      const response = await fetch("/api/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: byId("alert-json").value,
      });
      if (!response.ok) {
        setStatus("The local server refused the request (HTTP " + response.status + ").");
        return;
      }
      data = await response.json();
    } catch (error) {
      setStatus("The local server did not answer.");
      return;
    }
    render(data);
    setStatus("");
  }

  function render(data) {
    const root = byId("results");
    root.replaceChildren();
    const report = data.report;
    if (report.input.status !== "ok") {
      const box = el("article", "result rejected");
      const head = el("header", "result-head");
      head.append(el("strong", null, "Input rejected"), el("span", "label", "nothing was explained"));
      const body = block("Problems");
      for (const issue of report.input.issues) {
        body.append(el("p", null, issue.where + ": " + issue.message + " [" + issue.code + "]"));
      }
      box.append(head, body);
      root.append(box);
      return;
    }
    if (report.results.length === 0) {
      root.append(el("p", "muted", "The input holds no alerts."));
      return;
    }
    const checks = new Map(data.seal_checks.map((check) => [check.index, check]));
    for (const result of report.results) root.append(renderResult(result, checks.get(result.index)));
  }

  function renderResult(r, check) {
    const card = el("article", "result");
    const head = el("header", "result-head");
    head.append(el("span", "label", "Alert " + (r.index + 1)));
    head.append(el("code", "alert-id", r.alert_id === null ? "(no valid id)" : visible(r.alert_id)));
    card.append(head);

    if (r.status === "rejected") {
      const body = block("Rejected");
      const ul = el("ul", "plain issues");
      for (const error of r.errors) ul.append(el("li", null, error.where + ": " + error.message + " [" + error.code + "]"));
      body.append(ul);
      card.append(body);
      return card;
    }
    if (r.status === "duplicate") {
      const body = block("Duplicate");
      body.append(el("p", null, "Identical to alert " + (r.duplicate_of + 1) + "; explained once."));
      card.append(body);
      return card;
    }

    const rec = r.recommendation;
    const action = block("Recommendation");
    const line = el("p", "action-line");
    line.append(el("span", "chip action-" + rec.action, rec.action.toUpperCase()));
    line.append(el("span", "mock", "mock recommendation, not executed"));
    action.append(line);
    const why = rec.rules.map((rule) => rule.id + "  " + rule.text + "  ->  " + rule.action);
    if (why.length === 0) why.push("no rule fired, so the default: " + rec.policy_action);
    if (rec.escalated_by_injection_evidence) {
      why.push("raised from " + rec.policy_action + " by injection evidence (one level at most, never to contain)");
    }
    const agreement = { true: "agrees", false: "differs", null: "not usable" }[String(r.input_action.agrees_with_policy)];
    why.push("the alert's own suggestion: " + r.input_action.value + " (" + agreement + ")");
    action.append(list(why));
    const summary = el("div", "summary");
    summary.append(action);
    card.append(summary);

    const uncertainty = block("Uncertainty");
    const level = el("div", "level");
    const meter = el("span", "meter");
    meter.setAttribute("aria-hidden", "true");
    const rank = ["low", "medium", "high"].indexOf(r.uncertainty.level);
    for (let i = 0; i < 3; i += 1) meter.append(el("span", i <= rank ? "on" : null));
    level.append(meter, el("span", "level-name", r.uncertainty.level.toUpperCase()));
    uncertainty.append(level);
    if (r.uncertainty.reasons.length) {
      uncertainty.append(list(r.uncertainty.reasons.map((x) => "+" + x.add + "  " + x.rule + "  " + x.text)));
    } else {
      uncertainty.append(el("p", "muted", "No reason to doubt the evidence."));
    }
    summary.append(uncertainty);

    const evidence = block("Observed signals");
    const ul = el("ul", "evidence");
    for (const item of r.observed_signals) {
      const li = el("li");
      if (EVIDENCE_ID.test(item.evidence_id)) li.id = "ev-" + r.index + "-" + item.evidence_id;
      li.tabIndex = -1;
      li.append(el("span", "eid mono", item.evidence_id));
      const text = item.signal + (item.count === null ? "" : " = " + item.count) + "  (" + item.meaning + ")";
      li.append(el("span", "mono", text));
      ul.append(li);
    }
    if (r.observed_signals.length === 0) ul.append(el("li", "muted", "none"));
    evidence.append(ul);
    card.append(evidence);

    const narrative = block("Narrative");
    narrative.classList.add("narrative");
    if (r.explanation.sentences.length === 0) narrative.append(el("p", "muted", "Nothing the evidence supports."));
    for (const sentence of r.explanation.sentences) narrative.append(citedSentence(sentence, r.index));
    if (r.explanation.dropped.length) {
      narrative.append(el("p", "muted", r.explanation.dropped.length + " sentence(s) dropped by the verifier."));
    }
    card.append(narrative);

    const seal = block("Model input");
    seal.append(el("code", "hash", "SHA-256 " + r.model_input.sha256));
    if (check) {
      const ok = check.identical;
      seal.append(el("p", ok ? "seal-ok" : "seal-bad", ok
        ? "Seal check: identical to the clean twin (this alert with every free-text field removed)."
        : "Seal check: differs from the clean twin. This would be a bug."));
    }
    const details = el("details");
    details.append(el("summary", null, r.model_input.bytes + " bytes: the fixed prompt plus this view"));
    details.append(el("pre", "mono", r.model_input.view));
    seal.append(details);
    card.append(seal);

    const quarantine = block("Quarantine: free text, never given to any model");
    const flagged = r.injection_evidence.flagged_fields;
    const failed = r.quarantine.filter((item) => item.detector_error).map((item) => item.field);
    if (failed.length) {
      quarantine.append(el("p", "seal-bad", "Detector error: " + r.injection_evidence.detector +
        " could not score " + failed.join(", ") + "; those fields count as not flagged."));
    }
    if (flagged.length || !failed.length) {
      quarantine.append(el("p", flagged.length ? "seal-bad" : "muted", flagged.length
        ? "Instruction-like text in " + flagged.join(", ") + "."
        : "No instruction-like text found (" + r.injection_evidence.detector + ")."));
    }
    if (r.quarantine.length === 0) quarantine.append(el("p", "muted", "No free text besides the id."));
    for (const item of r.quarantine) {
      const box = el("div", "quarantine-item");
      box.append(el("span", "field mono", item.field));
      if (item.flagged) box.append(el("span", "flag", "instruction-like"));
      box.append(el("pre", "quarantine", item.text + (item.truncated ? "  ... (" + item.chars + " characters in all)" : "")));
      quarantine.append(box);
    }
    if (r.quarantine_omitted) quarantine.append(el("p", "muted", r.quarantine_omitted + " more item(s) not shown."));
    card.append(quarantine);
    return card;
  }

  function citedSentence(sentence, index) {
    const p = el("p");
    let last = 0;
    for (const match of sentence.matchAll(CITATION)) {
      p.append(document.createTextNode(sentence.slice(last, match.index)));
      const link = el("a", "cite", match[1]);
      link.href = "#ev-" + index + "-" + match[1];
      link.addEventListener("click", (event) => {
        event.preventDefault();
        const target = byId("ev-" + index + "-" + match[1]);
        if (!target) return;
        target.classList.add("highlight");
        target.focus();
        window.setTimeout(() => target.classList.remove("highlight"), 1600);
      });
      p.append(link);
      last = match.index + match[0].length;
    }
    p.append(document.createTextNode(sentence.slice(last)));
    return p;
  }

  document.addEventListener("DOMContentLoaded", () => {
    applyTheme(initialTheme());
    byId("theme-toggle").addEventListener("click", toggleTheme);
    byId("explain").addEventListener("click", explain);
    byId("alert-json").addEventListener("keydown", (event) => {
      if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
        event.preventDefault();
        explain();
      }
    });
    for (const button of document.querySelectorAll("[data-sample]")) {
      button.addEventListener("click", () => useSample(button.getAttribute("data-sample")));
    }
    loadSamples().then(() => useSample("track_example"));
  });
}());
