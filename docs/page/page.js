"use strict";

// The public page. Python (Pyodide) runs the sealed package in this tab; this file only moves text in and out.
// Every string that comes from the input, a report, the presets or a recorded reply is placed with textContent.
// Nothing here parses HTML: no innerHTML, no insertAdjacentHTML, no document.write, no eval. The alert text
// reaches Python only as a function argument, never inside code.

(function () {
  const PYODIDE_INDEX = "https://cdn.jsdelivr.net/pyodide/v0.27.7/full/";
  const BUNDLE = "page/sealed.zip";
  const PRESETS = "page/presets.json";
  const REPLIES = "page/replies.json";
  const PACKAGE_DIR = "/sealed-page";
  const ARMS = ["raw-prompt", "hardened"];
  const ARM_NAMES = { "raw-prompt": "Raw prompt", hardened: "Hardened prompt" };
  const SAMPLES = ["track_example", "attacked_username", "edge_cases"];
  const DECISIONS = ["allow", "monitor", "step-up", "contain"];
  const LOCAL_COMMAND = "python tools/ask_baselines.py alert.json --model qwen3-1.7b:bf16";
  const EVIDENCE_ID = /^S[0-9]{1,3}$/;
  const CITATION = /\[(S[0-9]{1,3})\]/g;
  const HEX64 = /^[0-9a-f]{64}$/;
  // Controls, format characters (bidi, zero-width), separators and other invisible code points.
  const INVISIBLE = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Cs}\p{Zl}\p{Zp}\u{034F}\u{115F}\u{1160}\u{17B4}\u{17B5}\u{180B}-\u{180F}\u{2800}\u{3164}\u{FFA0}]/gu;

  const byId = (id) => document.getElementById(id);
  const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
  let pageModule = null;
  let samples = {};
  let presets = [];
  let replies = null;
  let repliesNote = "";
  let timer = null;
  let runs = 0;

  // ---- small DOM helpers ------------------------------------------------------------------------------------

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

  function setStatus(text) { byId("status").textContent = text; }

  // JSON text of a value from the editor, or null when it is nested too deeply for the browser to write out.
  function compact(value, indent) {
    try { return JSON.stringify(value, null, indent); } catch (error) { return null; }
  }

  function setLoad(text, failed) {
    const node = byId("load-status");
    node.textContent = text;
    node.classList.toggle("load-failed", Boolean(failed));
    node.hidden = !text;
  }

  // ---- theme -------------------------------------------------------------------------------------------------

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

  // ---- the editor: fields and JSON stay in step; the JSON text is what both panes read --------------------------

  function parseDocument(text) {
    let doc;
    try { doc = JSON.parse(text); } catch (error) { return { doc: null, why: "The JSON does not parse." }; }
    if (doc === null || typeof doc !== "object" || Array.isArray(doc) || !Array.isArray(doc.alerts)) {
      return { doc: null, why: "The document has no alerts list." };
    }
    const first = doc.alerts[0];
    if (first === null || typeof first !== "object" || Array.isArray(first)) {
      return { doc: null, why: "The first alert is not an object." };
    }
    return { doc: doc, why: "" };
  }

  function fieldInputs() {
    return Array.from(document.querySelectorAll("[data-field]"));
  }

  function fillFields(text) {
    const parsed = parseDocument(text);
    const notes = [];
    for (const input of fieldInputs()) {
      const name = input.getAttribute("data-field");
      input.disabled = parsed.doc === null;
      input.value = "";
      input.removeAttribute("aria-invalid");
      if (parsed.doc === null) continue;
      const alert = parsed.doc.alerts[0];
      if (!own(alert, name) || alert[name] === null) continue;
      const value = alert[name];
      if (name === "signals") {
        const ok = Array.isArray(value) && value.every((s) => typeof s === "string" && !/[\r\n]/.test(s));
        input.value = ok ? value.join("\n") : (compact(value) || "(too deeply nested to show here)");
        input.disabled = !ok;
        if (!ok) notes.push("signals is not a list of one-line strings; edit it in the JSON.");
      } else if (typeof value === "string") {
        input.value = value;
      } else {
        input.value = compact(value) || "(too deeply nested to show here)";
        input.disabled = true;
        notes.push(name + " is not a string; edit it in the JSON.");
      }
    }
    if (parsed.doc === null) notes.push(parsed.why + " The fields are off until it does; both panes show what the parser says.");
    else if (parsed.doc.alerts.length > 1) notes.push("The fields edit alert 1 of " + parsed.doc.alerts.length + ".");
    byId("fields-note").textContent = notes.join(" ");
    fitRows(byId("f-signals"));
  }

  function fitRows(textarea) {
    textarea.rows = Math.min(8, Math.max(2, textarea.value.split("\n").length));
  }

  function fieldsToJson(changed) {
    const parsed = parseDocument(byId("alert-json").value);
    if (parsed.doc === null) return;
    const alert = parsed.doc.alerts[0];
    const name = changed.getAttribute("data-field");
    if (name === "signals") {
      alert.signals = changed.value.split(/\r?\n/).filter((line) => line.length > 0);
    } else if (changed.value === "") {
      delete alert[name];
    } else {
      alert[name] = changed.value;
    }
    const text = compact(parsed.doc, 2);
    if (text === null) {  // the JSON stays as it was, so the fields go back to what it holds
      fillFields(byId("alert-json").value);
      byId("fields-note").textContent = "This document is nested too deeply to edit through the fields; edit it in the JSON.";
      return;
    }
    byId("alert-json").value = text;
  }

  function setDocument(text) {
    byId("alert-json").value = text;
    fillFields(text);
    explainSoon(0);
  }

  function pretty(text) {
    try { return JSON.stringify(JSON.parse(text), null, 2); } catch (error) { return text; }
  }

  // ---- explaining ----------------------------------------------------------------------------------------------

  function explainSoon(delay) {
    window.clearTimeout(timer);
    timer = window.setTimeout(explainNow, delay);
  }

  // Every run replaces both panes, so a hash on screen always belongs to the text in the editor.
  function explainNow() {
    if (!pageModule) return;
    try {
      const state = JSON.parse(pageModule.page_state(byId("alert-json").value, byId("detector").value));
      renderSealed(state);
      renderRaw(state);
      setStatus("");
    } catch (error) {
      renderFailure(error && typeof error.type === "string" ? error.type : "unknown");
    }
    runs += 1;
    document.body.setAttribute("data-runs", String(runs));
  }

  function renderFailure(kind) {
    const text = "Internal error in the page (" + kind + "). Nothing is shown for this document. " +
      "If it keeps happening, reload the page; the same check runs offline with python -m sealed explain alert.json";
    for (const id of ["sealed-results", "raw-results"]) {
      const root = byId(id);
      root.replaceChildren();
      const box = el("article", "result rejected");
      box.setAttribute("data-failed", "true");
      const head = el("header", "result-head");
      head.append(el("strong", null, "Not explained"), el("span", "label", "no hash for this document"));
      box.append(head, el("p", null, text));
      root.append(box);
    }
    setStatus("Internal error in the page (" + kind + ").");
  }

  // ---- Sealed pane (the local app's layout, with the seal check first) ---------------------------------------

  function renderSealed(state) {
    const root = byId("sealed-results");
    root.replaceChildren();
    const report = state.report;
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
    const checks = new Map(state.seal_checks.map((check) => [check.index, check]));
    for (const result of report.results) root.append(sealedCard(result, checks.get(result.index)));
  }

  function cardHead(index, alertId) {
    const head = el("header", "result-head");
    head.append(el("span", "label", "Alert " + (index + 1)));
    head.append(el("code", "alert-id", alertId === null || alertId === undefined ? "(no valid id)" : visible(alertId)));
    return head;
  }

  function sealBlock(r, check) {
    const seal = el("section", "block seal");
    seal.append(el("h3", null, "Model input"));
    const hash = el("code", "hash", "SHA-256 " + r.model_input.sha256);
    if (HEX64.test(r.model_input.sha256)) hash.setAttribute("data-sha256", r.model_input.sha256);
    seal.append(hash);
    if (check) {
      const line = el("p", check.identical ? "seal-ok seal-line" : "seal-bad seal-line", check.identical
        ? "Identical to the clean alert: the same alert without its username, user agent, URL, host and extra fields."
        : "Differs from the clean alert. This would be a bug.");
      line.setAttribute("data-identical", check.identical ? "true" : "false");
      seal.append(line);
    }
    const details = el("details");
    details.append(el("summary", null, r.model_input.bytes + " bytes: the fixed prompt plus this view"));
    details.append(el("pre", "mono", r.model_input.view));
    seal.append(details);
    return seal;
  }

  function sealedCard(r, check) {
    const card = el("article", "result");
    card.setAttribute("data-index", String(r.index));
    card.append(cardHead(r.index, r.alert_id));
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
    card.append(sealBlock(r, check));

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
    card.append(summary);

    const evidence = block("Observed signals");
    const ul = el("ul", "evidence");
    for (const item of r.observed_signals) {
      const li = el("li");
      if (EVIDENCE_ID.test(item.evidence_id)) li.id = "ev-" + r.index + "-" + item.evidence_id;
      li.tabIndex = -1;
      li.append(el("span", "eid mono", item.evidence_id));
      li.append(el("span", "mono", item.signal + (item.count === null ? "" : " = " + item.count) + "  (" + item.meaning + ")"));
      ul.append(li);
    }
    if (r.observed_signals.length === 0) ul.append(el("li", "muted", "none"));
    evidence.append(ul);
    card.append(evidence);

    const narrative = block("Narrative (template narrator)");
    narrative.classList.add("narrative");
    if (r.explanation.sentences.length === 0) narrative.append(el("p", "muted", "Nothing the evidence supports."));
    for (const sentence of r.explanation.sentences) narrative.append(citedSentence(sentence, r.index));
    if (r.explanation.dropped.length) {
      narrative.append(el("p", "muted", r.explanation.dropped.length + " sentence(s) dropped by the verifier."));
    }
    card.append(narrative);

    const quarantine = block("Quarantine: free text, never given to any model");
    const flagged = r.injection_evidence.flagged_fields;
    const failed = r.quarantine.filter((item) => item.detector_error).map((item) => item.field);
    if (failed.length) {
      quarantine.append(el("p", "seal-bad", "Detector error: " + r.injection_evidence.detector +
        " could not score " + failed.join(", ") + "; those fields count as not flagged."));
    }
    if (flagged.length || !failed.length) {
      quarantine.append(el("p", flagged.length ? "seal-bad" : "muted", flagged.length
        ? "Instruction-like text in " + flagged.join(", ") + " (" + r.injection_evidence.detector + ")."
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

  // ---- raw-prompt pane -----------------------------------------------------------------------------------------

  function renderRaw(state) {
    const root = byId("raw-results");
    root.replaceChildren();
    const report = state.report;
    if (report.input.status !== "ok") {
      root.append(el("p", "muted", "The parser rejected this document, so there is no alert to put into a prompt."));
      return;
    }
    if (state.prompts.length === 0) {
      root.append(el("p", "muted", "No alert object to put into a prompt."));
      return;
    }
    const ids = new Map(report.results.map((r) => [r.index, r.alert_id]));
    for (const entry of state.prompts) root.append(rawCard(entry, ids.get(entry.index)));
    if (report.input.alerts > state.alerts_with_prompts) {
      root.append(el("p", "muted", "Prompts are shown for the first " + state.alerts_with_prompts + " alerts."));
    }
  }

  function rawCard(entry, alertId) {
    const card = el("article", "result");
    card.setAttribute("data-index", String(entry.index));
    card.append(cardHead(entry.index, alertId));
    const reads = block("What its model reads");
    for (const arm of ARMS) {
      const prompt = entry.arms[arm];
      const row = el("div", "prompt-row");
      row.append(el("span", "arm-name", ARM_NAMES[arm]));
      const hash = el("code", "hash", "prompt SHA-256 " + prompt.sha256);
      if (HEX64.test(prompt.sha256)) hash.setAttribute("data-prompt-sha256", prompt.sha256);
      row.append(hash);
      const same = prompt.sha256 === entry.clean_sha256[arm];
      row.append(el("p", same ? "muted" : "seal-bad", same
        ? "Same prompt as for the clean alert."
        : "Differs from the clean alert's prompt: the attacker's text is in it."));
      const details = el("details");
      details.append(el("summary", null, "Show the prompt (" + prompt.chars + " characters)"));
      details.append(el("pre", "mono prompt", prompt.text + (prompt.truncated ? "\n... (shortened here; the hash covers all of it)" : "")));
      row.append(details);
      reads.append(row);
    }
    card.append(reads);
    card.append(recordedBlock(entry));
    return card;
  }

  function matchingPreset(entry) {
    return presets.find((p) => ARMS.some((arm) => p.prompt_sha256[arm] === entry.arms[arm].sha256)) || null;
  }

  function liveModelNote(section) {
    section.append(el("p", null, "This page has no model, so a raw-prompt reply to text you typed cannot be shown. " +
      "To ask the raw-prompt and hardened arms about this exact alert, save the JSON document as alert.json in a " +
      "checkout of the repository, start a local model server on 127.0.0.1:11434 (tools/local_model_server.py, or " +
      "Ollama), and run:"));
    section.append(el("pre", "mono command", LOCAL_COMMAND));
  }

  function recordedBlock(entry) {
    const section = block("Model replies");
    const preset = matchingPreset(entry);
    if (preset) {
      section.append(el("p", null, "This is recorded attack " + preset.id + ": evaluation triple " + preset.triple + ", a " +
        preset.class + " string (" + preset.encoding + ", " + preset.language + ", " + preset.split + " split) in " +
        preset.field + "."));
    }
    if (!replies) {
      section.append(el("p", "muted", repliesNote));
      liveModelNote(section);
      return section;
    }
    if (!preset || !own(replies.presets, preset.id)) {
      section.append(el("p", "muted", "Recorded replies exist only for the recorded attacks above, loaded unchanged."));
      liveModelNote(section);
      return section;
    }
    const recorded = replies.presets[preset.id];
    section.append(el("p", "muted", "Recorded in the evaluation's model run (" + replies.source + "). The twin is the " +
      "same alert with \"x\" in the attacked field. A reply without a usable decision counts as a change."));
    for (const model of replies.models) {
      if (!own(recorded.replies, model)) continue;
      const box = el("div", "recorded-reply");
      box.append(el("h4", "model-name", model));
      const table = el("table", "decisions");
      const head = el("tr");
      for (const name of ["Arm", "Twin", "Attacked", ""]) head.append(el("th", null, name));
      table.append(head);
      for (const arm of ARMS) {
        if (preset.prompt_sha256[arm] !== entry.arms[arm].sha256 || !own(recorded.replies[model], arm)) continue;
        const pair = recorded.replies[model][arm];
        const twin = decision(pair.twin);
        const attacked = decision(pair.attacked);
        const changed = twin !== attacked || twin === "no decision" || attacked === "no decision";
        const tr = el("tr");
        tr.append(el("td", null, ARM_NAMES[arm]), el("td", "mono", twin), el("td", "mono", attacked),
          el("td", changed ? "seal-bad" : "muted", changed ? "changed" : "same"));
        table.append(tr);
      }
      box.append(table);
      for (const arm of ARMS) {
        if (preset.prompt_sha256[arm] !== entry.arms[arm].sha256 || !own(recorded.replies[model], arm)) continue;
        const details = el("details");
        details.append(el("summary", null, ARM_NAMES[arm] + ": the reply about the attacked alert"));
        details.append(el("pre", "quarantine", String(recorded.replies[model][arm].attacked.content)));
        box.append(details);
      }
      section.append(box);
    }
    return section;
  }

  function decision(reply) {
    return reply && DECISIONS.includes(reply.decision) ? reply.decision : "no decision";
  }

  // ---- presets and recorded replies ----------------------------------------------------------------------------

  function renderPresets(doc) {
    byId("preset-rule").textContent = typeof doc.rule === "string" ? doc.rule : "";
    const root = byId("preset-list");
    root.replaceChildren();
    for (const preset of presets) {
      const button = el("button", "preset");
      button.type = "button";
      button.append(el("span", "preset-id", preset.id + "  " + preset.class + " in " + preset.field));
      button.append(el("span", "preset-text", visible(preset.text)));
      button.addEventListener("click", () => setDocument(JSON.stringify({ alerts: [preset.alert] }, null, 2)));
      root.append(button);
    }
  }

  function validPresets(doc) {
    return doc && doc.schema === "sealed-page-presets/1" && Array.isArray(doc.presets) && doc.presets.every((p) =>
      p && typeof p.id === "string" && p.alert && typeof p.alert === "object" && p.prompt_sha256 &&
      ARMS.every((arm) => typeof p.prompt_sha256[arm] === "string"));
  }

  function validReplies(doc) {
    return doc && doc.schema === "sealed-page-replies/1" && doc.dry_run === false && Array.isArray(doc.models) &&
      doc.presets && typeof doc.presets === "object" && typeof doc.source === "string";
  }

  async function fetchJson(path) {
    const response = await fetch(path, { cache: "no-cache" });
    if (!response.ok) return null;
    try { return await response.json(); } catch (error) { return null; }
  }

  async function loadReplies() {
    const doc = await fetchJson(REPLIES).catch(() => null);
    if (doc && doc.dry_run !== false) {
      repliesNote = "The replies file on this site is a dry run made without a model, so it is not shown.";
    } else if (validReplies(doc)) {
      replies = doc;
    } else {
      repliesNote = "No recorded model replies are published on this page yet. They come from the evaluation's " +
        "model run, which has not finished; until then this pane shows no model reply.";
    }
  }

  // ---- start-up ------------------------------------------------------------------------------------------------

  async function start() {
    if (typeof window.loadPyodide !== "function") throw new Error("pyodide-missing");
    const pyodide = await window.loadPyodide({ indexURL: PYODIDE_INDEX });
    const response = await fetch(BUNDLE, { cache: "no-cache" });
    if (!response.ok) throw new Error("bundle-missing");
    pyodide.unpackArchive(await response.arrayBuffer(), "zip", { extractDir: PACKAGE_DIR });
    pyodide.pyimport("sys").path.insert(0, PACKAGE_DIR);
    pageModule = pyodide.pyimport("sealed.page");
    for (const name of SAMPLES) {
      samples[name] = pyodide.FS.readFile(PACKAGE_DIR + "/sealed/samples/" + name + ".json", { encoding: "utf8" });
    }
    const reason = pageModule.detector_status();
    const learned = byId("detector").querySelector("option[value=learned]");
    learned.disabled = Boolean(reason);
    byId("detector-note").textContent = reason ? "Learned detector unavailable here: " + reason : "";
    const presetDoc = await fetchJson(PRESETS).catch(() => null);
    if (validPresets(presetDoc)) {
      presets = presetDoc.presets;
      renderPresets(presetDoc);
    }
    await loadReplies();
  }

  function enable() {
    for (const node of document.querySelectorAll("[data-sample], #alert-json, #detector")) node.disabled = false;
  }

  document.addEventListener("DOMContentLoaded", () => {
    applyTheme(initialTheme());
    byId("theme-toggle").addEventListener("click", toggleTheme);
    for (const button of document.querySelectorAll("[data-sample]")) {
      button.addEventListener("click", () => {
        const name = button.getAttribute("data-sample");
        if (own(samples, name)) setDocument(pretty(samples[name]));
      });
    }
    for (const input of fieldInputs()) {
      input.addEventListener("input", () => {
        if (input.tagName === "TEXTAREA") fitRows(input);
        fieldsToJson(input);
        explainSoon(120);
      });
    }
    byId("alert-json").addEventListener("input", () => { fillFields(byId("alert-json").value); explainSoon(120); });
    byId("detector").addEventListener("change", () => explainSoon(0));
    setLoad("Loading Python into this tab (Pyodide, from cdn.jsdelivr.net). This takes a few seconds on the first visit.");
    start().then(() => {
      enable();
      setLoad("");
      setDocument(pretty(samples.track_example));
      document.body.setAttribute("data-state", "ready");
    }).catch((error) => {
      setLoad("Python could not be loaded into this tab (" + (error && error.message === "pyodide-missing"
        ? "the Pyodide script did not load" : "start-up failed") + "), so nothing can be explained here. " +
        "The same code runs offline from a checkout: python -m sealed app", true);
      document.body.setAttribute("data-state", "failed");
    });
  });
}());
