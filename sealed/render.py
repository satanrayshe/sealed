"""Readable text for a report from explain(). Free text is only ever printed escaped."""

from __future__ import annotations

from .quarantine import DISPLAY_CHARS, escape

PAD = " " * 15


def _show_id(alert_id: str | None) -> str:
    if alert_id is None:
        return "(no valid id)"
    shown, truncated = escape(alert_id, 60)
    return shown + (" ..." if truncated else "")


def _rows(label: str, values: list[str]) -> list[str]:
    return [f"  {label if i == 0 else '':<12} {value}" for i, value in enumerate(values)]


def _explained(r: dict) -> list[str]:
    out = []
    severity = r["severity"]
    out += _rows("severity", [severity["value"] + ("" if severity["known"] else "  (not a declared severity)")])

    signals = [f"{s['evidence_id']:<4}{s['signal']}" + (f" = {s['count']}" if s["count"] is not None else "")
               for s in r["observed_signals"]]
    signals = [f"{text:<34} {s['meaning']}" for text, s in zip(signals, r["observed_signals"])] or ["none"]
    if r["unrecognised_signals"]:
        signals.append(f"({', '.join(r['unrecognised_signals'])}: text held in quarantine)")
    out += _rows("signals", signals)

    rec = r["recommendation"]
    lines = [f"{rec['action'].upper()}  (mock recommendation, not executed)"]
    lines += [f"{rule['id']} {rule['text']} -> {rule['action']}" for rule in rec["rules"]]
    if not rec["rules"]:
        lines.append(f"no rule fired, so the default: {rec['policy_action']}")
    if rec["escalated_by_injection_evidence"]:
        lines.append(f"raised from {rec['policy_action']} by injection evidence (one level at most, never to contain)")
    agreement = {True: "agrees", False: "differs", None: "not usable"}[r["input_action"]["agrees_with_policy"]]
    lines.append(f"the alert's own suggestion: {r['input_action']['value']} ({agreement})")
    out += _rows("action", lines)

    uncertainty = r["uncertainty"]
    out += _rows("uncertainty", [uncertainty["level"].upper()]
                 + [f"+{x['add']} {x['rule']} {x['text']}" for x in uncertainty["reasons"]])

    explanation = r["explanation"]
    narrative = list(explanation["sentences"]) or ["(nothing the view supports; no sentence shown)"]
    if explanation["dropped"]:
        narrative.append(f"({len(explanation['dropped'])} sentence(s) dropped by the verifier: "
                         + ", ".join(d["reason"] for d in explanation["dropped"]) + ")")
    if explanation["fallback"]:
        narrative.append(f"(template used instead: {explanation['fallback']})")
    out += _rows("narrative", narrative)

    model_input = r["model_input"]
    out += _rows("model input", [f"SHA-256 {model_input['sha256']}",
                                 f"{model_input['bytes']} bytes: fixed prompt + {model_input['view']}"])

    evidence = r["injection_evidence"]
    if evidence["flagged_fields"]:
        out += _rows("injection", [f"instruction-like text in {', '.join(evidence['flagged_fields'])} "
                                   f"(score {evidence['max_score']:.2f} >= {evidence['threshold']:.2f}, {evidence['detector']})"])
    else:
        out += _rows("injection", [f"none found ({evidence['detector']}, threshold {evidence['threshold']:.2f})"])

    if not r["quarantine"]:
        out += _rows("quarantine", ["none (no free text besides the id, which is shown escaped above)"])
        return out
    out += _rows("quarantine", ["free text, shown escaped, never given to any model:"])
    for q in r["quarantine"]:
        more = f" ... (+{q['chars'] - DISPLAY_CHARS} more chars)" if q["truncated"] else ""
        flag = "   <- instruction-like" if q["flagged"] else ""
        out.append(f"{PAD}| {q['field']:<36} {q['text']}{more}{flag}")
    return out


def render(report: dict) -> str:
    lines = [f"Sealed {report['tool']['version']} | policy {report['policy']['version']} | "
             f"narrator {report['narrator']} | detector {report['detector']}"]
    source = report["input"]
    if source["status"] == "rejected":
        lines.append("Input REJECTED, nothing explained:")
        lines += [f"  {i['where']}: {i['message']} [{i['code']}]" for i in source["issues"]]
        return "\n".join(lines) + "\n"
    note = f", {source['ignored_top_level_fields']} unknown top-level field(s) ignored" if source["ignored_top_level_fields"] else ""
    lines.append(f"Input: {source['alerts']} alert(s){note}")
    for r in report["results"]:
        lines.append("")
        head = f"[{r['index'] + 1}/{source['alerts']}] alert {_show_id(r['alert_id'])}"
        if r["status"] == "rejected":
            lines.append(head + "  REJECTED")
            lines += [f"  {e['where']}: {e['message']} [{e['code']}]" for e in r["errors"]]
        elif r["status"] == "duplicate":
            lines.append(head + f"  DUPLICATE of [{r['duplicate_of'] + 1}]: identical content, explained once")
        else:
            lines.append(head)
            lines += _explained(r)
    lines += ["", "Executed controls: none. Every action above is a mock recommendation."]
    return "\n".join(lines) + "\n"
