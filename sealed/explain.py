"""The pipeline: parse, decide, seal, narrate, verify, report.

Structured values flow towards the narrator; free text flows only to the
quarantine and the detector. The narrator's input is built by seal() from
facts alone, and the action and uncertainty come from the declared policy,
so a narrator can neither see attacker text nor change a decision.

explain() never raises on bad input; problems come back inside the report.
The output schema is documented in schema/output.schema.json and README.md.
"""

from __future__ import annotations

from . import __version__
from .contract import Alert, Duplicate, Rejected, parse_document
from .detect import Detector, KeywordDetector, scan
from .narrate import NarratorError, TemplateNarrator
from .policy import POLICY, Policy, decide
from .quarantine import escape
from .verify import verify
from .view import PROMPT_VERSION, seal
from .vocabulary import SIGNALS, UNRECOGNISED
from .vocabulary import VERSION as VOCABULARY_VERSION

OUTPUT_SCHEMA = "sealed-output/1"


def _narrate(narrator, view) -> tuple[list, str, str | None]:
    """Narration is optional: any narrator failure falls back to the template and is reported."""
    try:
        return narrator.narrate(view), narrator.name, None
    except NarratorError as err:
        reason = str(err)
    except Exception as err:  # a narrator must never be able to crash the explainer
        reason = f"unexpected {type(err).__name__}"
    return TemplateNarrator().narrate(view), TemplateNarrator.name, f"{narrator.name} failed: {reason}"


def _explain_alert(alert: Alert, narrator, detector: Detector, policy: Policy) -> dict:
    scores = scan(detector, alert.free_text, policy.threshold)
    flagged = [s for s in scores if s.flagged]
    decision = decide(
        alert.facts, unrecognised=alert.unrecognised, signals_missing=alert.signals_missing,
        severity=alert.severity, input_action=alert.input_action, injection_flagged=bool(flagged),
        id_conflict=alert.id_conflicts > 0,
        policy=policy,
    )
    view = seal(alert.facts, alert.unrecognised)
    sentences, narrator_used, fallback = _narrate(narrator, view)
    verified = verify(view, sentences)
    rules = {rule.id: rule for rule in policy.action_rules}

    quarantine = []
    for item, score in zip(alert.free_text, scores):
        shown, truncated = escape(item.text)
        quarantine.append({
            "field": item.field, "text": shown, "chars": len(item.text), "truncated": truncated,
            "score": round(score.score, 4), "flagged": score.flagged, "detector_error": score.error,
        })

    return {
        "index": alert.index,
        "alert_id": alert.id,
        "status": "explained",
        "severity": {"value": alert.severity, "known": alert.severity != "unknown"},
        "observed_signals": [
            {"evidence_id": e.id, "signal": e.signal, "count": e.count,
             "meaning": (UNRECOGNISED if e.signal == UNRECOGNISED.code else SIGNALS[e.signal]).meaning}
            for e in view.evidence
        ],
        "unrecognised_signals": [f"unrecognised signal {k}" for k in range(1, alert.unrecognised + 1)],
        "recommendation": {
            "action": decision.action,
            "mock": True,
            "executed": False,
            "policy_action": decision.policy_action,
            "escalated_by_injection_evidence": decision.escalated,
            "rules": [{"id": r, "action": rules[r].action, "text": rules[r].text} for r in decision.rules],
        },
        "input_action": {"value": alert.input_action, "agrees_with_policy": decision.input_action_agrees},
        "uncertainty": {
            "level": decision.uncertainty,
            "reasons": [{"rule": r.rule, "add": r.add, "text": r.text} for r in decision.reasons],
        },
        "explanation": {
            "narrator": narrator_used,
            "fallback": fallback,
            "sentences": list(verified.kept),
            "dropped": [{"position": p, "reason": r} for p, r in verified.dropped],
        },
        "model_input": {
            "sha256": view.sha256, "bytes": len(view.model_input),
            "prompt_version": PROMPT_VERSION, "view": view.canonical_json,
        },
        "injection_evidence": {
            "detector": detector.name,
            "threshold": policy.threshold,
            "flagged_fields": [s.field for s in flagged],
            "max_score": round(max((s.score for s in scores), default=0.0), 4),
        },
        "quarantine": quarantine,
        "quarantine_omitted": alert.quarantine_omitted,
        "executed_controls": [],
    }


def _rejected(item: Rejected) -> dict:
    return {"index": item.index, "alert_id": item.id, "status": "rejected",
            "errors": [issue.as_dict() for issue in item.issues], "executed_controls": []}


def _duplicate(item: Duplicate) -> dict:
    return {"index": item.index, "alert_id": item.id, "status": "duplicate",
            "duplicate_of": item.duplicate_of, "executed_controls": []}


def explain(data: bytes | str, *, narrator=None, detector: Detector | None = None,
            policy: Policy = POLICY) -> dict:
    """Explain every alert in a Track 4 input document."""
    narrator = narrator or TemplateNarrator()
    detector = detector or KeywordDetector()
    document = parse_document(data)
    results = []
    for item in document.items:
        if isinstance(item, Alert):
            results.append(_explain_alert(item, narrator, detector, policy))
        elif isinstance(item, Duplicate):
            results.append(_duplicate(item))
        else:
            results.append(_rejected(item))
    return {
        "schema": OUTPUT_SCHEMA,
        "tool": {"name": "sealed", "version": __version__},
        "policy": {"version": policy.version, "sha256": policy.sha256},
        "vocabulary": VOCABULARY_VERSION,
        "narrator": getattr(narrator, "name", "unknown"),
        "detector": detector.name,
        "input": {
            "status": "ok" if document.ok else "rejected",
            "issues": [issue.as_dict() for issue in document.issues],
            "alerts": len(document.items),
            "ignored_top_level_fields": document.ignored_fields,
        },
        "results": results,
        "executed_controls": [],
    }
