from __future__ import annotations

from datetime import timedelta
from typing import Any, Literal

from pydantic import Field

from app.common import (
    Contract,
    DomainError,
    Identity,
    Ref,
    digest,
    fresh,
    get,
    independent,
    put,
    require,
    stamp,
)


class Control(Ref):
    title: str = Field(min_length=5, max_length=160)
    owner: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    mapping: list[str] = Field(min_length=1, max_length=8)
    test: Literal["branch-review", "storage-encryption", "workforce-mfa"]
    max_age_hours: int = Field(ge=1, le=2160)


class Evidence(Ref):
    control_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    source: Literal["synthetic-fixture", "github-export", "aws-export", "vanta-export"]
    source_ref: str = Field(min_length=1, max_length=240)
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    observed_at: str = Field(min_length=20, max_length=40)
    observation: bool | None


class ExceptionRequest(Ref):
    control_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    rationale: str = Field(min_length=20, max_length=500)
    compensation: str = Field(min_length=20, max_length=500)
    duration_hours: int = Field(ge=1, le=720)


class Grant(Contract):
    subject: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    controls: list[str] = Field(min_length=1, max_length=50)
    duration_hours: int = Field(ge=1, le=168)


class Download(Contract):
    control_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")


class AuditRequest(Ref):
    controls: list[str] = Field(min_length=1, max_length=30)
    assigned_to: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    period_start: str = Field(min_length=20, max_length=40)
    period_end: str = Field(min_length=20, max_length=40)
    due_at: str = Field(min_length=20, max_length=40)


class Fulfillment(Ref):
    evidence_ids: list[str] = Field(min_length=1, max_length=100)


class AcceptRequest(Ref):
    fulfillment_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


MODELS: dict[str, type[Contract]] = {
    "create-control": Control,
    "collect-evidence": Evidence,
    "request-exception": ExceptionRequest,
    "approve-exception": Ref,
    "grant-auditor": Grant,
    "download-evidence": Download,
}

MODELS.update(
    {
        "create-audit-request": AuditRequest,
        "fulfill-audit-request": Fulfillment,
        "accept-audit-request": AcceptRequest,
    }
)


def assessment(state: dict[str, Any], control: dict[str, Any], now: str) -> dict[str, Any]:
    records = [v for v in state.get("evidence", {}).values() if v["control_id"] == control["id"]]
    records.sort(key=lambda e: (stamp(e["observed_at"]), e["sequence"]))
    latest = records[-1] if records else None
    status = "untested"
    if latest:
        status = (
            "stale"
            if not fresh(latest["observed_at"], now, control["max_age_hours"])
            else "missing"
            if latest["observation"] is None
            else "passing"
            if latest["observation"]
            else "failing"
        )
    active = [
        e["id"]
        for e in state.get("exception", {}).values()
        if e["control_id"] == control["id"]
        and e["status"] == "approved"
        and stamp(e["expires_at"]) > stamp(now)
        and e["control_digest"] == digest(control)
    ]
    return {
        "id": control["id"],
        "title": control["title"],
        "owner": control["owner"],
        "mapping": control["mapping"],
        "status": status,
        "latest_evidence": latest["id"] if latest else None,
        "sample_count": len(records),
        "next_test_due_at": (
            stamp(latest["observed_at"]) + timedelta(hours=control["max_age_hours"])
        ).isoformat()
        if latest
        else "now",
        "observation_scope": "discrete_samples_only",
        "active_exceptions": active,
    }


def dispatch(
    state: dict[str, Any], actor: Identity, action: str, value: Contract, now: str
) -> dict[str, Any]:
    data = value.model_dump()
    if action == "create-audit-request":
        require(actor, "reviewer")
        if not stamp(data["period_start"]) <= stamp(data["period_end"]) <= stamp(now) or stamp(
            data["due_at"]
        ) <= stamp(now):
            raise DomainError("Audit request period or due date invalid", 422)
        if len(set(data["controls"])) != len(data["controls"]):
            raise DomainError("Duplicate control scope", 422)
        for key in data["controls"]:
            get(state, "control", key)
        return put(
            state,
            "audit-request",
            data["id"],
            {**data, "requested_by": actor.subject, "status": "open", "fulfillment": None},
            create=True,
        )
    if action == "fulfill-audit-request":
        require(actor, "operator")
        request = get(state, "audit-request", data["id"])
        if (
            request["status"] != "open"
            or request["assigned_to"] != actor.subject
            or stamp(request["due_at"]) <= stamp(now)
        ):
            raise DomainError(
                "Audit request is closed, overdue or assigned to another subject", 403
            )
        evidence = [get(state, "evidence", key) for key in data["evidence_ids"]]
        if (
            len(set(data["evidence_ids"])) != len(evidence)
            or {item["control_id"] for item in evidence} != set(request["controls"])
            or any(
                not stamp(request["period_start"])
                <= stamp(item["observed_at"])
                <= stamp(request["period_end"])
                for item in evidence
            )
        ):
            raise DomainError(
                "Evidence does not exactly cover the request scope and observation period"
            )
        fulfillment = {
            "evidence_ids": data["evidence_ids"],
            "evidence_sha256": [item["sha256"] for item in evidence],
            "submitted_by": actor.subject,
            "submitted_at": now,
        }
        fulfillment["sha256"] = digest(fulfillment)
        request.update(status="submitted", fulfillment=fulfillment)
        return put(state, "audit-request", data["id"], request)
    if action == "accept-audit-request":
        request = get(state, "audit-request", data["id"])
        if request["status"] != "submitted":
            raise DomainError("A submitted audit request is required")
        independent(actor, request["fulfillment"]["submitted_by"])
        if request["fulfillment"]["sha256"] != data["fulfillment_sha256"]:
            raise DomainError("Fulfillment evidence changed")
        request.update(status="accepted", accepted_by=actor.subject, accepted_at=now)
        return put(state, "audit-request", data["id"], request)
    if action == "create-control":
        require(actor, "operator")
        return put(state, "control", data["id"], {**data, "version": 1}, create=True)
    if action == "collect-evidence":
        require(actor, "operator")
        control = get(state, "control", data["control_id"])
        if not fresh(data["observed_at"], now, 24 * 365):
            raise DomainError("Evidence is future-dated or more than one year old", 422)
        record = {
            **data,
            "sequence": len(state.get("evidence", {})) + 1,
            "collected_at": now,
            "collected_by": actor.subject,
            "provenance": "operator_imported_export",
            "test": control["test"],
        }
        record["sha256"] = digest(record)
        put(state, "evidence", data["id"], record, create=True)
        return {"evidence": record, "assessment": assessment(state, control, now)}
    if action == "request-exception":
        require(actor, "operator")
        control = get(state, "control", data["control_id"])
        return put(
            state,
            "exception",
            data["id"],
            {
                **data,
                "requested_by": actor.subject,
                "requested_at": now,
                "expires_at": (stamp(now) + timedelta(hours=data["duration_hours"])).isoformat(),
                "control_digest": digest(control),
                "status": "pending",
            },
            create=True,
        )
    if action == "approve-exception":
        record = get(state, "exception", data["id"])
        independent(actor, record["requested_by"])
        if (
            record["status"] != "pending"
            or stamp(record["expires_at"]) <= stamp(now)
            or record["control_digest"] != digest(get(state, "control", record["control_id"]))
        ):
            raise DomainError("Exception is expired, changed or already decided")
        record.update(status="approved", approved_by=actor.subject, approved_at=now)
        return put(state, "exception", data["id"], record)
    if action == "grant-auditor":
        require(actor, "reviewer")
        if len(set(data["controls"])) != len(data["controls"]):
            raise DomainError("Duplicate control scope", 422)
        for control_id in data["controls"]:
            get(state, "control", control_id)
        return put(
            state,
            "grant",
            data["subject"],
            {
                **data,
                "expires_at": (stamp(now) + timedelta(hours=data["duration_hours"])).isoformat(),
            },
        )
    require(actor, "auditor")
    grant = get(state, "grant", actor.subject)
    if data["control_id"] not in grant["controls"] or stamp(grant["expires_at"]) <= stamp(now):
        raise DomainError("Evidence outside auditor scope", 403)
    control = get(state, "control", data["control_id"])
    return {
        "assessment": assessment(state, control, now),
        "evidence": [
            e for e in state.get("evidence", {}).values() if e["control_id"] == control["id"]
        ],
    }


def view(state: dict[str, Any], actor: Identity, now: str) -> dict[str, Any]:
    permitted = {"operator", "reviewer", "auditor"} & set(actor.roles)
    if not permitted:
        raise DomainError("Role not authorized", 403)
    controls = list(state.get("control", {}).values())
    if not set(actor.roles) & {"operator", "reviewer"}:
        grant = state.get("grant", {}).get(actor.subject)
        allowed = grant["controls"] if grant and stamp(grant["expires_at"]) > stamp(now) else []
        controls = [c for c in controls if c["id"] in allowed]
    results = [assessment(state, c, now) for c in controls]
    return {
        "controls": results,
        "audit_requests": [
            request
            for request in state.get("audit-request", {}).values()
            if "reviewer" in actor.roles or request["assigned_to"] == actor.subject
        ],
        "management": {
            "control_count": len(results),
            "requiring_attention": [c["id"] for c in results if c["status"] != "passing"],
            "claim": "observed_control_results_not_a_certification",
        },
    }
