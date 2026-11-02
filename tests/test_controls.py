from __future__ import annotations

from typing import Any

import pytest

from app.common import DEMO_IDENTITIES, DomainError, Identity, get
from app.domain import (
    Control,
    Download,
    Evidence,
    ExceptionRequest,
    Grant,
    Ref,
    assessment,
    dispatch,
    view,
)

NOW = "2026-11-01T12:00:00Z"
LATER = "2026-11-03T12:00:00Z"
OP = DEMO_IDENTITIES["demo-operator"]
REVIEW = DEMO_IDENTITIES["demo-reviewer"]


def seed() -> dict[str, Any]:
    state: dict[str, Any] = {}
    dispatch(
        state,
        OP,
        "create-control",
        Control(
            id="control",
            title="Review the source",
            owner="platform",
            mapping=["SOC2-CC8.1"],
            test="branch-review",
            max_age_hours=24,
        ),
        NOW,
    )
    return state


def test_missing_stale_failed_and_passing_are_distinct() -> None:
    state = seed()
    control = get(state, "control", "control")
    assert assessment(state, control, NOW)["status"] == "untested"
    for index, value in enumerate([None, False, True]):
        dispatch(
            state,
            OP,
            "collect-evidence",
            Evidence(
                id=f"evidence-{index}",
                control_id="control",
                source="synthetic-fixture",
                source_ref="fixture",
                source_sha256="a" * 64,
                observed_at=NOW,
                observation=value,
            ),
            NOW,
        )
        assert assessment(state, control, NOW)["status"] == ["missing", "failing", "passing"][index]
    assert assessment(state, control, LATER)["status"] == "stale"
    with pytest.raises(DomainError):
        dispatch(
            state,
            OP,
            "collect-evidence",
            Evidence(
                id="future",
                control_id="control",
                source="synthetic-fixture",
                source_ref="fixture",
                source_sha256="a" * 64,
                observed_at=LATER,
                observation=True,
            ),
            NOW,
        )


def test_exception_independence_expiry_and_auditor_scope() -> None:
    state = seed()
    dispatch(
        state,
        OP,
        "request-exception",
        ExceptionRequest(
            id="temporary",
            control_id="control",
            rationale="A bounded temporary operational exception.",
            compensation="An independent operator reviews each change.",
            duration_hours=1,
        ),
        NOW,
    )
    same = Identity(tenant="alder", subject=OP.subject, roles=["reviewer"])
    with pytest.raises(DomainError):
        dispatch(state, same, "approve-exception", Ref(id="temporary"), NOW)
    with pytest.raises(DomainError):
        dispatch(state, REVIEW, "approve-exception", Ref(id="temporary"), LATER)
    dispatch(state, REVIEW, "approve-exception", Ref(id="temporary"), NOW)
    assert assessment(state, get(state, "control", "control"), NOW)["active_exceptions"] == [
        "temporary"
    ]
    assert assessment(state, get(state, "control", "control"), LATER)["active_exceptions"] == []
    auditor = DEMO_IDENTITIES["demo-auditor"]
    assert view(state, auditor, NOW)["controls"] == []
    dispatch(
        state,
        REVIEW,
        "grant-auditor",
        Grant(subject=auditor.subject, controls=["control"], duration_hours=1),
        NOW,
    )
    assert len(view(state, auditor, NOW)["controls"]) == 1
    assert view(state, auditor, LATER)["controls"] == []
    with pytest.raises(DomainError):
        dispatch(state, auditor, "download-evidence", Download(control_id="control"), LATER)
    with pytest.raises(DomainError):
        dispatch(
            state,
            REVIEW,
            "grant-auditor",
            Grant(subject="casey", controls=["control", "control"], duration_hours=1),
            NOW,
        )
    with pytest.raises(DomainError):
        view(state, DEMO_IDENTITIES["demo-support"], NOW)


def test_audit_request_scope_period_and_independent_acceptance() -> None:
    from app.domain import AcceptRequest, AuditRequest, Fulfillment

    state = seed()
    dispatch(
        state,
        OP,
        "collect-evidence",
        Evidence(
            id="sample",
            control_id="control",
            source="synthetic-fixture",
            source_ref="fixture",
            source_sha256="a" * 64,
            observed_at=NOW,
            observation=True,
        ),
        NOW,
    )
    request = AuditRequest(
        id="request",
        controls=["control"],
        assigned_to=OP.subject,
        period_start="2026-10-30T00:00:00Z",
        period_end=NOW,
        due_at=LATER,
    )
    with pytest.raises(DomainError):
        dispatch(
            state,
            REVIEW,
            "create-audit-request",
            request.model_copy(update={"period_end": LATER}),
            NOW,
        )
    dispatch(state, REVIEW, "create-audit-request", request, NOW)
    with pytest.raises(DomainError):
        dispatch(
            state,
            OP,
            "fulfill-audit-request",
            Fulfillment(id="request", evidence_ids=["sample", "sample"]),
            NOW,
        )
    result = dispatch(
        state, OP, "fulfill-audit-request", Fulfillment(id="request", evidence_ids=["sample"]), NOW
    )
    same = Identity(tenant="alder", subject=OP.subject, roles=["reviewer"])
    approval = AcceptRequest(id="request", fulfillment_sha256=result["fulfillment"]["sha256"])
    with pytest.raises(DomainError):
        dispatch(state, same, "accept-audit-request", approval, NOW)
    with pytest.raises(DomainError):
        dispatch(
            state,
            REVIEW,
            "accept-audit-request",
            approval.model_copy(update={"fulfillment_sha256": "a" * 64}),
            NOW,
        )
    assert dispatch(state, REVIEW, "accept-audit-request", approval, NOW)["status"] == "accepted"


def test_unrelated_extra_role_cannot_expand_auditor_scope() -> None:
    state = seed()
    mixed = Identity(tenant="alder", subject="casey", roles=["auditor", "support"])
    assert view(state, mixed, NOW)["controls"] == []
    dispatch(
        state,
        REVIEW,
        "grant-auditor",
        Grant(subject="casey", controls=["control"], duration_hours=1),
        NOW,
    )
    assert len(view(state, mixed, NOW)["controls"]) == 1
    assert view(state, mixed, LATER)["controls"] == []
