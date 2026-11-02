from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

from app.collectors import aws, github


def test_native_github_protection_contract(monkeypatch) -> None:
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        value = (
            {"protected": True}
            if not command[-1].endswith("/protection")
            else {"required_pull_request_reviews": {"required_approving_review_count": 1}}
        )
        return SimpleNamespace(returncode=0, stdout=json.dumps(value).encode())

    monkeypatch.setattr("subprocess.run", run)
    result = github("jayekwere/controlledger", "main")
    assert result["observation"] is True and len(calls) == 2
    assert "bypass_not_evaluated" in result["test_scope"]
    with pytest.raises(ValueError):
        github("bad; command", "main")
    with pytest.raises(ValueError):
        github("jayekwere/controlledger", "--evil")


def test_native_github_unavailable_is_not_clean(monkeypatch) -> None:
    monkeypatch.setattr("subprocess.run", lambda *a, **k: SimpleNamespace(returncode=1, stdout=b""))
    with pytest.raises(ValueError):
        github("jayekwere/controlledger", "main")
    monkeypatch.setattr(
        "subprocess.run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=b'{"protected":false}'),
    )
    assert github("jayekwere/controlledger", "main")["observation"] is False


def test_aws_normalization_limits_scope(monkeypatch) -> None:
    class Client:
        def get_bucket_encryption(self, **kwargs):
            assert kwargs == {"Bucket": "synthetic-bucket"}
            return {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                }
            }

    monkeypatch.setitem(
        sys.modules,
        "boto3",
        SimpleNamespace(
            Session=lambda **kwargs: SimpleNamespace(client=lambda *args, **kw: Client())
        ),
    )
    result = aws("synthetic-bucket", "sandbox")
    assert result["observation"] is True and "existing_objects" in result["test_scope"]
    with pytest.raises(ValueError):
        aws("../bad", "sandbox")
