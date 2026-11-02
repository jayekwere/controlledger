from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from app.common import canonical, clock


def github(repository: str, branch: str) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not re.fullmatch(
        r"[A-Za-z0-9_][A-Za-z0-9_.-]*", branch
    ):
        raise ValueError("Provide an explicit repository and simple branch name")
    base = f"repos/{repository}/branches/{branch}"

    def read(endpoint: str) -> dict[str, Any]:
        result = subprocess.run(
            ["gh", "api", "--hostname", "github.com", endpoint],
            capture_output=True,
            timeout=20,
            check=False,
            env={**os.environ, "GH_DEBUG": "", "GH_PAGER": "cat"},
        )
        if result.returncode or len(result.stdout) > 262144:
            raise ValueError("GitHub read unavailable; no passing observation produced")
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise ValueError("Unexpected native response")
        return value

    raw = {"branch": read(base)}
    observation: bool | None = None
    if raw["branch"].get("protected") is False:
        observation = False
    elif raw["branch"].get("protected") is True:
        raw["protection"] = read(base + "/protection")
        review = raw["protection"].get("required_pull_request_reviews")
        observation = (
            isinstance(review, dict)
            and type(review.get("required_approving_review_count")) is int
            and review["required_approving_review_count"] >= 1
        )
    return {
        "source": "github-export",
        "source_ref": f"github.com/{repository}/tree/{branch}",
        "observation": observation,
        "test_scope": "branch_protection_at_least_one_required_approval_rulesets_and_bypass_not_evaluated",
        "observed_at": clock(),
        "raw": raw,
    }


def aws(bucket: str, profile: str) -> dict[str, Any]:
    import boto3
    from botocore.config import Config

    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        raise ValueError("Explicit bucket name required")
    client = boto3.Session(profile_name=profile).client(
        "s3", config=Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 1})
    )
    raw = client.get_bucket_encryption(Bucket=bucket)
    raw.pop("ResponseMetadata", None)
    rules = raw.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
    algorithms = [
        rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") for rule in rules
    ]
    observation = bool(algorithms) and all(
        algorithm in {"AES256", "aws:kms", "aws:kms:dsse"} for algorithm in algorithms
    )
    return {
        "source": "aws-export",
        "source_ref": f"s3://{bucket}",
        "observation": observation,
        "test_scope": "default_bucket_encryption_only_existing_objects_and_key_permissions_not_evaluated",
        "observed_at": clock(),
        "raw": raw,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only native evidence collectors")
    parser.add_argument("provider", choices=["github", "aws"])
    parser.add_argument("--repository", default="")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--bucket", default="")
    parser.add_argument("--profile", default="cloud-admin")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = (
        github(args.repository, args.branch)
        if args.provider == "github"
        else aws(args.bucket, args.profile)
    )
    result["source_sha256"] = hashlib.sha256(canonical(result["raw"]).encode()).hexdigest()
    result["provenance"] = "native_read_by_local_collector_export_requires_operator_import"
    with os.fdopen(os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as file:
        json.dump(result, file, indent=2)
    print(
        json.dumps(
            {"collector": args.provider, "output_written": True, "test_scope": result["test_scope"]}
        )
    )


if __name__ == "__main__":
    main()
