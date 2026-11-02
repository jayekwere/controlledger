# Security design decisions

- Keep state and replay receipts transactional; reject conflicting command keys.
- Derive tenant and roles exclusively from trusted identities.
- Compare independent reviewers by subject, including when one subject holds multiple roles.
- Preserve missing evidence, stale observations and unknown permissions as distinct outcomes.
- Scope exports and retain provenance instead of asserting external truth from a digest.
- Use private local files and exclusive writes for generated material.
- Keep cloud and third-party writes outside these demos.
- Pin CI actions by commit, limit workflow permissions to contents read and avoid persisted checkout credentials.
- Hash-lock Python dependencies and lock exact Node dependencies.

A forged, stale or future-dated observation could create misleading assurance. Preserve its operator-imported trust label and source hash, reject future evidence and keep stale/missing states distinct. An auditor must never use a control identifier from an expired grant or another tenant. Exceptions must not turn a failed control into a passing result.
