# ControlLedger architecture

Each control defines one supported boolean safeguard and a freshness window. Evidence is immutable after ingestion and retains a hash of its imported source, a source reference, collection identity and observed time. The latest observed sample determines the displayed state; an accepted exception remains separate from that state. Auditor grants bind a subject to explicit controls and expire after at most seven days. Every download passes that scope check before returning evidence. Required approvals and cloud encryption are narrow observations rather than whole-system compliance conclusions.

## Domain sequence

Control owner --> Imported observation --> Freshness assessment --> Independent exception review --> Scoped auditor download

## Consistency and recovery

`app/domain.py` owns explicit schemas and domain transitions. `app/service.py` validates input and commits state, audit entry and idempotency receipt in one SQLite transaction with `BEGIN IMMEDIATE`. `app/api.py` authenticates server-owned identities, limits request bytes and exposes scoped operations. `app/cli.py` executes the committed scenario against the same service. `web/` validates the scenario contract and renders real API results without HTML interpolation.

A process crash before commit rolls back domain state and receipts. Local filesystem effects in the certificate authority are separate from SQLite and partial CA initialization fails closed. Container state is disposable. Persistence, backups, independent audit checkpoints and external identity lifecycle are deployment responsibilities.

## Explicit scope

No SOC 2 attestation, ISO 27001 certification or guarantee of sustained control operation. Samples do not establish continuous operation across an audit period. Framework references are illustrative mapping labels, not licensed framework text or an authoritative mapping. Imported observations and hashes are assertions by an authorized collector operator. The API does not independently authenticate upstream exports. Vanta exports are a supported provenance label only; there is no native Vanta account connector. GitHub branch rulesets and administrative bypass are outside the branch-protection collector scope. AWS collection observes a bucket default, not historical object encryption or key access.

The audit request workflow pins explicit controls and an observation period. Fulfillment must cover that exact scope using immutable evidence records. Independent acceptance binds the fulfillment digest. Sample coverage remains distinct from sustained operation. The latest evidence also provides a next-test due timestamp.
