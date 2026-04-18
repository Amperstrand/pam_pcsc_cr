# NTAG424 DNA local PAM 2FA plan

## Scope and assumptions

- Target is **local PAM second factor** only (sudo, tty, display manager).
- Not for remote SSH/online-worker mode.
- Verifier secrets live on the local host.
- Work is split into small milestones to keep the tree testable and auditable.

## Current `pam_pcsc_cr` architecture review

### What should stay

- `pam_pcsc_cr.c` as the PAM entrypoint pattern (argument parsing, PAM user handling, fail-closed behavior).
- Existing project layout and autotools/test style.
- `pcsc_cr.c` concept of backend/token interface (reusable idea, not reusable implementation).
- Existing unit-test style with small C test executables.

### What should be replaced or bypassed

- `authobj/authfile` state model is tightly tied to YubiKey challenge/response and should not be reused for NTAG424 SUN verification.
- `ykneo.c` APDU flow is token-specific and not reusable for Type 4/NDEF reading.
- Current nonce-based anti-replay is specific to legacy flow and should be replaced by per-card monotonic counter checks.

### Abstraction decision

- Keep PAM code thin and separate from protocol logic.
- Add new modules with explicit boundaries:
  1. pure verifier (`p`/`c` parsing + crypto),
  2. reader/NDEF extraction,
  3. config/policy + replay store,
  4. PAM glue.

## Library choices

### Reader stack

- Keep direct `pcsc-lite` (`winscard.h`) in C for reader access.
- Do not introduce large NFC frameworks in PAM path for now.
- Rationale: lower dependency surface, easier deployment in PAM environments, direct APDU control for Type 4/NDEF flow.

### Crypto

- Reuse project crypto backends via `crypto.h` AES block primitive for Milestone 1.
- Implement AES-CMAC (RFC 4493) in verifier module using AES-128 block encryption.
- Later, if needed, migrate verifier internals to EVP/CMAC directly; Milestone 1 prioritizes minimal integration risk.

### Replay state

- Use **SQLite** (WAL + transactions) for replay state in Milestone 3.
- Rationale: robust locking/concurrency, crash safety, atomic monotonic updates, better than race-prone flat files.

## Data model and config direction

## User/card binding model

- Per-user allowlist of card identities and key references.
- Auth succeeds only if:
  1. `p/c` verifies cryptographically,
  2. recovered card identity matches policy for the PAM user,
  3. replay check passes.

### Keys

- Store verifier keys locally in root-readable config/state files.
- Prefer per-card key references in config; avoid implicit global trust across all users.
- Milestone 1 supports direct K1/K2 input for unit tests only.

### Config format

- Keep parser simple and auditable for PAM:
  - initial plan: INI-like key/value format (one global file + optional user map file),
  - strict parsing and fail-closed on malformed entries.
- Avoid JSON/YAML parser dependencies in PAM path.

### Replay state schema (planned)

- SQLite table keyed by stable card identifier (e.g., UID or configured card id), with:
  - `last_counter`,
  - `updated_at`.
- Update rule: accept only strictly increasing counters in a single transaction.

## Security model and logging

- This design is suitable only where verifier secrets are trusted on host.
- Local secrets required:
  - SDM decryption/verification keys (K1/K2 or equivalent derived verifier keys),
  - user/card policy mapping,
  - replay state database.
- Must never log by default:
  - full NDEF URL,
  - raw `p` and `c`,
  - key material,
  - full decrypted card payload.
- Log only minimal outcomes (success/failure reason category), with optional debug mode that is still redacted.
- Avoid global-card bypass: all auth decisions must include PAM user policy check.

## Test strategy

### Unit tests without hardware

- Pure verifier tests with fixed vectors for:
  - hex parsing,
  - URL `p/c` extraction,
  - UID/counter recovery from `p`,
  - CMAC verification pass/fail,
  - malformed inputs.
- Use known vectors from referenced JS tests and RFC 4493 CMAC vectors.

### Mocking and integration

- Reader layer behind interface; add mock reader returning synthetic NDEF URLs.
- Add small standalone reader harness before PAM wiring.
- For replay logic, use temp SQLite DB in tests to prove:
  - first use accepted,
  - increasing counters accepted,
  - equal/lower rejected,
  - concurrent updates remain monotonic.

## Milestone plan

### Milestone 0 (this change)

- Design review document + architecture/library/security/testing decisions.

### Milestone 1 (this change, started)

- Add pure C verifier module:
  - parse/extract `p` and `c`,
  - recover UID/counter from `p` using K1,
  - verify CMAC from `c` using K2,
  - return structured status/results.
- Add unit tests using deterministic fixtures, no PC/SC hardware required.

### Milestone 2 (next)

- Add PC/SC Type 4/NDEF reader module and standalone reader test tool.

### Milestone 3 (next)

- Add local config parser + SQLite replay protection.

### Milestone 4 (next)

- Wire verifier + reader + policy + replay into PAM as second factor after password.

### Milestone 5 (next)

- Documentation for setup, testing, and lockout recovery.

## Known blockers / uncertainty

- Current upstream tree is not fully green in this environment before NTAG changes (pre-existing compile failures in unrelated legacy files).
- Milestone 1 therefore includes standalone verifier tests; full tree green-up may require a dedicated baseline-fix pass before later milestones.
