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

### Milestone 0 (done)

- Design review document + architecture/library/security/testing decisions.

### Milestone 1 (done)

- Added pure C verifier module (`ntag424_verifier.{c,h}`):
  - parse/extract `p` and `c` from URL or bare query string
  - recover UID/counter from `p` using K1 (AES-128-ECB decrypt)
  - verify CMAC from `c` using K2 (RFC 4493 AES-CMAC chain)
  - return structured `ntag424_verify_result` with UID and counter
  - NDEF URL extraction (`ntag424_extract_url_from_ndef`), all 36 NFC URI prefixes
  - convenience pipeline (`ntag424_verify_from_ndef`, `ntag424_verify_from_url`)
  - exposed testing helpers (`ntag424_cmac_compute`, `ntag424_sv2_and_ct`)
- 120 unit tests (all vectors, RFC 4493, NDEF parsing, error paths, null args)

### Milestone 2 (done)

- Added PC/SC + Type 4 / NDEF reader layer (`ntag424_reader.{c,h}`):
  - **Transport abstraction** (`ntag424_transport_t`): a small function-pointer
    struct that decouples APDU exchange from higher-level logic; the PC/SC
    backend and any mock/test backend both implement the same interface.
  - **`ntag424_parse_cc`**: pure parser for NFC Forum Type 4 Capability
    Container (V2.0, TLV scan, extracts NDEF file ID / max size).
  - **`ntag424_read_ndef`**: transport-agnostic full read flow —
    SELECT NDEF application → SELECT CC → READ CC → parse CC →
    SELECT NDEF file (ID from CC) → READ NLEN → READ NDEF content
    (chunked for content > 240 bytes).
  - **PC/SC backend** (`ntag424_pcsc_{open,select_reader,connect,
    get_transport,reader_name,close}`): thin wrapper over pcsc-lite that
    negotiates protocol (T=0/T=1) and fills the transport struct.
  - **`ntag424_testread`** (`ntag424_testread.c`): manual hardware test
    utility; prints reader name, NDEF length, and whether `p=`/`c=`
    parameters are present — without printing sensitive URL values.
- 53 unit tests using mock transport (no hardware required):
  - CC parsing: valid, too-short, null args, bad version, minor version
    accepted, terminator-only, extra TLV before NDEF TLV, truncated TLV
  - NDEF read: happy path, SW failures at each step, bad CC content,
    transport error, empty NDEF, buffer-too-small, chunked read (250 bytes)
  - End-to-end: reader output → `ntag424_extract_url_from_ndef` →
    `ntag424_extract_p_c` (all mock, no hardware)

### Milestone 3 (next)

- Add local config parser + SQLite replay protection.

### Milestone 4 (next)

- Wire verifier + reader + policy + replay into PAM as second factor after password.

### Milestone 5 (next)

- Documentation for setup, testing, and lockout recovery.

## Known blockers / uncertainty

- Current upstream tree is not fully green in this environment before NTAG changes (pre-existing compile failures in unrelated legacy files).
- Milestone 1 therefore includes standalone verifier tests; full tree green-up may require a dedicated baseline-fix pass before later milestones.
