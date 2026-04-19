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

### Milestone 3 (done)

- Added local config / policy layer (`ntag424_policy.{c,h}`):
  - **Config format**: small strict INI-like file; `[card:<id>]` sections with
    `uid`, `k1`, `k2`, `user` fields; unknown keys and malformed values cause
    immediate rejection (fail-closed).
  - **`ntag424_policy_load`**: strict line-by-line parser (max 511-char lines;
    rejects: unknown section type, unknown key, missing required field,
    duplicate card ID, malformed hex, wrong-length hex, line overflow).
  - **`ntag424_policy_free`**: frees all parser state.
  - **`ntag424_policy_lookup`**: finds a card entry matching *both* username
    and UID (constant-time UID comparison to avoid timing sidechannels).
  - **`ntag424_policy_try_verify`**: iterates all cards for a user, calls
    `ntag424_verify_from_url` with each card's K1/K2, and checks the
    recovered UID against the config UID — the single function needed to go
    from URL + username to a verified card identity.
- Added SQLite replay protection (`ntag424_replay.{c,h}`):
  - **Schema**: `ntag424_replay(card_id TEXT PK, last_counter INTEGER,
    updated_at INTEGER)`; created automatically on first open.
  - **WAL mode** for crash safety and concurrent read robustness.
  - **`ntag424_replay_open`**: opens (or creates) the DB, enables WAL, creates
    schema.
  - **`ntag424_replay_check_and_update`**: single `BEGIN IMMEDIATE` transaction;
    inserts first-seen card; accepts strictly-greater counters; rejects equal
    or lower; all errors fail closed.
  - **`ntag424_replay_close`**: frees handle.
- Added non-PAM end-to-end harness (`ntag424_authcheck.c`, `noinst_PROGRAMS`):
  - `ntag424_authcheck -u <user> -c <config> -d <db> --url <url>`
  - Runs: policy load → replay DB open → `ntag424_policy_try_verify` → replay
    check+update → prints `AUTH OK` or `AUTH FAILED: <reason>`.
  - Does NOT print sensitive URL, `p`, `c`, or key material.
  - Exit code 0 = OK, 1 = auth failure, 2 = usage error.
- 90 new unit tests (no hardware required):
  - Policy: 58 tests — valid config (1/2 cards, comments, whitespace), all
    missing-field combinations, unknown key, unknown section, kv outside
    section, duplicate card_id, malformed hex, wrong-length hex, line too
    long, lookup wrong user, lookup wrong uid, multi-card lookup, try_verify
    success, wrong user, bad URL, wrong keys, UID mismatch in config, null args
  - Replay: 32 tests — open/create, first use (counter 0 and non-zero), same
    counter rejected, lower counter rejected, sequential increases, independent
    card IDs, state persistence across reopen, null/invalid args, invalid path

### Milestone 4 (done)

- Added thin PAM orchestration layer (`ntag424_pam_glue.{c,h}`):
  - **`ntag424_auth_run`**: PC/SC backend entry point — opens reader, reads NDEF,
    runs verifier, checks policy, updates replay DB.
  - **`ntag424_auth_run_with_transport`**: testable entry point with injected
    transport; all orchestration logic is shared with `ntag424_auth_run`.
  - All errors fail closed; `NTAG424_AUTH_ERR_{ARGS,CONFIG,DB,READER,POLICY,REPLAY}`.
  - Nothing logged contains URL, p/c values, or key material.
- Modified `pam_pcsc_cr.c` — opt-in NTAG424 path:
  - **`backend=ntag424`** module argument selects the NTAG424 path; legacy
    HMAC-SHA1/YubiKey path is the default and remains entirely unchanged.
  - New module arguments: `ntag424_config=<path>`, `ntag424_db=<path>`,
    `ntag424_reader=<substring>`.
  - `pam_sm_authenticate` dispatches to `ntag424_auth_run` when NTAG424 mode
    is selected; the old authfile/token_key path is unreachable in that branch.
- Updated `pam_pcsc_cr.8` man page:
  - Documents all new module arguments.
  - Includes example PAM stack with NTAG424 as second factor after `pam_unix`.
  - Includes the config file format.
- 33 new unit tests (`test_ntag424_pam_glue.c`, no hardware required):
  - Null / invalid argument handling (5 tests).
  - Config not found, invalid DB path, malformed config (3 tests).
  - Reader / NDEF error paths via mock transport (2 tests).
  - Full success path via mock transport + BoltCard test vector (1 test).
  - Replay rejection after first acceptance — same NDEF / same counter (2 tests).
  - Policy mismatch: wrong user, wrong keys, UID mismatch in config (3 tests).
  - `parse_cfg` argument parsing: `backend=ntag424`, default legacy, NTAG424
    options, reader substr default NULL (5 tests).
  - Status string coverage (8 tests).

### Milestone 5 (done)

- Added `ntag424_policy_validate_card_entry` and `ntag424_policy_add_card`
  to `ntag424_policy.{c,h}`:
  - Validate card entry fields (non-empty card_id, username).
  - `ntag424_policy_add_card(path, entry, overwrite)`: creates a new config
    file if absent; validates existing config before appending; rejects
    duplicate card_id unless overwrite=1; writes via temp file + atomic
    rename for crash safety.
  - 28 new unit tests (validation, new file, append, duplicate reject,
    overwrite, null args, malformed file, preserve, hex round-trip).
- Added `ntag424_setup` CLI tool (`bin_PROGRAMS`):
  - Registers a card in the policy config.
  - Auto-generates card ID as `card-<user>-<uid>` if not supplied.
  - `--force` flag for overwriting existing entries.
  - Validates UID (14 hex), K1/K2 (32 hex) before writing.
- Total policy tests: 86 (up from 58).

### Still TODO

- Packaging (RPM/deb).
- Optional: `--issuer-key` flag for `ntag424_setup` to auto-derive K1/K2.

## Known blockers / uncertainty

- Pre-existing legacy compile failures (`reader.h` missing `<stdint.h>`,
  `pcsc_cr.c` `SCARD_ATTR_ATR_STRING` resolution, `authfile.c` GCC
  stringop-overflow) have been fixed during the stabilization pass.
  The full tree now builds clean with `-Werror` and all tests pass.

## Hardware validation (done)

Tested with ACS ACR1252 USB reader, Bolt Card (NTAG424 DNA), pcscd on Ubuntu.
Card uses deterministic key derivation (IssuerKey `0x00..01`, Version 1).

- Card read → NDEF → URL → p/c extraction: **pass**
- K1 decrypt → UID/counter recovery: **pass**
- K2 CMAC verification: **pass**
- Replay rejection (same counter): **pass**
- Counter increment across taps: **pass**
- Full PAM auth cycle via `pam_test boltcard-login boltcard`: **pass**
- Replay rejection through PAM: **pass**
