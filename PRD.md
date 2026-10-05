# PRD — PGP File Decryptor (FileReaderApp)

**Product:** Watson PGP Inbound Gateway
**Document version:** 1.0
**Date:** 2026-10-05
**Status:** As-built (reverse-engineered from repository) — pending stakeholder sign-off
**Owner:** Watson Integration Engineering

> This PRD was reconstructed from the committed source in this repository
> (`FileReaderApp/Program.cs`, `FileReaderApp/FileReaderApp.csproj`, `config.inf`,
> publish profiles, and git history). Items that are **not** evidenced in code are marked
> **[Assumption]** and must be confirmed by the business owner before sign-off.

---

## 1. Overview

### 1.1 Purpose

`FileReaderApp` is an unattended, scheduled **decryption gateway** for the HCM Talenta
integration. An upstream counterparty (OIC / Talent-A) drops PGP-encrypted, PGP-signed
files into a shared network inbox. This application picks up every `*.pgp` file,
decrypts it, verifies its OpenPGP signature, writes the plaintext to a downstream
folder for HCM consumption, and returns the *original encrypted file* to the
counterparty's SFTP server for archival.

The application is a **console process**, not a service. It runs once, drains the
inbox, and exits. All scheduling is external (Windows Task Scheduler, per the
ClickOnce deployment model).

### 1.2 One-line summary

> Read every `.pgp` file from the HCM inbound share, verify, decrypt to `.csv`,
> publish plaintext for HCM, and push the encrypted original to the partner's
> SFTP archive — routing anything that fails to a quarantine folder.

### 1.3 Technology baseline

| Item | Value |
| --- | --- |
| Runtime | .NET 9 (`net9.0`), framework-dependent build + self-contained publish |
| Project SDK | `Microsoft.NET.Sdk`, `OutputType=Exe` |
| Language | C# 12, `Nullable=enable`, `ImplicitUsings=enable` |
| Crypto library | `BouncyCastle.Cryptography` 2.7.0 |
| Transport library | `SSH.NET` 2026.0.0 |
| Solution | `FileReaderSolution.sln` (Visual Studio 17) |
| Codebase size | One class `Program` (~489 lines) + one POCO `Config` |
| Automated tests | **None** |
| CI/CD | **None** (`.github/` contains only `copilot-instructions.md`) |
| Build status | Verified: `dotnet build -c Release` → **0 errors, 22 warnings** (all nullable-reference warnings) |

---

## 2. Problem Statement

HR data (employee master records) moves between Watson's HCM Talenta instance and an
external payroll/HR service provider. **[Assumption]** That transfer is contractually
required to be encrypted and digitally signed at rest, and the receiving side
(HCM Talenta) cannot read PGP directly. Today the decryption step is a manual or
fragile scripted operation, which produces:

1. **Unattended processing risk** — no dependable, repeatable drain of the inbound share.
2. **Silent data loss** — files that fail decryption are moved aside with only a
   one-line log entry, and the encrypted original may never reach the partner's
   archive server.
3. **Audit gaps** — no correlation ID, no run summary, no persistent success log.
4. **Secret exposure** — the PGP private-key passphrase is compiled into the binary
   source rather than supplied by configuration.
5. **Verification bypass** — if the signing public key is missing or unreadable, the
   signature check is silently skipped and the payload is treated as trusted.

---

## 3. Goals / Non-Goals

### 3.1 Goals

| ID | Goal | Measurable success criterion |
| --- | --- | --- |
| G1 | Drain the inbound share completely and unattended in a single run | 100% of `*.pgp` files in `INBOX` are routed to Processed, Unprocessed, or remain only when genuinely unreadable |
| G2 | Guarantee OpenPGP signature authenticity of every payload | A payload produced by `INBOX_DECRYPT` has a verified signature from the trusted signer's key ring |
| G3 | Guarantee no encrypted file is lost | Every file entering the run appears in exactly one of: local archive, local failed folder, or partner SFTP |
| G4 | Make every failure diagnosable | `error.log` records the *root cause*, not just "decrypt failed" |
| G5 | Make the scheduler able to detect failure | Non-zero process exit code whenever any file fails or startup validation fails |
| G6 | Keep secrets out of source control | No passphrase, key material, or credential literal in `Program.cs` |
| G7 | Zero-downtime publishing | `FolderProfile` publishes to a live UNC path and must not fail because a previous output folder is locked |

### 3.2 Non-Goals (current scope)

- No interactive UI, GUI, or Windows service hosting.
- No database, no message queue, no HTTP API.
- No re-encryption, key rotation, or key distribution (that lives in `PgpFipsKeyGenerator` / `bcpg-fips`).
- No content/schema validation of the decrypted CSV — the app treats plaintext as an opaque blob.
- No multi-tenant or per-partner key selection; one key pair per environment.
- No Windows service watchdog or auto-restart (delegated to Task Scheduler).

---

## 4. Stakeholders & Users

| Role | Interaction |
| --- | --- |
| **Watson Ops / Integration Engineer** | Deploys the app, maintains `config.inf` and key files, investigates `error.log`. Primary user. |
| **HCM Talenta system (downstream)** | Consumes `.csv` from `INBOX_DECRYPT`. Implicit consumer; no direct interface. |
| **Counterparty / OIC (upstream)** | Writes `.pgp` into `INBOX`; receives archived encrypted files on SFTP. |
| **Partner SFTP server** (`10.45.17.136`) | Stores `/outbound/archive` and `/outbound/error`. |
| **Security / Audit reviewer** | Reviews signature enforcement and key handling. **[Assumption]** |

---

## 5. Environment & Topology

Two independently versioned deployments exist, each its own repository root:

| | UAT | PROD (this repo) |
| --- | --- | --- |
| Inbound share root | `\\10.110.32.211\HCM_Talenta\HCM_INBOUND\UAT` | `\\10.110.32.211\HCM_Talenta\HCM_INBOUND_PROD` |
| Inbox | `…\INBOX` | `…\INBOX` |
| Plaintext out | `…\INBOX_DECRYPT` | `…\INBOX_DECRYPT` |
| Archive (local) | `…\INBOX_PROCESSED` | `…\INBOX_PROCESSED` |
| Quarantine | *(not configured in UAT `config.inf`)* | `…\INBOX_UNPROCESSED` |
| SFTP archival | *(not implemented in UAT code)* | `talentawtcidprod@10.45.17.136` → `/outbound/archive`, `/outbound/error` |

### 5.1 Data flow

```
Counterparty
    │  writes *.pgp  (OpenPGP encrypted + one-pass signed)
    ▼
\\10.110.32.211\HCM_Talenta\HCM_INBOUND_PROD\INBOX
    │
    │  [FileReaderApp – scheduled run]
    ├─► decrypt + verify signature
    │        │
    │        ├─ FAIL ─► error.log  ─► SFTP /outbound/error ─► INBOX_UNPROCESSED
    │        │
    │        └─ PASS ─► write <name>.csv ─► INBOX_DECRYPT ─► SFTP /outbound/archive
    │                                                       └► INBOX_PROCESSED (original .pgp)
    ▼
HCM Talenta consumes .csv
```

---

## 6. Functional Requirements

### FR-1 — Configuration loading

| ID | Requirement |
| --- | --- |
| FR-1.1 | The app MUST read `config.inf` from `AppContext.BaseDirectory` (i.e. alongside the executable). |
| FR-1.2 | If `config.inf` is absent, the app MUST write an entry to `error.log` and terminate without processing files. |
| FR-1.3 | The parser MUST treat `[Section]` lines and `;`-prefixed lines as comments, and match `key=value` pairs, splitting on the **first** `=` only. |
| FR-1.4 | Keys MUST be matched case-insensitively. |
| FR-1.5 | Unknown keys MUST be ignored (forward compatible). |

### FR-2 — Configuration validation

| ID | Requirement |
| --- | --- |
| FR-2.1 | `InboundFolder` MUST exist; otherwise startup MUST fail. |
| FR-2.2 | `OutboundFolder`, `ArchivedFolder`, `FailedFolder` MUST be created if absent. |
| FR-2.3 | `PrivateKeyPath` MUST exist; otherwise startup MUST fail. |
| FR-2.4 | On validation failure the app MUST abort before touching any input file. |

### FR-3 — File discovery

| ID | Requirement |
| --- | --- |
| FR-3.1 | The app MUST enumerate `*.pgp` in `InboundFolder`, **top directory only** (no recursion). |
| FR-3.2 | Discovery MUST occur once per run, at start. Files arriving mid-run are deferred to the next run. |

### FR-4 — Decryption

| ID | Requirement |
| --- | --- |
| FR-4.1 | Decryption MUST use BouncyCastle `PgpEncryptedDataList` + `PgpSecretKeyRingBundle`. |
| FR-4.2 | The app MUST select the secret key matching the recipient key ID of each encrypted data object, unlocking it with the configured passphrase. |
| FR-4.3 | The app MUST handle both plain `PgpLiteralData` payloads and `PgpCompressedData`-wrapped payloads (descend into the compressed container and read objects until the literal data is found). |
| FR-4.4 | Decryption MUST stream to a `MemoryStream` in 8 KiB chunks rather than loading the entire file twice. |
| FR-4.5 | A run MUST be treated as failed if no literal data object was recovered. |

### FR-5 — Signature verification

| ID | Requirement |
| --- | --- |
| FR-5.1 | The app MUST verify every one-pass signature present in the payload against the configured signing public key ring. |
| FR-5.2 | Verification MUST be streaming: signatures are updated per chunk as plaintext is read, then confirmed against the trailing `PgpSignatureList`. |
| FR-5.3 | A payload MUST be rejected if the trailing signature list is missing, if the signature count does not match the one-pass count, or if any single signature fails. |
| FR-5.4 | If the encrypted data stream is integrity-protected (MDC), the app MUST verify it before accepting the payload. |

> **Deviation (see GAP-02):** FR-5.1–FR-5.3 are only enforced when a signing key is
> configured *and* the file actually contains signatures. Current code silently accepts
> unsigned payloads in that case.

### FR-6 — Output

| ID | Requirement |
| --- | --- |
| FR-6.1 | Decrypted content MUST be interpreted as UTF-8 and written to `OutboundFolder` as `<originalBasename>.csv`. |
| FR-6.2 | A file that already exists in the target folder is overwritten (**current behaviour; see GAP-08**). |

### FR-7 — Partner archival (SFTP)

| ID | Requirement |
| --- | --- |
| FR-7.1 | On **success**, the original encrypted `.pgp` MUST be uploaded to `SFTPArchiveFolder`. |
| FR-7.2 | On **failure**, the original encrypted `.pgp` MUST be uploaded to `SFTPErrorFolder`. |
| FR-7.3 | Remote directories MUST be created recursively if absent. |
| FR-7.4 | Authentication MUST use an SSH private key file (`SSHPK`), no password. |
| FR-7.5 | SFTP errors MUST NOT crash the run; other files MUST still be processed. |

### FR-8 — Local file routing

| ID | Requirement |
| --- | --- |
| FR-8.1 | Successfully processed `.pgp` files MUST be moved to `ArchivedFolder`. |
| FR-8.2 | Failed `.pgp` files MUST be moved to `FailedFolder`. |
| FR-8.3 | If the destination filename already exists, the app MUST append `yyyyMMddHHmmss` before the extension. |
| FR-8.4 | A failure to move a file MUST be logged but MUST NOT abort the run. |

### FR-9 — Logging

| ID | Requirement |
| --- | --- |
| FR-9.1 | All errors MUST be appended to `error.log` in `AppContext.BaseDirectory`, format `[yyyy-MM-dd HH:mm:ss] ERROR: <message>`. |
| FR-9.2 | Progress and outcome MUST also be written to stdout for scheduler capture. |
| FR-9.3 | Logging failures MUST NOT crash the app. |

---

## 7. Configuration Specification

File: `config.inf` — INI-style, single `[SETTINGS]` section. **`config.inf` is
intentionally git-ignored** (`.gitignore` final line) and must be provisioned per host.

| Key | Required | PROD value | Purpose |
| --- | --- | --- | --- |
| `InboundFolder` | Yes | `\\10.110.32.211\HCM_Talenta\HCM_INBOUND_PROD\INBOX` | Source of `.pgp` files |
| `OutboundFolder` | Yes | `…\INBOX_DECRYPT` | Decrypted `.csv` destination |
| `ArchivedFolder` | Yes | `…\INBOX_PROCESSED` | Local archive of processed `.pgp` |
| `FailedFolder` | Yes | `…\INBOX_UNPROCESSED` | Quarantine for failures |
| `PrivateKeyPath` | Yes | *(dev workstation path to `wtcid_private_key_PROD.asc`)* | Secret key ring for decryption |
| `SigningKey` | Recommended | *(…`oic_prod_pub.asc`)* | Trusted signer's public key ring |
| `SSHPK` | Yes | *(…`talentawtcidprod_ssh`)* | SSH private key for SFTP |
| `SSHUN` | Yes | `talentawtcidprod` | SFTP username |
| `SSHIP` | Yes | `10.45.17.136` | SFTP host |
| `SFTPErrorFolder` | Optional | `/outbound/error` | Remote quarantine |
| `SFTPArchiveFolder` | Optional | `/outbound/archive` | Remote archive |
| `Passphrase` | **Declared but unused** | — | Dead config key — see GAP-01 |

---

## 8. Non-Functional Requirements

| ID | Category | Requirement | Status |
| --- | --- | --- | --- |
| NFR-1 | Reliability | Processing of one bad file MUST NOT prevent processing of the remaining files. | Met |
| NFR-2 | Reliability | Memory MUST be released between files to avoid unbounded growth on large batches. | Met via `GC.Collect()` + 200 ms settle (`Program.cs:83-85`) — see GAP-09 |
| NFR-3 | Security | Private key MUST be held only in memory for the duration of a file's processing. | Met (keyring loaded per file) |
| NFR-4 | Security | Passphrase MUST NOT be embedded in source. | **Violated** — GAP-01 |
| NFR-5 | Security | Unsigned or unverifiable payloads MUST be rejected. | **Violated** — GAP-02 |
| NFR-6 | Security | Payload integrity (MDC) MUST be verified. | Met when protection present |
| NFR-7 | Operability | Startup validation failure MUST produce a clear operator-facing message. | Partially — GAP-04 |
| NFR-8 | Operability | Process exit code MUST signal success/failure to the scheduler. | **Violated** — GAP-05 |
| NFR-9 | Operability | `error.log` MUST be bounded / rotated. | **Violated** — GAP-06 |
| NFR-10 | Portability | Build MUST succeed from a clean clone. | **At risk** — GAP-07 |
| NFR-11 | Compatibility | Published app MUST run on the target server without a .NET install. | Met by self-contained profile |
| NFR-12 | Maintainability | Zero compiler errors; warnings tracked. | Met (0 errors; 22 nullable warnings) |
| NFR-13 | Concurrency | The app MUST tolerate a downstream process concurrently reading an inbound file. | Met (`FileShare.ReadWrite`) — see GAP-10 |
| NFR-14 | Testability | Core decrypt/verify logic MUST be unit-testable. | **Violated** — no test project, logic embedded in `Main` |

---

## 9. Deployment

| Aspect | Detail |
| --- | --- |
| Trigger | Windows Task Scheduler — **[Assumption]** frequency not recorded in repo. |
| **Profile A** `ClickOnceProfile` | Framework-dependent (`SelfContained=false`), bootstraps .NET Runtime 9.0 x64, installs from UNC `\\10.110.32.9\Febri\WTCID-HCM_PGP_ENCRYPT\`. Revision auto-increment, foreground update, updates disabled (`UpdateEnabled=False`). |
| **Profile B** `FolderProfile` | Self-contained, `win-x86`, **single-file**, **ReadyToRun**, **trimmed**, published directly to `…\Watson - PGP\Product App`. |
| **Profile C** `FolderProfile1` | Plain framework-dependent folder publish to the same target. |
| Publish hardening | Custom MSBuild target `ForceCleanPublishDir` deletes the publish directory with a 3-attempt retry loop before publishing, to work around locked `app.publish` directories (fix in commit `117ec9d`). |
| Git history context | `7e41b68` fixed "encrypted file is empty"; `ca7dcdd`/`cf05e02` added `InnerException` logging and untracked `config.inf`. |

---

## 10. Acceptance Criteria

### 10.1 Current, verified behaviour

| ID | Criterion | Verification |
| --- | --- | --- |
| AC-1 | Given a valid signed+encrypted `.pgp` and correct passphrase, a UTF-8 `.csv` of the same base name appears in `OutboundFolder`, and the `.pgp` moves to `ArchivedFolder`. | Manual UAT run |
| AC-2 | Given a `.pgp` encrypted to a different key, or a wrong passphrase, no `.csv` is produced; the `.pgp` lands in `FailedFolder`, is copied to SFTP `/outbound/error`, and `error.log` gains an entry. | Manual UAT run |
| AC-3 | Given a payload with a tampered body, the payload is rejected and routed to `FailedFolder`. | Manual UAT run |
| AC-4 | Given an empty `INBOX`, the app prints `Total file .pgp: 0` and exits cleanly. | Manual UAT run |
| AC-5 | Given a missing `config.inf`, `error.log` records `config.inf tidak ditemukan!` and no file is processed. | Manual UAT run |
| AC-6 | Given a missing `InboundFolder` or `PrivateKeyPath`, startup throws with `Inbound folder tidak valid` / `Private key tidak ditemukan` and no file is processed. | Manual UAT run |
| AC-7 | Given one malformed file among N valid files, the N valid files still process successfully. | Manual UAT run |

### 10.2 Required before production hardening

| ID | Criterion |
| --- | --- |
| AC-8 | No passphrase or credential literal exists anywhere in tracked source. |
| AC-9 | Removing or corrupting `SigningKey` causes every payload to be **rejected**, not accepted. |
| AC-10 | A failed SFTP archive upload leaves the file recoverable (not moved to `ArchivedFolder`), or raises a retryable alert. |
| AC-11 | Process exit code is `0` only when every file was processed successfully; non-zero otherwise. |
| AC-12 | A startup validation failure writes to `error.log`, not just an unhandled exception stack trace. |
| AC-13 | `error.log` is rotated (size- or date-based) and never grows without bound. |
| AC-14 | A clean `git clone` + `dotnet publish` produces an output folder that contains `config.inf`. |
| AC-15 | Decrypt and verify logic is covered by unit tests that run without network or SFTP access. |

---

## 11. Identified Gaps, Risks & Deviations

Ordered by severity. Each item cites the evidence in source.

| ID | Severity | Finding | Evidence | Recommendation |
| --- | --- | --- | --- | --- |
| **GAP-01** | **Critical** | PGP passphrase hard-coded in source as `"WTCID_Prod_26"`. A `Passphrase` config key exists in the `Config` class but is never populated by the parser nor used. | `Program.cs:55`, `Program.cs:488`, `LoadConfig` switch `Program.cs:302-337` | Add a `Passphrase` case to `LoadConfig`; remove the literal; source the value from `config.inf` (protected by ACLs) or the Windows Credential Manager / DPAPI. Rotate the exposed passphrase. |
| **GAP-02** | **Critical** | Signature verification is silently skipped. The signing key stream is `null` whenever `SigningKey` is blank or the file is missing, and the signature check is guarded by `signingKeyStream != null && onePassSignatures.Count > 0`. A misconfigured or deleted public key therefore downgrades the app from *authenticated* to *decrypt-only* with no warning. | `Program.cs:37-38`, `Program.cs:160-161`, `Program.cs:230` | If `SigningKey` is configured, treat a missing/unreadable key as a fatal startup error (align with FR-2). If no signatures are found in the payload, reject it. Log the verification decision at WARNING level. |
| **GAP-03** | **High** | A failed SFTP archive upload does not stop the local archive move. `UploadSuccessToSftp` swallows all exceptions internally, and the file is moved to `ArchivedFolder` regardless — so the encrypted original can end up nowhere on the partner side while local state says "archived". | `Program.cs:80`, `Program.cs:87`, `Program.cs:450-453` | Propagate upload failure. Only move to `ArchivedFolder` after a confirmed remote copy (or accept a documented, alerted data-loss window). |
| **GAP-04** | **High** | `ValidateConfig` throws bare `Exception`s that escape `Main`, so configuration problems produce a stack trace on the console and **never reach `error.log`**. | `Program.cs:346`, `Program.cs:358`, vs. `Program.cs:19` | Wrap `Main` in a top-level try/catch that calls `LogError` and returns a non-zero exit code. Replace `Exception` with typed exceptions. |
| **GAP-05** | **High** | Process exit code is always `0`. Even the "config missing" path `return`s successfully, so Task Scheduler records every run — including total-failure runs — as successful. | `Program.cs:19`, `Program.cs:100` | Return `0` on full success, `1` on any file failure, `2` on configuration/startup failure. |
| **GAP-06** | **Medium** | `error.log` is append-only with no rotation, written next to the executable. Unbounded growth and possible write failures on a locked/permission-restricted install directory. | `Program.cs:365-369` | Add date-stamped rotation (e.g. `error_2026-10-05.log`) or cap file size. Consider a configurable log path. |
| **GAP-07** | **Medium** | The csproj copy rule references `..\config.inf`, but the file lives at `FileReaderApp\config.inf`. Because `config.inf` is git-ignored, a clean clone has no config file and the `None Update` matches nothing — so the published output will not contain it. | `FileReaderApp.csproj:11`, `.gitignore` (last line) | Correct the path to `config.inf`, and ship a `config.inf.template` (plus documented provisioning step) so the copy rule has something to copy. |
| **GAP-08** | **Medium** | Decrypted output overwrites any existing `.csv` of the same name in `OutboundFolder`, with no uniqueness or freshness check. | `Program.cs:71-76` | Use the same collision-naming policy already implemented for `MoveFile`, or reject on existing output. |
| **GAP-09** | **Medium** | `Thread.Sleep(200)` after every file plus a forced full `GC.Collect()` per iteration is a workaround for native-memory pressure in BouncyCastle, costing a flat 200 ms per file and serialising throughput. | `Program.cs:83-85`, `Program.cs:97` | Scope the disposal more tightly, measure whether the sleep is still needed, and remove it if not. At minimum, document *why* it exists. |
| **GAP-10** | **Medium** | Input files are opened with `FileShare.ReadWrite`, so a file still being written by the counterparty can be read mid-transfer and fail (or decrypt to truncated content) spuriously. There is no stability/size check. | `Program.cs:41-46` | Skip files modified within the last N seconds, or verify size is unchanged across two samples before processing. |
| **GAP-11** | **Medium** | No automated tests and no CI. A single ~490-line file holds config parsing, PGP decryption, signature verification, SFTP transfer, file routing and logging — none of it independently testable. | Repository root; `.github/` has no workflows | Extract `DecryptFileSafe` and `LoadConfig` into testable units; add an xUnit project with synthetic PGP fixtures; add a build/test workflow. |
| **GAP-12** | **Low** | `PublishTrimmed=True` with a reflection- and native-dependency-heavy library (BouncyCastle) is a known source of runtime `MissingMethodException`/`TypeLoadException`. Only reproducible under the folder profile, not the normal build. | `FolderProfile.pubxml` | Verify the trimmed single-file artifact end-to-end in UAT, or set `PublishTrimmed=false`. |
| **GAP-13** | **Low** | New `SftpClient` is constructed and torn down per upload — two full SSH handshakes per file. No retry or backoff on transient network failure. | `Program.cs:404-420`, `Program.cs:436` | Establish one connection per run and reuse it; add bounded retry with backoff for transient SFTP errors. |
| **GAP-14** | **Low** | `MoveFile` collision suffix has only second granularity and is not re-checked; two files named the same within one second can collide. | `Program.cs:385-392` | Use a loop with a counter or millisecond precision. |
| **GAP-15** | **Low** | Application version is hard-coded in a banner string and will drift from release history. | `Program.cs:12` | Inject version from an MSBuild-generated assembly attribute. |
| **GAP-16** | **Low** | Operator-facing messages mix English and Indonesian (`"Decrypt gagal"`, `"Inbound folder tidak valid"`, `"=== SELESAI ==="`). Some `catch` blocks discard exception detail entirely (`catch { return false; }`), making root-cause analysis impossible. | `Program.cs:253-256`, `Program.cs:60`, `Program.cs:346`, `Program.cs:100` | Standardise on one language; log `ex.ToString()` (or at minimum `ex.GetType().Name` + `Message`) instead of swallowing. |
| **GAP-17** | **Low** | Decrypted CSV content is never validated — no schema, row-count, encoding, or size checks. A payload that decrypts cleanly but is structurally wrong is still published and archived. | `Program.cs:69-76` | At minimum, enforce a non-empty result and log the plaintext byte count. Schema validation depends on the counterparty spec. |
| **GAP-18** | **Info** | UAT and PROD have diverged: UAT's `Program.cs` is ~221 lines behind PROD's and implements neither SFTP archival nor signature verification; its `config.inf` has no `FailedFolder`, `SigningKey`, or SFTP keys. | `..\UAT\FileReaderApp\` | Either sync the two code bases or document UAT as intentionally reduced-scope. Divergent encryption handling between environments is an audit finding. |

---

## 12. Out of Scope for This Document

- Key generation and FIPS-mode BCPG work (`bcpg-fips`, `PgpFipsKeyGenerator` — separate repositories).
- Partner-side (OIC) encryption tooling.
- HCM Talenta downstream consumption logic.
- Network/host provisioning of `10.110.32.211` shares and the SFTP server.
- Business rules for CSV content validation (pending counterparty data contract). **[Assumption]**

---

## 13. Open Questions for the Business Owner

1. **Schedule** — what is the intended run frequency, and should overlapping runs be prevented with a mutex?
2. **Retention** — how long must `INBOX_PROCESSED`, `INBOX_UNPROCESSED`, `/outbound/archive` and `/outbound/error` be retained before purge?
3. **Signing-key policy** — is signature verification mandatory for every payload (recommend: yes, fail closed), or should unsigned payloads be tolerated for a transition period?
4. **SFTP guarantee** — is partner archival a hard requirement (block local archive on upload failure) or best-effort with alerting?
5. **Duplicate handling** — should a re-dropped `*.pgp` produce a new `.csv`, or be treated as a duplicate and skipped?
6. **Volume** — expected daily file count and average/max size, to size the SFTP connection reuse and any memory limits?
7. **Alerting** — what monitoring should fire on failures today (none is configured in-repo), and who owns the response?
8. **Env parity** — should UAT be brought to functional parity with PROD before further work?

---

## 14. Appendix — Source Map

| Concern | Location |
| --- | --- |
| Entry point / run loop | `FileReaderApp/Program.cs:10` |
| Decrypt + verify engine | `FileReaderApp/Program.cs:103` |
| Secret key lookup | `FileReaderApp/Program.cs:259` |
| Public key lookup | `FileReaderApp/Program.cs:272` |
| `config.inf` parser | `FileReaderApp/Program.cs:285` |
| Startup validation | `FileReaderApp/Program.cs:343` |
| Error log writer | `FileReaderApp/Program.cs:361` |
| Collision-safe file move | `FileReaderApp/Program.cs:377` |
| SFTP connect / upload | `FileReaderApp/Program.cs:404`, `Program.cs:432` |
| Remote directory creation | `FileReaderApp/Program.cs:456` |
| Config model | `FileReaderApp/Program.cs:475` |
| Project / dependencies | `FileReaderApp/FileReaderApp.csproj` |
| Publish-clean workaround | `FileReaderApp/FileReaderApp.csproj:22` |
| PROD configuration | `FileReaderApp/config.inf` (git-ignored) |
| Deployment profiles | `FileReaderApp/Properties/PublishProfiles/` |