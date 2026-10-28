# AI-DFIR: AI-Powered Digital Forensics Investigation System

An educational digital-forensics prototype built with Flask, Pandas, Scikit-learn, SQLite, and ReportLab.

## Features
- Create an investigation case and upload CSV, TXT, or LOG evidence.
- SHA-256 hashes for uploaded files and a basic integrity re-check.
- Parse normalized CSV evidence or text logs.
- Rule-based findings for repeated failed logins, suspicious ports, and unusual byte counts.
- Optional Isolation Forest anomaly detection when enough numeric network events are present.
- Event timeline, findings dashboard, SQLite case history, and PDF report.
- Case status, priority, investigator assignment, tags, analyst notes, and case activity history.
- Evidence chain-of-custody events for upload, access, transfer, integrity verification, and export.
- PCAP/PCAPNG network analysis for IP flows, DNS queries, uncommon ports, repeated SYN attempts, and traffic-volume spikes.
- Optional OpenAI case assistant with citations restricted to records supplied to the model.
- Optional VirusTotal IP/hash enrichment with a 24-hour cache and retrieval timestamps.
- Finding-level true/false-positive and true/false-negative labels with precision, recall, and false-positive-rate calculations.
- PDF and CSV reports containing findings, evidence hashes, model explanations, network summaries, evaluation, and custody history.
- Responsive investigator workspace with persistent light and dark themes.
- Dark workspace theme using slate panels, restrained teal accents, severity colors, searchable case/evidence/audit tables, keyboard focus states, and compact responsive navigation.
- The case evidence register shows stored filename, SHA-256, size, upload time, integrity-check state, and analysis state; status labels reflect stored custody and analysis records rather than assumed verification.
- Authenticated administrator and user sign-in, password hashing, CSRF protection, and private user-owned cases. Administrators can review all cases.
- Clickable account profiles for users and administrators, with database-persisted username/recovery-email updates, current-password verification, and secure password changes that invalidate other sessions.
- Optional TOTP MFA with one-time recovery codes, login-attempt throttling, account disable/MFA reset controls, and expiring email password-reset links.
- Docker/Waitress deployment with safe production secret checks, security headers, SQLite WAL/busy-timeout settings, and a health endpoint.
- Encrypted S3-compatible backup/restore for database snapshots, uploaded evidence, and reports, with a signed backup manifest and SHA-256 verification.
- Disk-image evidence intake for split E01/EWF, AFF, DD, RAW, and IMG images (up to 64 GiB per image set).
- Read-only partition-table and filesystem inspection, recursive file listings, and explicit file extraction/recovery through The Sleuth Kit.
- SHA-256 hashes for uploaded containers and each segment, the decoded logical image, full file listings, and every recovered file.

## Requirements
- Python 3.10 or newer recommended.

## Run
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

For local development, `app.py` uses Flask's development server on `127.0.0.1`; debug mode is disabled unless `AI_DFIR_DEBUG=1`. Do not expose that development server to a network. A production environment requires a unique `AI_DFIR_SECRET` with at least 32 characters; the app starts with Waitress when `AI_DFIR_ENV=production`.

## Docker deployment

Docker Compose runs the app behind Waitress and an S3-compatible MinIO object store, and persists application data in Docker volumes. Copy `.env.example` to `.env`, then replace the admin and MinIO credential placeholders and generate separate random application, backup-signing, and 32-byte encryption keys. Keep `.env` and these keys outside source control and store backup keys separately from the backup objects.

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
docker compose up --build -d
```

Use a generated long random string for `AI_DFIR_SECRET` and `AI_DFIR_BACKUP_SIGNING_KEY`; use the base64 output of the second command as `AI_DFIR_S3_SSE_KEY`. The app is bound to `127.0.0.1:5000` and the MinIO console to `127.0.0.1:9001`; put a TLS-terminating reverse proxy in front of the app before remote access. Set `AI_DFIR_COOKIE_SECURE=1` when serving only over HTTPS. Do not publish the MinIO console or its API directly to the internet.

The mounted evidence volume remains the active local forensic working copy because disk-image, PCAP, and text parsers currently consume local paths. The backup command uploads a consistent database snapshot and evidence/report files to S3-compatible storage using S3 SSE-C with the configured 32-byte key. This is encrypted backup storage, not a replacement for encrypting the host volume; protect the Docker host and its data volume. For off-host backup, configure a private HTTPS S3-compatible endpoint and appropriate credentials instead of the bundled MinIO service. Keep the encryption and signing keys in a secure location separate from the object store; without them, restore and signature verification are not possible.

Create, list, and restore backups from the app container:

```powershell
docker compose exec app python backup_evidence.py create
docker compose exec app python backup_evidence.py list
docker compose exec app python backup_evidence.py restore <backup-id> /app/data/restore-staging
```

Restore extracts to a new directory and verifies every file before completing. Stop the app before copying a verified restore into the live data volume. Keep a separate copy of the current data before replacing it, and test the restore procedure periodically. Backup encryption protects confidentiality; the signed manifest and per-file hashes detect accidental or unauthorized changes, but do not make the MinIO account immutable or tamper-proof.

## Accounts and access

Configure the first administrator before starting the app. The administrator is created only when no administrator account exists; restarting the app does not reset an existing password.

```powershell
$env:AI_DFIR_ADMIN_USERNAME = "admin"
$env:AI_DFIR_ADMIN_PASSWORD = "use-a-unique-password-of-at-least-12-characters"
$env:AI_DFIR_SECRET = "replace-with-a-long-random-secret"
python app.py
```

The first admin username must contain 3-32 letters, numbers, underscores, or hyphens; the password must contain at least 12 characters. Users can create user accounts from the sign-in page. The login screen requires selecting the matching account type; users cannot register as administrators. User accounts can access only cases they created, while an administrator can review all cases, including cases created by other users. Existing cases from before account support are visible to administrators and are not assigned to user accounts.

For HTTPS deployments, set `AI_DFIR_COOKIE_SECURE=1` so session cookies are sent only over HTTPS. Keep the Flask development server on localhost; deploy behind a properly configured production WSGI server before exposing the app to a network.

Users can enable TOTP from **Account security** and should securely save the one-time recovery codes. Administrators can disable accounts or clear a user's MFA enrollment from **Manage accounts**. Sign-in throttles after five failed attempts per account/IP combination within 15 minutes. Password-reset email links require SMTP configuration (`AI_DFIR_SMTP_HOST`, `AI_DFIR_SMTP_FROM`, and optional authentication settings); reset links expire after 30 minutes, can only be used once, and reset MFA enrollment. Use a trusted SMTP provider with TLS. If email is not configured, users must contact the administrator for account recovery.

The signed-in username in the top bar links to **My profile** for both users and administrators. Profile changes are stored in the SQLite user account; updating account details requires the current password, and changing the password invalidates other active sessions. Account role and administrator privileges cannot be changed from the self-service profile.

The theme control in the top bar switches between the dark investigator dashboard and the light theme, and remembers the choice in the browser. The workspace sidebar links to the overview, cases, evidence, network analysis, findings, reports, and custody/audit sections. Evidence and audit tables provide in-page search. The evidence register distinguishes a stored hash from a subsequent integrity verification; use **Verify integrity** to compare saved evidence with its current SHA-256. Analysis status is based on records saved for that evidence or the persisted disk-image processing state.

## Optional external services

The core evidence workflow works without API keys. Configure optional services in the server environment before starting Flask:

```powershell
$env:OPENAI_API_KEY = "your-key"
$env:OPENAI_MODEL = "gpt-4o-mini" # optional
$env:VIRUSTOTAL_API_KEY = "your-key"
python app.py
```

The assistant sends the question and a bounded summary of selected case records (up to 50 findings of each type, 50 evidence files, 25 disk images, 25 packet captures, and 25 analyst notes) to OpenAI when an investigator submits a question. Citation references are checked against the records supplied. VirusTotal receives only an explicitly requested IP address or SHA-256 hash. Its responses are cached for 24 hours; unavailable or unknown reputation is not treated as a clean result. Review each provider's terms and do not submit data unless authorized.

Case assignees are workflow labels, not account permissions. Account identity is used for audit and chain-of-custody actions. This remains an educational prototype, not a production evidence vault or a validated forensic suite. Configure unique secrets for deployments and place API keys in protected environment configuration, never in source control.

## Packet-capture limits

PCAP/PCAPNG intake is limited to 256 MiB and analysis stops after 1,000,000 packets. To bound resource use, analysis tracks at most 20,000 distinct flows and stores a maximum of 5,000 flow summaries, traffic spikes, and DNS groups in each category. Reports and the case page indicate when results were capped; capped findings are not a complete account of the capture.

## Accepted evidence formats
- CSV with optional columns such as `timestamp`, `source_ip`, `destination_ip`, `event_type`, `username`, `status`, `bytes`, `port`, `message`.
- TXT/LOG: one event per line. The parser extracts a timestamp if it sees an ISO-like date/time and uses keyword heuristics.
- Disk images: `.E01` through `.E99` segments, `.AFF`, `.DD`, `.RAW`, and `.IMG`. Select the complete, contiguous E01 segment set together; select only one image set per upload.

For best results, use the included `sample_evidence.csv`.

## Disk-image analysis setup
Image parsing and recovery require a compatible The Sleuth Kit installation (4.14.0 or newer recommended). Add the directory containing `img_stat`, `img_cat`, `mmls`, `fsstat`, `fls`, and `tsk_recover` to `PATH`, then restart the Flask app. The installed build must include EWF support for E01 and AFF support for AFF images; support varies by build. The app reports missing tools or unsupported image formats instead of treating an image as analyzed.

Upload preserves the supplied image segments and hashes each segment and the concatenated container bytes. Analysis verifies those hashes, reads the partition table and filesystems without modifying the evidence, and hashes the decoded logical image stream. The recursive file listings can be downloaded. The separate “Extract & recover files” action invokes `tsk_recover -e`; it may consume substantial time and disk space. A JSON-lines manifest is generated with the size and SHA-256 of each recovered file, and recovered files can be downloaded individually from the case page.

Long image operations run in a single in-process background worker. Keep the app running until the case page reports completion. This prototype does not acquire directly from physical devices, write to images, or replace a validated forensic workstation. The configured 64 GiB limit applies to the combined uploaded image set; ensure enough free disk space for the uploaded image and any extracted output.

## Safety and forensic limitations
- Use only evidence you are authorized to examine.
- This is a learning prototype, not a validated forensic suite.
- Keep original evidence read-only and work from copies. This app stores uploaded files in `uploads/`; do not use it as a production evidence vault.
- Only analyze images you are authorized to examine. Preserve originals and verify the recorded hashes independently before relying on results.
- SHA-256 supports integrity checking but does not prove authenticity, provenance, or truth.
- Alerts are leads for human review, not proof of malicious activity or criminal conduct.
- ML anomaly detection is unsupervised and can generate false positives and false negatives.
- Evaluation metrics use investigator-provided labels and should only be interpreted against an appropriate labeled test set. Rule and model counts are triage summaries, not a comparative benchmark.
- Do not upload private, sensitive, or real case data to an unsecured demo server.
