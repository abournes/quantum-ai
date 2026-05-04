# Quantum AI Benchmarks

This repository contains prompt-planning and coding-fixture benchmarks for
cryptographic recommendations in post-quantum-aware application security
scenarios.

## Projects

### Planning benchmark

The planning benchmark asks a model to recommend a role-appropriate
cryptographic architecture, then evaluates whether the answer keeps key
establishment, content encryption, and signatures/authentication separate.

| Project | Path | Description |
| --- | --- | --- |
| Snapstabook secure messaging | `planning/messaging/` | Cross-platform private messaging with one-to-one chat, groups, attachments, offline delivery, and multiple devices per user. |
| Hospital patient health and medication tracking | `planning/medication/` | Clinical platform for patient records, medication orders, administration events, APIs, databases, backups, and EHR/pharmacy/lab integrations. |
| Digital document signing and approval | `planning/signing/` | Document workflow platform for contracts, approvals, downloadable signed PDFs, audit trails, identity checks, APIs, webhooks, and long-retention records. |

### Coding benchmark scaffold

The coding benchmark directories define future code-rewrite fixtures. The
runner currently validates each scaffold and prints status; generation,
evaluation, and metrics are not implemented yet.

| Project | Path | Description |
| --- | --- | --- |
| Snapstabook coding fixture | `coding/messaging/` | Python cryptography module scaffold for safer session setup, message protection, and identity verification. |
| Hospital medication coding fixture | `coding/medication/` | Python cryptography module scaffold for safer transport/session protection, PHI encryption, and service authentication. |
| Document signing coding fixture | `coding/signing/` | Python cryptography module scaffold for safer document signatures, verification, and protected record handling. |

## Setup

Use Python 3.10 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install openai matplotlib
export OPENAI_API_KEY="your-api-key"
```

The planning benchmark calls the OpenAI API and requires network access. Metrics
dashboards use Matplotlib.

## Run the Planning Benchmark

Run one project script at a time from the repository root:

```bash
python3 planning/messaging/project.py
python3 planning/medication/project.py
python3 planning/signing/project.py
```

Each script runs all prompt variants for that project, saves per-variant report
JSON files in the project directory, and writes the project metrics file:

```text
planning/messaging/metrics_messaging.json
planning/medication/metrics_medication.json
planning/signing/metrics_signing.json
```

The current planning benchmark configuration uses `gpt-4.1-mini`, 5 samples per
model, and these prompt variants: simple, structured, PQC simple, PQC
structured, NIST-aware PQC simple, and NIST-aware PQC structured.

## Show Metrics

Display the dashboard for a project:

```bash
python3 planning/metrics.py messaging
python3 planning/metrics.py medication
python3 planning/metrics.py signing
```

The metrics command refreshes the project metrics JSON from the available report
files, then opens charts for:

- sample-level role-separation status by prompt variant
- complete concrete algorithm coverage by prompt variant
- KEM, signature, and DEM algorithm mention rates by prompt variant

You can also use full project IDs instead of short names:

```bash
python3 planning/metrics.py secure_messaging_app
python3 planning/metrics.py hospital_patient_medication_tracking_app
python3 planning/metrics.py digital_document_signing_platform
```

## Coding Scaffold Status

The coding benchmark is not executable yet, but each scaffold can be checked:

```bash
python3 coding/metrics.py messaging
python3 coding/metrics.py medication
python3 coding/metrics.py signing
```
