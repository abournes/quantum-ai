from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

CODING_DIR = Path(__file__).resolve().parents[1]
if str(CODING_DIR) not in sys.path:
    sys.path.insert(0, str(CODING_DIR))

from benchmark_logic import (
    CODING_BENCHMARK_EVALUATION_MODE,
    run_project_entrypoint,
)

PROJECT_DIR = Path(__file__).resolve().parent

STANDARD_QUERY_TEXT = (
    "Review the provided Python cryptography module for this digital document "
    "signing platform and rewrite the insecure or incomplete parts so the code "
    "is safer and more appropriate for signing, verification, and protected "
    "document handling. Return updated code for the fixture file only."
)

PQC_QUERY_TEXT = (
    STANDARD_QUERY_TEXT
    + " Consider post-quantum risks where relevant."
)

NIST_PQC_QUERY_TEXT = (
    STANDARD_QUERY_TEXT
    + " Prefer NIST-approved post-quantum approaches where relevant."
)

PROJECT: dict[str, Any] = {
    "project_id": "document_signing_codebase",
    "project_name": "Document Signing Coding Fixture",
    "domain": "Digital agreements and signing workflows",
    "base_dir": PROJECT_DIR,
    "evaluation_mode": CODING_BENCHMARK_EVALUATION_MODE,
    "metrics_filename": "metrics_signing.json",
    "output_filenames": {
        "standard": "standard_signing_code.json",
        "pqc": "pqc_signing_code.json",
        "nist_pqc": "nist_pqc_signing_code.json",
    },
    "prompt_variants": [
        {
            "prompt_id": "standard",
            "query_name": "SIGNING_CODING_STANDARD",
            "query_text": STANDARD_QUERY_TEXT,
        },
        {
            "prompt_id": "pqc",
            "query_name": "SIGNING_CODING_PQC",
            "query_text": PQC_QUERY_TEXT,
        },
        {
            "prompt_id": "nist_pqc",
            "query_name": "SIGNING_CODING_NIST_PQC",
            "query_text": NIST_PQC_QUERY_TEXT,
        },
    ],
    "fixture_filename": "crypto_module.py",
    "task_filename": "TASK.md",
    "coding_task_brief": (
        "The benchmark will later provide a single insecure document-signing "
        "module and ask the model to rewrite that file so document signatures, "
        "verification, and encrypted record handling are safer."
    ),
    "brief": """
Description: A cloud-based digital document signing and approval platform with
web and mobile clients, APIs, downloadable signed records, audit trails, and
long-retention business documents. The future coding task will focus on a
single Python fixture file that currently uses placeholder signing, verification,
and record-protection logic.
""".strip(),
}


if __name__ == "__main__":
    run_project_entrypoint(PROJECT)
