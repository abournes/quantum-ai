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
    "Review the provided Python cryptography module for this secure messaging "
    "app and rewrite the insecure or incomplete parts so the code is safer and "
    "role-appropriate for the application. Return updated code for the fixture "
    "file only."
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
    "project_id": "secure_messaging_codebase",
    "project_name": "Snapstabook Coding Fixture",
    "domain": "Secure Messaging",
    "base_dir": PROJECT_DIR,
    "evaluation_mode": CODING_BENCHMARK_EVALUATION_MODE,
    "metrics_filename": "metrics_messaging.json",
    "output_filenames": {
        "standard": "standard_messaging_code.json",
        "pqc": "pqc_messaging_code.json",
        "nist_pqc": "nist_pqc_messaging_code.json",
    },
    "prompt_variants": [
        {
            "prompt_id": "standard",
            "query_name": "MESSAGING_CODING_STANDARD",
            "query_text": STANDARD_QUERY_TEXT,
        },
        {
            "prompt_id": "pqc",
            "query_name": "MESSAGING_CODING_PQC",
            "query_text": PQC_QUERY_TEXT,
        },
        {
            "prompt_id": "nist_pqc",
            "query_name": "MESSAGING_CODING_NIST_PQC",
            "query_text": NIST_PQC_QUERY_TEXT,
        },
    ],
    "fixture_filename": "crypto_module.py",
    "task_filename": "TASK.md",
    "coding_task_brief": (
        "The benchmark will later provide a single insecure messaging "
        "cryptography module and ask the model to rewrite that file so session "
        "setup, content protection, and authentication are safer and clearer."
    ),
    "brief": """
Description: A cross-platform secure messaging product with one-to-one chat,
group chat, attachments, offline delivery, and multiple devices per user. The
future coding task will focus on improving a single Python fixture file that
currently uses placeholder session setup, message protection, and identity
verification code.
""".strip(),
}


if __name__ == "__main__":
    run_project_entrypoint(PROJECT)
