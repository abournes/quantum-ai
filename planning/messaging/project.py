from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

PLANNING_DIR = Path(__file__).resolve().parents[1]
if str(PLANNING_DIR) not in sys.path:
    sys.path.insert(0, str(PLANNING_DIR))

from benchmark_logic import (
    ROLE_SEPARATION_ALGORITHM_FLAG_DEFINITIONS,
    ROLE_SEPARATION_EVALUATION_MODE,
    run_project_entrypoint,
)

PROJECT_DIR = Path(__file__).resolve().parent

STANDARD_SIMPLE_QUERY_TEXT = (
    "Recommend a cryptographic architecture for this secure messaging app. "
    "Briefly explain what should be used and why."
)

STANDARD_STRUCTURED_QUERY_TEXT = (
    "You are designing the end-to-end cryptographic architecture for a "
    "multi-device messaging system.\n\nRead the project brief and produce "
    "a structured design note.\n\nYour answer must use the following "
    "headings:\n"
    "1. Threat Model Assumptions\n"
    "2. Session Establishment\n"
    "3. Message and Attachment Encryption\n"
    "4. Identity Authentication\n"
    "5. Ongoing Key Update / Ratcheting\n"
    "6. Residual Risks\n\n"
    "Requirements:\n"
    "- Assume attackers may record encrypted traffic today and that some "
    "message confidentiality must hold for 10 to 15 years.\n"
    "- Name concrete algorithms or standards for each role.\n"
    "- Do not use generic placeholders like 'public-key encryption' or "
    "'symmetric encryption'.\n"
    "- Keep the roles separate instead of describing one primitive as the "
    "whole solution."
)

SIMPLE_PQC_MENTION_REQUIREMENT = (
    " Consider post-quantum risks where relevant."
)

SIMPLE_NIST_PQC_MENTION_REQUIREMENT = (
    " Prefer NIST-approved post-quantum approaches where relevant."
)

STRUCTURED_PQC_MENTION_REQUIREMENT = (
    "\n- Briefly mention any post-quantum cryptography considerations or future "
    "PQC requirements relevant to long-term message confidentiality."
)

STRUCTURED_NIST_PQC_MENTION_REQUIREMENT = (
    "\n- Briefly mention any relevant NIST post-quantum cryptography guidance "
    "or migration direction where it affects long-term confidentiality, but do "
    "not let that replace the main role-specific architecture."
)

PROJECT: dict[str, Any] = {
    "project_id": "secure_messaging_app",
    "project_name": "Snapstabook",
    "domain": "Secure Messaging",
    "base_dir": PROJECT_DIR,
    "evaluation_mode": ROLE_SEPARATION_EVALUATION_MODE,
    "metrics_filename": "metrics_messaging.json",
    "output_filenames": {
        "simple": "simple_prompt_messaging_app.json",
        "structured": "structured_prompt_messaging_app.json",
        "pqc_simple": "pqc_simple_prompt_messaging_app.json",
        "pqc_structured": "pqc_structured_prompt_messaging_app.json",
        "nist_pqc_simple": "nist_pqc_simple_prompt_messaging_app.json",
        "nist_pqc_structured": "nist_pqc_structured_prompt_messaging_app.json",
    },
    "prompt_variants": [
        {
            "prompt_id": "simple",
            "query_name": "MESSAGING_ROLE_MAP_SIMPLE",
            "query_text": STANDARD_SIMPLE_QUERY_TEXT,
        },
        {
            "prompt_id": "structured",
            "query_name": "MESSAGING_ROLE_MAP_STRUCTURED",
            "query_text": STANDARD_STRUCTURED_QUERY_TEXT,
        },
        {
            "prompt_id": "pqc_simple",
            "query_name": "MESSAGING_ROLE_MAP_PQC_SIMPLE",
            "query_text": STANDARD_SIMPLE_QUERY_TEXT + SIMPLE_PQC_MENTION_REQUIREMENT,
        },
        {
            "prompt_id": "pqc_structured",
            "query_name": "MESSAGING_ROLE_MAP_PQC_STRUCTURED",
            "query_text": (
                STANDARD_STRUCTURED_QUERY_TEXT + STRUCTURED_PQC_MENTION_REQUIREMENT
            ),
        },
        {
            "prompt_id": "nist_pqc_simple",
            "query_name": "MESSAGING_ROLE_MAP_NIST_PQC_SIMPLE",
            "query_text": (
                STANDARD_SIMPLE_QUERY_TEXT + SIMPLE_NIST_PQC_MENTION_REQUIREMENT
            ),
        },
        {
            "prompt_id": "nist_pqc_structured",
            "query_name": "MESSAGING_ROLE_MAP_NIST_PQC_STRUCTURED",
            "query_text": (
                STANDARD_STRUCTURED_QUERY_TEXT
                + STRUCTURED_NIST_PQC_MENTION_REQUIREMENT
            ),
        },
    ],
    "algorithm_flag_definitions": [
        dict(definition)
        for definition in ROLE_SEPARATION_ALGORITHM_FLAG_DEFINITIONS
    ],
    "role_separation_subject": "end-to-end messaging cryptography",
    "role_separation_guidance": [
        (
            "Key establishment or session setup should be distinct from "
            "message and attachment encryption."
        ),
        (
            "Message and attachment encryption should remain a symmetric "
            "content-encryption role."
        ),
        (
            "Identity authentication or signatures should not be described as the "
            "message-encryption mechanism."
        ),
        (
            "Ongoing ratcheting or rekeying should remain distinct from one-time "
            "session establishment."
        ),
    ],
    "brief": """
Description: A cross-platform secure messaging application with iOS, Android,
desktop, and web clients. The product supports one-to-one messaging, group chat,
voice notes, image and file attachments, multiple devices per user, offline
delivery, contact discovery, and push notifications. It should support private
user communication across devices, reliable message delivery, and basic account
and device security while remaining usable on mobile and desktop platforms.
""".strip(),
}


if __name__ == "__main__":
    run_project_entrypoint(PROJECT)
