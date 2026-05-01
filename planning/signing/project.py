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
    "Recommend a cryptographic architecture for this digital document signing "
    "platform. Briefly explain what should be used and why."
)

STANDARD_STRUCTURED_QUERY_TEXT = (
    "You are designing the cryptographic architecture for a digital "
    "document signing and approval platform with web, mobile, APIs, "
    "cloud storage, audit trails, and downloadable signed records.\n\n"
    "Read the project brief and produce a structured design note.\n\n"
    "Your answer must use the following headings:\n"
    "1. Threat Model Assumptions\n"
    "2. Session Establishment\n"
    "3. Document Signatures and Verification\n"
    "4. Document and Attachment Encryption\n"
    "5. Signer / Service Identity Authentication and Key Lifecycle\n"
    "6. Residual Risks\n\n"
    "Requirements:\n"
    "- Assume attackers may record encrypted traffic today and that signed "
    "records may need confidentiality and verifiability for 10 to 15 years.\n"
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
    "PQC requirements relevant to long-term confidentiality or verification of "
    "signed records."
)

STRUCTURED_NIST_PQC_MENTION_REQUIREMENT = (
    "\n- Briefly mention any relevant NIST post-quantum cryptography guidance "
    "or migration direction where it affects long-term confidentiality or "
    "verification of signed records, but do not let that replace the main "
    "role-specific architecture."
)

PROJECT: dict[str, Any] = {
    "project_id": "digital_document_signing_platform",
    "project_name": "Digital Document Signing and Approval Platform",
    "domain": "Digital agreements, identity, and document workflow security",
    "base_dir": PROJECT_DIR,
    "evaluation_mode": ROLE_SEPARATION_EVALUATION_MODE,
    "metrics_filename": "metrics_signing.json",
    "output_filenames": {
        "simple": "simple_document_signing_platform.json",
        "structured": "structured_document_signing_platform.json",
        "pqc_simple": "pqc_simple_document_signing_platform.json",
        "pqc_structured": "pqc_structured_document_signing_platform.json",
        "nist_pqc_simple": "nist_pqc_simple_document_signing_platform.json",
        "nist_pqc_structured": "nist_pqc_structured_document_signing_platform.json",
    },
    "prompt_variants": [
        {
            "prompt_id": "simple",
            "query_name": "SIGNING_ROLE_MAP_SIMPLE",
            "query_text": STANDARD_SIMPLE_QUERY_TEXT,
        },
        {
            "prompt_id": "structured",
            "query_name": "SIGNING_ROLE_MAP_STRUCTURED",
            "query_text": STANDARD_STRUCTURED_QUERY_TEXT,
        },
        {
            "prompt_id": "pqc_simple",
            "query_name": "SIGNING_ROLE_MAP_PQC_SIMPLE",
            "query_text": STANDARD_SIMPLE_QUERY_TEXT + SIMPLE_PQC_MENTION_REQUIREMENT,
        },
        {
            "prompt_id": "pqc_structured",
            "query_name": "SIGNING_ROLE_MAP_PQC_STRUCTURED",
            "query_text": (
                STANDARD_STRUCTURED_QUERY_TEXT + STRUCTURED_PQC_MENTION_REQUIREMENT
            ),
        },
        {
            "prompt_id": "nist_pqc_simple",
            "query_name": "SIGNING_ROLE_MAP_NIST_PQC_SIMPLE",
            "query_text": (
                STANDARD_SIMPLE_QUERY_TEXT + SIMPLE_NIST_PQC_MENTION_REQUIREMENT
            ),
        },
        {
            "prompt_id": "nist_pqc_structured",
            "query_name": "SIGNING_ROLE_MAP_NIST_PQC_STRUCTURED",
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
    "role_separation_subject": "document signing and approval cryptography",
    "role_separation_guidance": [
        (
            "Session establishment between clients and services should be distinct "
            "from document-signing and signature-verification roles."
        ),
        (
            "Document signatures should remain an authenticity, integrity, and "
            "non-repudiation role rather than a confidentiality mechanism."
        ),
        (
            "Document, attachment, and transport encryption should remain a "
            "symmetric content-encryption role."
        ),
        (
            "Signer, device, or service identity authentication and key lifecycle "
            "management should remain distinct from both signing and encryption."
        ),
    ],
    "brief": """
Project name: Sign-o-Doc
Description: A cloud-based digital document signing and approval platform similar
to DocuSign. Businesses use it to prepare, send, review, approve, and sign
contracts, HR forms, procurement approvals, NDAs, and regulated disclosures.
The system includes web and mobile clients, reusable templates, multi-party
signing order, delegated signing, downloadable signed PDFs, audit trails,
identity verification steps, admin controls, APIs and webhooks, cloud storage,
and integrations with CRM, HR, and document management systems. It should
support tamper-evident signed documents, reliable signer attribution, and
verifiable records over long retention periods.
""".strip(),
}


if __name__ == "__main__":
    run_project_entrypoint(PROJECT)
