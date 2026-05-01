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
    "Recommend a cryptographic architecture for this clinical health system. "
    "Briefly explain what should be used and why."
)

STANDARD_STRUCTURED_QUERY_TEXT = (
    "You are designing the cryptographic architecture for a regulated "
    "clinical health system with web, mobile, APIs, databases, backups, "
    "and external integrations.\n\nRead the project brief and produce a "
    "structured design note.\n\nYour answer must use the following "
    "headings:\n"
    "1. Threat Model Assumptions\n"
    "2. Session Establishment for Clinical APIs and System Links\n"
    "3. PHI, API Payload, and Backup Encryption\n"
    "4. Machine and Service Identity Authentication\n"
    "5. Ongoing Key Rotation / Credential Lifecycle\n"
    "6. Residual Risks\n\n"
    "Requirements:\n"
    "- Assume attackers may record encrypted traffic today and that some "
    "patient-data confidentiality must hold for 10 to 15 years.\n"
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
    "PQC requirements relevant to long-term patient-data confidentiality."
)

STRUCTURED_NIST_PQC_MENTION_REQUIREMENT = (
    "\n- Briefly mention any relevant NIST post-quantum cryptography guidance "
    "or migration direction where it affects long-term patient-data "
    "confidentiality, but do not let that replace the main role-specific "
    "architecture."
)

PROJECT: dict[str, Any] = {
    "project_id": "hospital_patient_medication_tracking_app",
    "project_name": "Hospital Patient Health and Medication Tracking App",
    "domain": "Clinical health systems",
    "base_dir": PROJECT_DIR,
    "evaluation_mode": ROLE_SEPARATION_EVALUATION_MODE,
    "metrics_filename": "metrics_medication.json",
    "output_filenames": {
        "simple": "simple_medication_tracking_app.json",
        "structured": "structured_medication_tracking_app.json",
        "pqc_simple": "pqc_simple_medication_tracking_app.json",
        "pqc_structured": "pqc_structured_medication_tracking_app.json",
        "nist_pqc_simple": "nist_pqc_simple_medication_tracking_app.json",
        "nist_pqc_structured": "nist_pqc_structured_medication_tracking_app.json",
    },
    "prompt_variants": [
        {
            "prompt_id": "simple",
            "query_name": "MEDICATION_ROLE_MAP_SIMPLE",
            "query_text": STANDARD_SIMPLE_QUERY_TEXT,
        },
        {
            "prompt_id": "structured",
            "query_name": "MEDICATION_ROLE_MAP_STRUCTURED",
            "query_text": STANDARD_STRUCTURED_QUERY_TEXT,
        },
        {
            "prompt_id": "pqc_simple",
            "query_name": "MEDICATION_ROLE_MAP_PQC_SIMPLE",
            "query_text": STANDARD_SIMPLE_QUERY_TEXT + SIMPLE_PQC_MENTION_REQUIREMENT,
        },
        {
            "prompt_id": "pqc_structured",
            "query_name": "MEDICATION_ROLE_MAP_PQC_STRUCTURED",
            "query_text": (
                STANDARD_STRUCTURED_QUERY_TEXT + STRUCTURED_PQC_MENTION_REQUIREMENT
            ),
        },
        {
            "prompt_id": "nist_pqc_simple",
            "query_name": "MEDICATION_ROLE_MAP_NIST_PQC_SIMPLE",
            "query_text": (
                STANDARD_SIMPLE_QUERY_TEXT + SIMPLE_NIST_PQC_MENTION_REQUIREMENT
            ),
        },
        {
            "prompt_id": "nist_pqc_structured",
            "query_name": "MEDICATION_ROLE_MAP_NIST_PQC_STRUCTURED",
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
    "role_separation_subject": "clinical system cryptography",
    "role_separation_guidance": [
        (
            "Session establishment between clients, devices, services, or partner "
            "systems should be distinct from PHI, API payload, database, and backup "
            "encryption."
        ),
        (
            "PHI, API payload, database, and backup encryption should remain a "
            "symmetric data-encryption role."
        ),
        (
            "Machine, device, or service authentication and signatures should remain "
            "distinct from encryption."
        ),
        (
            "Ongoing key rotation, certificate lifecycle, or credential management "
            "should remain distinct from one-time session setup."
        ),
    ],
    "brief": """
Project name: TrackPatients.AI
Description: A hospital patient health and medication tracking platform used by
physicians, nurses, pharmacists, and administrators. The system stores patient
health records, diagnoses, medication orders, allergies, barcode medication
administration events, lab results, discharge notes, and audit records. It has
web and mobile clients, backend APIs, cloud-hosted databases, encrypted backups,
reporting dashboards, and integrations with EHR, pharmacy, and laboratory
systems. It should support routine clinical workflows, controlled access for
authorized staff, and basic protection for patient and medication data across
web, mobile, and backend systems.
""".strip(),
}


if __name__ == "__main__":
    run_project_entrypoint(PROJECT)
