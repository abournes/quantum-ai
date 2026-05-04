from __future__ import annotations

import json
import os
import platform
import random
import re
import statistics
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from openai import (
    APIConnectionError,
    APIError,
    APITimeoutError,
    InternalServerError,
    OpenAI,
    RateLimitError,
)

BASE_DIR = Path(__file__).resolve().parent

API_KEY = os.environ.get("OPENAI_API_KEY", "")
NUM_SAMPLES_PER_MODEL = 5
MODELS_UNDER_TEST = ["gpt-4.1-mini"]
EVALUATOR_MODEL = "gpt-4.1-mini"
MAX_PARALLEL_SAMPLES = 5
REQUEST_TIMEOUT_SECONDS = 120.0
MAX_API_ATTEMPTS = 4
INITIAL_RETRY_DELAY_SECONDS = 2.0
RETRY_JITTER_SECONDS = 0.5

STUDY_ID = "nist-pqc-application-recommendation-benchmark"
PROMPT_VERSION = "2026-04-29-a"
RUBRIC_VERSION = "nist-pqc-benchmark-v5"

PROMPT_VARIANT_LABELS = {
    "simple": "Standard Simple",
    "structured": "Standard Structured",
    "pqc_simple": "PQC Simple",
    "pqc_structured": "PQC Structured",
    "nist_pqc_simple": "NIST-Aware PQC Simple",
    "nist_pqc_structured": "NIST-Aware PQC Structured",
}

METRIC_EVALUATION_MODE = "project_specific_metrics"
ROLE_SEPARATION_EVALUATION_MODE = "role_separation_algorithm_flags"
LEGACY_MESSAGING_ROLE_SEPARATION_MODE = "messaging_role_separation"

CURRENT_NIST_KEM_KEYWORDS = [
    "ml-kem",
    "ml kem",
    "fips 203",
    "fips-203",
    "kyber",
    "crystals-kyber",
    "crystals kyber",
]
CURRENT_NIST_SIGNATURE_KEYWORDS = [
    "ml-dsa",
    "ml dsa",
    "fips 204",
    "fips-204",
    "dilithium",
    "crystals-dilithium",
    "crystals dilithium",
    "slh-dsa",
    "slh dsa",
    "fips 205",
    "fips-205",
    "sphincs",
    "sphincs+",
    "sphincs plus",
]
OTHER_PQC_SAFE_KEYWORDS = [
    "bike",
    "hqc",
    "classic mceliece",
    "mceliece",
    "ntru",
    "falcon",
    "fn-dsa",
    "fn dsa",
    "fips 206",
    "fips-206",
]
PQC_GENERAL_KEYWORDS = [
    "post-quantum",
    "post quantum",
    "quantum-safe",
    "quantum safe",
    "quantum-resistant",
    "quantum resistant",
    "pqc",
    *CURRENT_NIST_KEM_KEYWORDS,
    *CURRENT_NIST_SIGNATURE_KEYWORDS,
    *OTHER_PQC_SAFE_KEYWORDS,
]
CURRENT_NIST_FLAG_BY_FAMILY = {
    "kem": "uses_current_nist_kem_names",
    "signature": "uses_current_nist_signature_names",
}

PROJECT_DIAGNOSTIC_FLAGS = {
    "uses_current_nist_kem_names",
    "uses_current_nist_signature_names",
    "uses_legacy_or_non_nist_pqc_names",
    "mentions_any_pqc",
    "migration_or_interoperability_present",
    "has_pqc_role_confusion",
}

ASSESSMENT_CREDIT = {
    "met": 1.0,
    "partial": 0.5,
    "absent": 0.0,
    "contradicted": 0.0,
}

SIMPLE_QUERY = """
Recommend an encryption scheme that should be used for this app.
Make sure it adheres to the necessary standards for the app.
""".strip()

STRUCTURED_NEUTRAL_QUERY = """
You are a security architect.

Read the project brief and produce a structured security plan for this system.

Your answer must use the following headings:
1. System Assumptions
2. Recommended Security Architecture
3. Technical Recommendations
4. Operational Considerations
5. Migration and Compatibility
6. Residual Risks

Requirements:
- Name concrete standards, protocols, or algorithms whenever you recommend one.
- Explain what each recommendation protects.
- Tailor the answer to the project's needs and operating environment.
- Do not give a generic one-paragraph answer.
""".strip()

PROJECT_EVALUATION_MODES = {
    METRIC_EVALUATION_MODE,
    ROLE_SEPARATION_EVALUATION_MODE,
    LEGACY_MESSAGING_ROLE_SEPARATION_MODE,
}

ROLE_SEPARATION_EVALUATION_MODES = {
    ROLE_SEPARATION_EVALUATION_MODE,
    LEGACY_MESSAGING_ROLE_SEPARATION_MODE,
}

ROLE_SEPARATION_STATUS_ORDER = ["pass", "fail", "unclear"]
ROLE_SEPARATION_STATUSES = set(ROLE_SEPARATION_STATUS_ORDER)

ROLE_SEPARATION_ALGORITHM_CATALOG: dict[str, dict[str, Any]] = {
    "kem_current_nist": {
        "flag_id": "kem_has_current_nist_pqc",
        "labels": {
            "ML-KEM": ["ml-kem", "ml kem"],
            "FIPS 203": ["fips 203", "fips-203"],
            "Kyber": ["kyber", "crystals-kyber", "crystals kyber"],
        },
    },
    "kem_legacy_or_non_nist": {
        "flag_id": "kem_has_legacy_or_non_nist_pqc",
        "labels": {
            "HQC": ["hqc"],
            "BIKE": ["bike"],
            "Classic McEliece": ["classic mceliece", "mceliece"],
            "NTRU": ["ntru"],
        },
    },
    "kem_classical": {
        "flag_id": "kem_has_classical",
        "labels": {
            "X3DH": [
                "x3dh",
                "extended triple diffie-hellman",
                "extended triple diffie hellman",
            ],
            "X25519": ["x25519"],
            "X448": ["x448"],
            "ECDH": ["ecdh"],
            "ECDHE": ["ecdhe"],
            "Curve25519": ["curve25519"],
            "P-256": ["p-256", "nist p-256", "secp256r1"],
            "RSA Key Exchange": ["rsa key exchange"],
        },
    },
    "signature_current_nist": {
        "flag_id": "signature_has_current_nist_pqc",
        "labels": {
            "ML-DSA": ["ml-dsa", "ml dsa"],
            "FIPS 204": ["fips 204", "fips-204"],
            "Dilithium": ["dilithium", "crystals-dilithium", "crystals dilithium"],
            "SLH-DSA": ["slh-dsa", "slh dsa"],
            "FIPS 205": ["fips 205", "fips-205"],
            "SPHINCS+": ["sphincs", "sphincs+", "sphincs plus"],
        },
    },
    "signature_legacy_or_non_nist": {
        "flag_id": "signature_has_legacy_or_non_nist_pqc",
        "labels": {
            "Falcon": ["falcon", "fn-dsa", "fn dsa", "fips 206", "fips-206"],
        },
    },
    "signature_classical": {
        "flag_id": "signature_has_classical",
        "labels": {
            "Ed25519": ["ed25519"],
            "ECDSA": ["ecdsa"],
            "RSA": ["rsa"],
            "RSA-PSS": ["rsa-pss"],
        },
    },
    "dem_quantum_resistant_symmetric": {
        "flag_id": "dem_has_quantum_resistant_symmetric",
        "labels": {
            "AES-256-GCM": ["aes-256-gcm"],
            "AES-256-GCM-SIV": ["aes-256-gcm-siv"],
            "AES-256": ["aes-256"],
            "ChaCha20-Poly1305": ["chacha20-poly1305"],
            "XChaCha20-Poly1305": ["xchacha20-poly1305"],
        },
    },
    "dem_non_quantum_resistant_symmetric": {
        "flag_id": "dem_has_non_quantum_resistant_symmetric",
        "labels": {
            "AES-128-GCM": ["aes-128-gcm"],
            "AES-128-CCM": ["aes-128-ccm"],
            "AES-128": ["aes-128"],
        },
    },
}

ROLE_SEPARATION_ALGORITHM_FLAG_DEFINITIONS: list[dict[str, str]] = [
    {
        "flag_id": "kem_has_current_nist_pqc",
        "label": "Approved PQC KEM Family",
        "description": (
            "Whether the response names the approved NIST PQC KEM family for key "
            "establishment, including ML-KEM / FIPS 203 and Kyber family aliases."
        ),
    },
    {
        "flag_id": "kem_has_legacy_or_non_nist_pqc",
        "label": "Other PQC-Safe KEM Family",
        "description": (
            "Whether the response names other PQC-safe KEM families such as HQC, "
            "BIKE, Classic McEliece, or NTRU."
        ),
    },
    {
        "flag_id": "kem_has_classical",
        "label": "Classical KEM",
        "description": (
            "Whether the response names classical key-establishment choices such "
            "as X3DH, X25519, ECDH, or RSA key exchange."
        ),
    },
    {
        "flag_id": "signature_has_current_nist_pqc",
        "label": "Approved PQC Signature Family",
        "description": (
            "Whether the response names approved NIST PQC signature families, "
            "including ML-DSA / FIPS 204 / Dilithium and SLH-DSA / FIPS 205 / "
            "SPHINCS+."
        ),
    },
    {
        "flag_id": "signature_has_legacy_or_non_nist_pqc",
        "label": "Other PQC-Safe Signature Family",
        "description": (
            "Whether the response names other PQC-safe signature families such as "
            "Falcon / FN-DSA."
        ),
    },
    {
        "flag_id": "signature_has_classical",
        "label": "Classical Signature",
        "description": (
            "Whether the response names classical signature choices such as "
            "Ed25519, ECDSA, or RSA-PSS."
        ),
    },
    {
        "flag_id": "dem_has_quantum_resistant_symmetric",
        "label": "Strong Symmetric DEM",
        "description": (
            "Whether the response names strong symmetric bulk-encryption or "
            "content-encryption choices such as AES-256-GCM or ChaCha20-Poly1305."
        ),
    },
    {
        "flag_id": "dem_has_non_quantum_resistant_symmetric",
        "label": "Weak / Short-Key Symmetric DEM",
        "description": (
            "Whether the response names weaker or shorter-key symmetric "
            "bulk-encryption or content-encryption choices such as AES-128-GCM."
        ),
    },
]

ROLE_SEPARATION_ALGORITHM_FLAG_IDS = tuple(
    entry["flag_id"] for entry in ROLE_SEPARATION_ALGORITHM_FLAG_DEFINITIONS
)

ROLE_SEPARATION_REQUIRED_ALGORITHM_GROUPS: dict[str, tuple[str, ...]] = {
    "key establishment": (
        "kem_has_current_nist_pqc",
        "kem_has_legacy_or_non_nist_pqc",
        "kem_has_classical",
    ),
    "content encryption": (
        "dem_has_quantum_resistant_symmetric",
        "dem_has_non_quantum_resistant_symmetric",
    ),
    "authentication or signatures": (
        "signature_has_current_nist_pqc",
        "signature_has_legacy_or_non_nist_pqc",
        "signature_has_classical",
    ),
}

NIST_PQC_BASELINE = """
Use this baseline when evaluating the model response.

As of April 19, 2026:
- FIPS 203 standardizes ML-KEM for key encapsulation / key establishment.
- FIPS 204 standardizes ML-DSA for digital signatures.
- FIPS 205 standardizes SLH-DSA for digital signatures.
- SP 800-227 provides recommendations for key-encapsulation mechanisms.
- Falcon is being standardized separately as FN-DSA / FIPS 206 and should be
  treated as an alternative PQC-safe signature family rather than a negative
  signal.

Important interpretation rule:
- Strong answers should distinguish post-quantum key establishment and digital
  signatures from bulk encryption. They should not misdescribe ML-KEM, ML-DSA,
  or SLH-DSA as drop-in bulk data encryption algorithms for databases or stored
  message bodies.
- Family aliases such as Kyber, Dilithium, and SPHINCS+ should count as
  approved or safe references to the standardized NIST algorithm families.
- Other PQC-safe algorithms such as Falcon / FN-DSA, HQC, BIKE, Classic
  McEliece, and NTRU should be tracked as alternative PQC-safe families rather
  than as negative-quality signals.
""".strip()

RETRYABLE_OPENAI_EXCEPTIONS = (
    APIConnectionError,
    APITimeoutError,
    InternalServerError,
    RateLimitError,
)


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def create_client() -> OpenAI:
    if not API_KEY:
        raise ValueError(
            "OPENAI_API_KEY is empty. Export it before running the study."
        )
    return OpenAI(
        api_key=API_KEY,
        timeout=REQUEST_TIMEOUT_SECONDS,
        max_retries=0,
    )


def get_openai_package_version() -> str | None:
    try:
        return version("openai")
    except PackageNotFoundError:
        return None


def get_text_response(response: Any) -> str:
    text = getattr(response, "output_text", "")
    if not text:
        raise ValueError("Model response did not include output_text.")
    return text.strip()


def parse_json_object(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(0))


def safe_mean(values: list[float]) -> float | None:
    if not values:
        return None
    return round(statistics.fmean(values), 3)


def safe_weighted_average(
    value_weight_pairs: list[tuple[float | None, int | float]],
) -> float | None:
    usable_pairs = [
        (value, weight)
        for value, weight in value_weight_pairs
        if value is not None and weight > 0
    ]
    if not usable_pairs:
        return None

    weighted_sum = sum(value * weight for value, weight in usable_pairs)
    total_weight = sum(weight for _, weight in usable_pairs)
    if total_weight == 0:
        return None
    return round(weighted_sum / total_weight, 3)


def contains_any(text: str, keywords: list[str]) -> bool:
    return any(keyword.lower() in text for keyword in keywords)


def is_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1", "present"}
    return False


def normalize_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def project_evaluation_mode(project: dict[str, Any]) -> str:
    return str(project.get("evaluation_mode", METRIC_EVALUATION_MODE)).strip()


def is_role_separation_evaluation_mode(value: Any) -> bool:
    return str(value).strip() in ROLE_SEPARATION_EVALUATION_MODES


def is_role_separation_project(project: dict[str, Any]) -> bool:
    return is_role_separation_evaluation_mode(project_evaluation_mode(project))


def is_messaging_project(project: dict[str, Any]) -> bool:
    return is_role_separation_project(project)


def is_messaging_evaluation_mode(value: Any) -> bool:
    return is_role_separation_evaluation_mode(value)


def prompt_variants_for_project(project: dict[str, Any]) -> list[dict[str, str]]:
    prompt_variants = project.get("prompt_variants", [])
    return [dict(prompt_variant) for prompt_variant in prompt_variants]


def project_base_dir(project: dict[str, Any]) -> Path:
    base_dir = project.get("base_dir")
    if not base_dir:
        return BASE_DIR
    return Path(base_dir)


def project_file_path(project: dict[str, Any], filename: str) -> Path:
    return project_base_dir(project) / filename


def algorithm_flag_definitions(project: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "flag_id": str(definition["flag_id"]),
            "label": str(definition["label"]),
            "description": str(definition["description"]),
        }
        for definition in project.get("algorithm_flag_definitions", [])
    ]


def role_separation_subject(project: dict[str, Any]) -> str:
    return str(project.get("role_separation_subject", "")).strip()


def role_separation_guidance(project: dict[str, Any]) -> list[str]:
    return normalize_string_list(project.get("role_separation_guidance", []))


def expected_report_filenames(project: dict[str, Any]) -> list[str]:
    return [
        project["output_filenames"][prompt_variant["prompt_id"]]
        for prompt_variant in prompt_variants_for_project(project)
    ]


def prompt_variant_for_output_filename(
    project: dict[str, Any],
    filename: str,
) -> dict[str, str]:
    for prompt_variant in prompt_variants_for_project(project):
        if project["output_filenames"][prompt_variant["prompt_id"]] == filename:
            return dict(prompt_variant)
    raise ValueError(
        f"Project {project['project_id']} has no prompt variant for {filename}."
    )


def metric_ids(project: dict[str, Any]) -> list[str]:
    return [
        metric["metric_id"]
        for metric in project.get("metric_definitions", [])
    ]


def metric_metadata(project: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "metric_id": metric["metric_id"],
            "label": metric["label"],
            "description": metric["description"],
        }
        for metric in project.get("metric_definitions", [])
    ]


def prompt_variant_label(prompt_variant: str) -> str:
    return PROMPT_VARIANT_LABELS.get(
        prompt_variant,
        prompt_variant.replace("_", " ").title(),
    )


def current_nist_flag_name(family: str) -> str:
    return CURRENT_NIST_FLAG_BY_FAMILY[family]


def build_sample_status_summary(samples: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "total_runs": len(samples),
        "complete_runs": sum(1 for sample in samples if sample["status"] == "complete"),
        "partial_runs": sum(1 for sample in samples if sample["status"] == "partial"),
        "error_runs": sum(1 for sample in samples if sample["status"] == "error"),
        "models_tested": sorted({sample["model"] for sample in samples}),
    }


def build_trial_status_counts(trial_metrics: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "sample_count": sum(trial["sample_count"] for trial in trial_metrics),
        "complete_sample_count": sum(
            trial["complete_sample_count"] for trial in trial_metrics
        ),
        "partial_sample_count": sum(
            trial["partial_sample_count"] for trial in trial_metrics
        ),
        "error_sample_count": sum(
            trial["error_sample_count"] for trial in trial_metrics
        ),
    }


def validate_metric_definition(
    project_id: str,
    metric_definition: dict[str, Any],
    requirement_ids: set[str],
) -> None:
    metric_id = metric_definition.get("metric_id")
    if not metric_id:
        raise ValueError(f"Project {project_id} has a metric without metric_id.")

    score_source = metric_definition.get("score_source", {})
    source_type = score_source.get("type")
    if source_type not in {
        "criterion",
        "criteria_average",
        "current_nist_name",
        "avoid_legacy_or_non_nist_names",
    }:
        raise ValueError(
            f"Project {project_id} metric {metric_id} has unsupported "
            f"score_source type: {source_type}"
        )

    if source_type == "criterion":
        criterion_id = score_source.get("criterion_id")
        if criterion_id not in requirement_ids:
            raise ValueError(
                f"Project {project_id} metric {metric_id} references unknown "
                f"criterion_id: {criterion_id}"
            )

    if source_type == "criteria_average":
        criterion_ids = score_source.get("criterion_ids", [])
        if not criterion_ids:
            raise ValueError(
                f"Project {project_id} metric {metric_id} must define criterion_ids."
            )
        unknown_ids = sorted(set(criterion_ids) - requirement_ids)
        if unknown_ids:
            raise ValueError(
                f"Project {project_id} metric {metric_id} references unknown "
                f"criterion_ids: {unknown_ids}"
            )

    if source_type in {"current_nist_name", "avoid_legacy_or_non_nist_names"}:
        family = score_source.get("family")
        if family not in {"kem", "signature"}:
            raise ValueError(
                f"Project {project_id} metric {metric_id} must define family "
                f"as 'kem' or 'signature'."
            )


def validate_prompt_configuration(
    project_id: str,
    project: dict[str, Any],
) -> None:
    output_filenames = project.get("output_filenames", {})
    if not isinstance(output_filenames, dict):
        raise ValueError(f"Project {project_id} must define output_filenames as a dict.")

    prompt_variants = prompt_variants_for_project(project)
    if not prompt_variants:
        raise ValueError(f"Project {project_id} must define at least one prompt variant.")

    prompt_ids: list[str] = []
    expected_filenames: list[str] = []
    for prompt_variant in prompt_variants:
        prompt_id = str(prompt_variant.get("prompt_id", "")).strip()
        query_name = str(prompt_variant.get("query_name", "")).strip()
        query_text = str(prompt_variant.get("query_text", "")).strip()
        if not prompt_id:
            raise ValueError(f"Project {project_id} has a prompt variant without prompt_id.")
        if not query_name:
            raise ValueError(
                f"Project {project_id} prompt variant {prompt_id} is missing query_name."
            )
        if not query_text:
            raise ValueError(
                f"Project {project_id} prompt variant {prompt_id} is missing query_text."
            )
        prompt_ids.append(prompt_id)

        output_filename = output_filenames.get(prompt_id)
        if not output_filename:
            raise ValueError(
                f"Project {project_id} is missing an output filename for {prompt_id}."
            )
        output_filename = str(output_filename)
        if not output_filename.endswith(".json"):
            raise ValueError(
                f"Output filename {output_filename} must end with .json."
            )
        expected_filenames.append(output_filename)

    if len(set(prompt_ids)) != len(prompt_ids):
        raise ValueError(f"Project {project_id} has duplicate prompt ids.")
    if len(set(expected_filenames)) != len(expected_filenames):
        raise ValueError(f"Project {project_id} has duplicate output filenames.")

    unknown_output_prompt_ids = sorted(set(output_filenames) - set(prompt_ids))
    if unknown_output_prompt_ids:
        raise ValueError(
            f"Project {project_id} has output_filenames entries without matching "
            f"prompt variants: {unknown_output_prompt_ids}"
        )


def validate_metric_project(project_id: str, project: dict[str, Any]) -> None:
    nist_family = project.get("nist_family")
    if nist_family not in {"kem", "signature"}:
        raise ValueError(
            f"Project {project_id} must define nist_family as 'kem' or 'signature'."
        )

    project_specific_requirements = project.get("project_specific_requirements", [])
    if not project_specific_requirements:
        raise ValueError(
            f"Project {project_id} must define project_specific_requirements."
        )

    requirement_ids = [
        requirement["criterion_id"]
        for requirement in project_specific_requirements
    ]
    if len(set(requirement_ids)) != len(requirement_ids):
        raise ValueError(f"Project {project_id} has duplicate criterion ids.")

    metric_definitions = project.get("metric_definitions", [])
    if not metric_definitions:
        raise ValueError(f"Project {project_id} must define metric_definitions.")

    ids = metric_ids(project)
    if len(set(ids)) != len(ids):
        raise ValueError(f"Project {project_id} has duplicate metric ids.")

    requirement_id_set = set(requirement_ids)
    for metric_definition in metric_definitions:
        validate_metric_definition(project_id, metric_definition, requirement_id_set)


def validate_role_separation_project(project_id: str, project: dict[str, Any]) -> None:
    if "prompt_variants" not in project:
        raise ValueError(
            f"Project {project_id} must define prompt_variants for role-separation mode."
        )

    diagnostic_dimensions = project.get("diagnostic_dimensions", [])
    if diagnostic_dimensions:
        raise ValueError(
            f"Project {project_id} should not define diagnostic_dimensions in "
            "role-separation mode."
        )

    algorithm_definitions = algorithm_flag_definitions(project)
    if not algorithm_definitions:
        raise ValueError(
            f"Project {project_id} must define algorithm_flag_definitions."
        )

    algorithm_flag_ids = [definition["flag_id"] for definition in algorithm_definitions]
    if len(set(algorithm_flag_ids)) != len(algorithm_flag_ids):
        raise ValueError(f"Project {project_id} has duplicate algorithm flag ids.")

    expected_flag_ids = set(ROLE_SEPARATION_ALGORITHM_FLAG_IDS)
    configured_flag_ids = set(algorithm_flag_ids)
    if configured_flag_ids != expected_flag_ids:
        missing_flag_ids = sorted(expected_flag_ids - configured_flag_ids)
        unexpected_flag_ids = sorted(configured_flag_ids - expected_flag_ids)
        problems: list[str] = []
        if missing_flag_ids:
            problems.append(f"missing {missing_flag_ids}")
        if unexpected_flag_ids:
            problems.append(f"unexpected {unexpected_flag_ids}")
        raise ValueError(
            f"Project {project_id} algorithm_flag_definitions do not match the "
            f"role-separation evaluator catalog: {', '.join(problems)}"
        )

    if not role_separation_subject(project):
        raise ValueError(
            f"Project {project_id} must define role_separation_subject."
        )

    guidance = role_separation_guidance(project)
    if not guidance:
        raise ValueError(
            f"Project {project_id} must define non-empty role_separation_guidance."
        )


def validate_project(project: dict[str, Any]) -> None:
    if NUM_SAMPLES_PER_MODEL < 1:
        raise ValueError("NUM_SAMPLES_PER_MODEL must be at least 1.")
    if MAX_PARALLEL_SAMPLES < 1:
        raise ValueError("MAX_PARALLEL_SAMPLES must be at least 1.")
    if MAX_API_ATTEMPTS < 1:
        raise ValueError("MAX_API_ATTEMPTS must be at least 1.")
    if REQUEST_TIMEOUT_SECONDS <= 0:
        raise ValueError("REQUEST_TIMEOUT_SECONDS must be greater than 0.")
    if not MODELS_UNDER_TEST:
        raise ValueError("MODELS_UNDER_TEST is empty. Add at least one model.")

    project_id = project.get("project_id")
    if not project_id:
        raise ValueError("Each project must define project_id.")

    for required_field in ["project_name", "domain", "brief"]:
        if not str(project.get(required_field, "")).strip():
            raise ValueError(
                f"Project {project_id} must define a non-empty {required_field}."
            )

    evaluation_mode = project_evaluation_mode(project)
    if evaluation_mode not in PROJECT_EVALUATION_MODES:
        raise ValueError(
            f"Project {project_id} has unsupported evaluation_mode: {evaluation_mode}."
        )

    metrics_filename = project.get("metrics_filename")
    if not metrics_filename or not str(metrics_filename).endswith(".json"):
        raise ValueError(f"Project {project_id} must define a .json metrics_filename.")

    diagnostic_dimensions = project.get("diagnostic_dimensions", [])
    unknown_diagnostic_dimensions = sorted(
        set(diagnostic_dimensions) - PROJECT_DIAGNOSTIC_FLAGS
    )
    if unknown_diagnostic_dimensions:
        raise ValueError(
            f"Project {project_id} has unknown diagnostic_dimensions: "
            f"{unknown_diagnostic_dimensions}"
        )

    if evaluation_mode == METRIC_EVALUATION_MODE:
        validate_metric_project(project_id, project)
    else:
        validate_role_separation_project(project_id, project)

    validate_prompt_configuration(project_id, project)


def build_study_metadata(project: dict[str, Any]) -> dict[str, Any]:
    evaluation_mode = project_evaluation_mode(project)
    if is_role_separation_evaluation_mode(evaluation_mode):
        rubric_scope = (
            "Role separation plus algorithm-selection flags under the NIST PQC baseline"
        )
    else:
        rubric_scope = "PQC/NIST-only, project-specific metrics"

    return {
        "study_id": STUDY_ID,
        "generated_at_utc": now_utc_iso(),
        "prompt_version": PROMPT_VERSION,
        "rubric_version": RUBRIC_VERSION,
        "rubric_scope": rubric_scope,
        "evaluation_mode": evaluation_mode,
        "prompt_variants": [
            {
                "prompt_id": prompt_variant["prompt_id"],
                "query_name": prompt_variant["query_name"],
                "query_text": prompt_variant["query_text"],
            }
            for prompt_variant in prompt_variants_for_project(project)
        ],
        "num_samples_per_model": NUM_SAMPLES_PER_MODEL,
        "models_under_test": MODELS_UNDER_TEST,
        "evaluator_model": EVALUATOR_MODEL,
        "python_version": sys.version,
        "platform": platform.platform(),
        "openai_package_version": get_openai_package_version(),
        "nist_pqc_baseline": {
            "last_reviewed": "2026-04-19",
            "references": [
                {
                    "standard": "FIPS 203",
                    "algorithm": "ML-KEM",
                    "role": "key establishment / KEM",
                    "published": "2024-08-13",
                },
                {
                    "standard": "FIPS 204",
                    "algorithm": "ML-DSA",
                    "role": "digital signatures",
                    "published": "2024-08-13",
                },
                {
                    "standard": "FIPS 205",
                    "algorithm": "SLH-DSA",
                    "role": "digital signatures",
                    "published": "2024-08-13",
                },
                {
                    "publication": "SP 800-227",
                    "role": "KEM usage guidance",
                    "published": "2025-09",
                },
            ],
        },
    }


def build_recommendation_prompt(
    project: dict[str, Any],
    query_text: str,
) -> str:
    return f"""
{query_text}

Project name:
{project["project_name"]}

Project domain:
{project["domain"]}

Project brief:
{project["brief"]}
""".strip()


def should_retry_exception(exc: Exception) -> bool:
    if isinstance(exc, RETRYABLE_OPENAI_EXCEPTIONS):
        return True
    if isinstance(exc, APIError):
        status_code = getattr(exc, "status_code", None)
        return status_code is None or status_code >= 500
    return False


def get_retry_delay_seconds(attempt_number: int) -> float:
    base_delay = INITIAL_RETRY_DELAY_SECONDS * (2 ** (attempt_number - 1))
    jitter = random.uniform(0, RETRY_JITTER_SECONDS)
    return round(base_delay + jitter, 2)


def call_with_retries(
    operation: Any,
    request_label: str,
) -> tuple[Any, int]:
    for attempt_number in range(1, MAX_API_ATTEMPTS + 1):
        try:
            return operation(), attempt_number
        except Exception as exc:
            if not should_retry_exception(exc) or attempt_number == MAX_API_ATTEMPTS:
                raise

            delay_seconds = get_retry_delay_seconds(attempt_number)
            print(
                f"    Retrying {request_label} after {type(exc).__name__} "
                f"(attempt {attempt_number}/{MAX_API_ATTEMPTS}) in "
                f"{delay_seconds:.2f}s"
            )
            time.sleep(delay_seconds)


def get_recommendation(
    client: OpenAI,
    project: dict[str, Any],
    model: str,
    query_text: str,
) -> tuple[str, str]:
    prompt = build_recommendation_prompt(project, query_text)
    response = client.responses.create(
        model=model,
        input=prompt,
    )
    return get_text_response(response), prompt


def format_project_specific_requirements(project: dict[str, Any]) -> str:
    return "\n".join(
        f"- {requirement['criterion_id']}: {requirement['description']}"
        for requirement in project["project_specific_requirements"]
    )


def build_project_specific_extraction_prompt(
    project: dict[str, Any],
    recommendation: str,
) -> str:
    project_specific_requirements = format_project_specific_requirements(project)

    return f"""
You are extracting only PQC/NIST-specific findings from one model response for a
research benchmark. Do not score general security quality. Only extract details
needed to evaluate approved NIST PQC family naming, alternative PQC-safe family
naming, PQC role confusion, and the project-specific PQC criteria.

{NIST_PQC_BASELINE}

Project:
{project["project_name"]}

Project brief:
{project["brief"]}

Model response:
{recommendation}

Return JSON only with the following shape:
{{
  "response_type": "substantive | refusal | unclear",
  "named_pqc_items": ["..."],
  "pqc_controls": {{
    "key_establishment": ["..."],
    "digital_signatures": ["..."],
    "migration_or_interoperability": ["..."],
    "role_separation": ["..."],
    "other_pqc": ["..."]
  }},
  "other_pqc_safe_names_used": ["..."],
  "possible_role_confusions": ["..."],
  "normalized_pqc_findings": {{
    "uses_current_nist_kem_names": true,
    "uses_current_nist_signature_names": true,
    "uses_legacy_or_non_nist_pqc_names": true,
    "has_pqc_role_confusion": false,
    "mentions_any_pqc": true,
    "migration_or_interoperability_present": true
  }},
  "project_specific_findings": [
    {{
      "criterion_id": "...",
      "assessment": "met | partial | absent | contradicted",
      "evidence": ["..."],
      "notes": "..."
    }}
  ],
  "concise_pqc_summary": "..."
}}

Project-specific PQC criteria to assess in the extraction:
{project_specific_requirements}

Extraction rules:
- Include every project-specific criterion exactly once in project_specific_findings.
- Treat approved NIST PQC family references flexibly: ML-KEM / FIPS 203 /
  Kyber for KEMs, ML-DSA / FIPS 204 / Dilithium and SLH-DSA / FIPS 205 /
  SPHINCS+ for signatures.
- Mark other PQC-safe family names when the response uses Falcon / FN-DSA, HQC,
  BIKE, Classic McEliece, NTRU, or similar alternative PQC-safe families.
- Do not assign broad security scores or evaluate general architecture quality.
""".strip()


def format_role_separation_guidance(project: dict[str, Any]) -> str:
    return "\n".join(
        f"- {guidance_item}"
        for guidance_item in role_separation_guidance(project)
    )


def build_role_separation_extraction_prompt(
    project: dict[str, Any],
    recommendation: str,
) -> str:
    guidance_text = format_role_separation_guidance(project)

    return f"""
You are evaluating only protocol-role separation for one model response in a
research benchmark about {role_separation_subject(project)}. Do not score overall security
quality. Do not grade whether the chosen algorithms are modern or standards
aligned. Only determine whether the response keeps the major cryptographic roles
separate and coherent for this system design.

Project:
{project["project_name"]}

Project brief:
{project["brief"]}

Model response:
{recommendation}

Project-specific role-separation guidance:
{guidance_text}

Return JSON only with the following shape:
{{
  "response_type": "substantive | refusal | unclear",
  "role_separation_status": "pass | fail | unclear",
  "role_separation_evidence": ["..."],
  "role_separation_notes": "...",
  "concise_summary": "..."
}}

Judging rules:
- Use "pass" when the response keeps the major roles distinct and does not
  collapse the system into one primitive or violate the project-specific
  guidance.
- Use "fail" when the response conflates roles, such as using a KEM for bulk
  content/data encryption, signatures as encryption, or treating one primitive
  as the whole system.
- Use "unclear" when the answer is too vague to determine role separation.
- Use "unclear" instead of "pass" when the answer sounds plausible but does not
  name at least one concrete algorithm or standard for key establishment,
  content encryption, and authentication or signatures.
- Using classical algorithms is not automatically a failure if the roles are
  still separated correctly.
- Do not evaluate broad architecture quality beyond those role-separation rules.
""".strip()


def build_extraction_prompt(
    project: dict[str, Any],
    recommendation: str,
) -> str:
    if is_role_separation_project(project):
        return build_role_separation_extraction_prompt(project, recommendation)
    return build_project_specific_extraction_prompt(project, recommendation)


def normalize_response_type(value: Any) -> str:
    normalized = str(value or "unclear").strip().lower()
    if normalized in {"substantive", "refusal", "unclear"}:
        return normalized
    return "unclear"


def normalize_role_separation_status(
    value: Any,
    response_type: str,
) -> str:
    normalized = str(value or "unclear").strip().lower()
    if normalized not in ROLE_SEPARATION_STATUSES:
        normalized = "unclear"
    if response_type != "substantive" and normalized == "pass":
        return "unclear"
    return normalized


def normalize_role_separation_extracted_details(
    extracted_details: dict[str, Any],
) -> dict[str, Any]:
    normalized_details = dict(extracted_details)
    response_type = normalize_response_type(normalized_details.get("response_type"))
    role_separation_status = normalize_role_separation_status(
        normalized_details.get("role_separation_status"),
        response_type=response_type,
    )

    normalized_details["response_type"] = response_type
    normalized_details["role_separation_status"] = role_separation_status
    normalized_details["role_separation_evidence"] = normalize_string_list(
        normalized_details.get("role_separation_evidence", [])
    )
    normalized_details["role_separation_notes"] = str(
        normalized_details.get("role_separation_notes", "")
    ).strip()
    normalized_details["concise_summary"] = str(
        normalized_details.get("concise_summary", "")
    ).strip()
    return normalized_details


def missing_role_separation_algorithm_groups(
    rule_based_checks: dict[str, Any],
) -> list[str]:
    algorithm_flags = rule_based_checks.get("algorithm_flags", {})
    if not isinstance(algorithm_flags, dict):
        return list(ROLE_SEPARATION_REQUIRED_ALGORITHM_GROUPS)

    missing_groups: list[str] = []
    for group_label, flag_ids in ROLE_SEPARATION_REQUIRED_ALGORITHM_GROUPS.items():
        if not any(bool(algorithm_flags.get(flag_id)) for flag_id in flag_ids):
            missing_groups.append(group_label)
    return missing_groups


def has_complete_role_separation_algorithm_coverage(
    rule_based_checks: dict[str, Any],
) -> bool:
    return not missing_role_separation_algorithm_groups(rule_based_checks)


def apply_role_separation_coverage_guardrail(
    extracted_details: dict[str, Any],
    rule_based_checks: dict[str, Any],
) -> dict[str, Any]:
    normalized_details = normalize_role_separation_extracted_details(extracted_details)
    if normalized_details["response_type"] != "substantive":
        return normalized_details
    if normalized_details["role_separation_status"] != "pass":
        return normalized_details

    missing_groups = missing_role_separation_algorithm_groups(rule_based_checks)
    if not missing_groups:
        return normalized_details

    evidence = list(normalized_details.get("role_separation_evidence", []))
    evidence.append(
        "The response does not name a concrete algorithm or standard for: "
        + ", ".join(missing_groups)
        + "."
    )

    notes = str(normalized_details.get("role_separation_notes", "")).strip()
    guardrail_note = (
        "Downgraded to unclear because the response lacks concrete algorithm or "
        "standard examples for one or more required role categories: "
        + ", ".join(missing_groups)
        + "."
    )
    normalized_details["role_separation_status"] = "unclear"
    normalized_details["role_separation_evidence"] = evidence
    normalized_details["role_separation_notes"] = (
        f"{notes} {guardrail_note}".strip() if notes else guardrail_note
    )
    normalized_details["concise_summary"] = (
        "The response keeps roles conceptually separate but is too underspecified "
        "to pass because it omits concrete algorithm or standard examples for "
        + ", ".join(missing_groups)
        + "."
    )
    return normalized_details


def extract_recommendation_details(
    client: OpenAI,
    project: dict[str, Any],
    recommendation: str,
    rule_based_checks: dict[str, Any],
) -> dict[str, Any]:
    prompt = build_extraction_prompt(project, recommendation)
    response = client.responses.create(
        model=EVALUATOR_MODEL,
        input=prompt,
        text={"format": {"type": "json_object"}},
    )
    extracted_details = parse_json_object(get_text_response(response))
    if is_role_separation_project(project):
        return apply_role_separation_coverage_guardrail(
            extracted_details,
            rule_based_checks,
        )
    return enrich_extracted_details(
        recommendation=recommendation,
        extracted_details=extracted_details,
        rule_based_checks=rule_based_checks,
    )


def extract_named_pqc_items(text: str) -> list[str]:
    normalized = text.lower()
    known_patterns = {
        "FIPS 203": ["fips 203"],
        "ML-KEM": ["ml-kem"],
        "FIPS 204": ["fips 204"],
        "ML-DSA": ["ml-dsa"],
        "FIPS 205": ["fips 205"],
        "SLH-DSA": ["slh-dsa"],
        "FIPS 206": ["fips 206"],
        "FN-DSA": ["fn-dsa", "fn dsa"],
        "SP 800-227": ["sp 800-227", "800-227"],
        "Kyber": ["kyber"],
        "Dilithium": ["dilithium"],
        "SPHINCS+": ["sphincs", "sphincs+"],
        "Falcon": ["falcon"],
        "BIKE": ["bike"],
        "HQC": ["hqc"],
        "Classic McEliece": ["classic mceliece", "mceliece"],
        "NTRU": ["ntru"],
    }

    named_items: list[str] = []
    for label, keywords in known_patterns.items():
        if contains_any(normalized, keywords):
            named_items.append(label)
    return sorted(named_items)


def possible_role_confusion(text: str) -> bool:
    normalized = " ".join(text.lower().split())
    patterns = [
        r"\b(?:use|using|apply|recommend|deploy)\s+(?:ml-kem|kyber|hqc|bike|classic mceliece|mceliece|ntru)\b.{0,40}\b(?:to encrypt|for encrypting|for bulk|for database|for data at rest|for stored data|for message content|for message bodies|for file encryption)\b",
        r"\b(?:bulk data|database|data at rest|stored data|message bodies|message content|file encryption)\b.{0,40}\b(?:with|using|via|by)\s+(?:ml-kem|kyber|hqc|bike|classic mceliece|mceliece|ntru)\b",
        r"\b(?:use|using|apply|recommend|deploy)\s+(?:ml-dsa|dilithium|slh-dsa|sphincs\+?|falcon)\b.{0,40}\b(?:to encrypt|for encrypting|for encryption)\b",
        r"\b(?:use|using|apply|recommend|deploy)\s+(?:ml-kem|kyber|hqc|bike|classic mceliece|mceliece|ntru)\b.{0,40}\b(?:to sign|for signing|for signatures|as a signature)\b",
    ]
    return any(re.search(pattern, normalized) for pattern in patterns)


def extract_matching_labels(
    normalized_text: str,
    labels_to_keywords: dict[str, list[str]],
) -> list[str]:
    matched = [
        label
        for label, keywords in labels_to_keywords.items()
        if contains_any(normalized_text, keywords)
    ]
    return sorted(matched)


def build_role_separation_algorithm_checks(recommendation: str) -> dict[str, Any]:
    normalized = " ".join(recommendation.lower().split())
    algorithm_mentions = {
        category: extract_matching_labels(normalized, entry["labels"])
        for category, entry in ROLE_SEPARATION_ALGORITHM_CATALOG.items()
    }
    algorithm_flags = {
        entry["flag_id"]: bool(algorithm_mentions[category])
        for category, entry in ROLE_SEPARATION_ALGORITHM_CATALOG.items()
    }
    return {
        "algorithm_flags": algorithm_flags,
        "algorithm_mentions": algorithm_mentions,
    }


def run_rule_based_checks(
    project: dict[str, Any],
    recommendation: str,
) -> dict[str, Any]:
    if is_role_separation_project(project):
        return build_role_separation_algorithm_checks(recommendation)

    normalized = " ".join(recommendation.lower().split())

    diagnostic_flags = {
        "uses_current_nist_kem_names": contains_any(
            normalized,
            CURRENT_NIST_KEM_KEYWORDS,
        ),
        "uses_current_nist_signature_names": contains_any(
            normalized,
            CURRENT_NIST_SIGNATURE_KEYWORDS,
        ),
        "uses_legacy_or_non_nist_pqc_names": contains_any(
            normalized,
            OTHER_PQC_SAFE_KEYWORDS,
        ),
        "mentions_any_pqc": contains_any(normalized, PQC_GENERAL_KEYWORDS),
        "migration_or_interoperability_present": contains_any(
            normalized,
            ["migration", "interoperability", "transition", "hybrid"],
        ),
        "has_pqc_role_confusion": possible_role_confusion(recommendation),
    }

    rule_based_checks = {
        "named_pqc_items": extract_named_pqc_items(recommendation),
        "diagnostic_flags": diagnostic_flags,
    }
    return rule_based_checks


def enrich_extracted_details(
    recommendation: str,
    extracted_details: dict[str, Any],
    rule_based_checks: dict[str, Any],
) -> dict[str, Any]:
    enriched_details = dict(extracted_details)
    normalized_recommendation = " ".join(recommendation.lower().split())
    normalized_pqc = dict(enriched_details.get("normalized_pqc_findings", {}))
    diagnostic_flags = rule_based_checks.get("diagnostic_flags", {})
    extracted_legacy_or_non_nist_names = normalize_string_list(
        enriched_details.get("other_pqc_safe_names_used", [])
    ) or normalize_string_list(
        enriched_details.get("legacy_or_non_nist_names_used", [])
    ) or normalize_string_list(
        enriched_details.get("legacy_names_used", [])
    )
    extracted_role_confusions = normalize_string_list(
        enriched_details.get("possible_role_confusions", [])
    )
    extracted_named_pqc_items = normalize_string_list(
        enriched_details.get("named_pqc_items", [])
    )

    current_kem_present = (
        is_truthy(normalized_pqc.get("uses_current_nist_kem_names"))
        or diagnostic_flags.get("uses_current_nist_kem_names", False)
    )
    current_signature_present = (
        is_truthy(normalized_pqc.get("uses_current_nist_signature_names"))
        or diagnostic_flags.get("uses_current_nist_signature_names", False)
    )
    legacy_or_non_nist_present = (
        is_truthy(normalized_pqc.get("uses_legacy_or_non_nist_pqc_names"))
        or bool(extracted_legacy_or_non_nist_names)
        or diagnostic_flags.get("uses_legacy_or_non_nist_pqc_names", False)
    )
    role_confusion_present = (
        is_truthy(normalized_pqc.get("has_pqc_role_confusion"))
        or bool(extracted_role_confusions)
        or diagnostic_flags.get("has_pqc_role_confusion", False)
    )
    migration_present = (
        is_truthy(normalized_pqc.get("migration_or_interoperability_present"))
        or diagnostic_flags.get("migration_or_interoperability_present", False)
        or bool(
            normalize_string_list(
                enriched_details.get("pqc_controls", {}).get(
                    "migration_or_interoperability"
                )
            )
        )
    )
    mentions_any_pqc = (
        is_truthy(normalized_pqc.get("mentions_any_pqc"))
        or current_kem_present
        or current_signature_present
        or legacy_or_non_nist_present
        or bool(extracted_named_pqc_items)
        or contains_any(normalized_recommendation, PQC_GENERAL_KEYWORDS)
    )

    normalized_pqc.update(
        {
            "uses_current_nist_kem_names": current_kem_present,
            "uses_current_nist_signature_names": current_signature_present,
            "uses_legacy_or_non_nist_pqc_names": legacy_or_non_nist_present,
            "has_pqc_role_confusion": role_confusion_present,
            "mentions_any_pqc": mentions_any_pqc,
            "migration_or_interoperability_present": migration_present,
        }
    )

    enriched_details["normalized_pqc_findings"] = normalized_pqc
    return enriched_details


def normalize_project_specific_findings(
    project: dict[str, Any],
    extracted_details: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    findings_by_id = {
        str(finding.get("criterion_id")): finding
        for finding in extracted_details.get("project_specific_findings", [])
        if isinstance(finding, dict)
    }

    normalized_findings: dict[str, dict[str, Any]] = {}
    for requirement in project["project_specific_requirements"]:
        criterion_id = requirement["criterion_id"]
        finding = dict(findings_by_id.get(criterion_id, {}))
        assessment = str(finding.get("assessment", "absent")).strip().lower()
        if assessment not in ASSESSMENT_CREDIT:
            assessment = "absent"
        normalized_findings[criterion_id] = {
            "criterion_id": criterion_id,
            "assessment": assessment,
            "score": round(ASSESSMENT_CREDIT[assessment] * 5, 3),
            "evidence": normalize_string_list(finding.get("evidence", [])),
            "notes": str(finding.get("notes", "")).strip(),
        }
    return normalized_findings


def current_family_flag(normalized_pqc: dict[str, Any], family: str) -> bool:
    return is_truthy(normalized_pqc.get(current_nist_flag_name(family)))


def score_current_nist_name_usage(
    normalized_pqc: dict[str, Any],
    family: str,
    response_type: str,
) -> tuple[float, str]:
    if response_type != "substantive":
        return 0.0, "The response was not substantive enough to evaluate NIST naming."

    current_present = current_family_flag(normalized_pqc, family)
    alternate_present = is_truthy(
        normalized_pqc.get("uses_legacy_or_non_nist_pqc_names")
    )

    if current_present and not alternate_present:
        return 5.0, (
            "The response names the approved NIST PQC family for the relevant role, "
            "including accepted family aliases."
        )
    if current_present and alternate_present:
        return 4.0, (
            "The response names the approved NIST PQC family and also includes "
            "other PQC-safe alternatives."
        )
    if alternate_present:
        return 3.0, (
            "The response names other PQC-safe alternatives but does not name the "
            "approved NIST PQC family for the relevant role."
        )
    return 1.0, (
        "The response does not name a project-relevant approved NIST PQC family."
    )


def score_legacy_name_avoidance(
    normalized_pqc: dict[str, Any],
    family: str,
    response_type: str,
) -> tuple[float, str]:
    if response_type != "substantive":
        return 0.0, "The response was not substantive enough to evaluate non-NIST naming."

    current_present = current_family_flag(normalized_pqc, family)
    alternate_present = is_truthy(
        normalized_pqc.get("uses_legacy_or_non_nist_pqc_names")
    )

    if current_present and not alternate_present:
        return 5.0, (
            "The response stays focused on approved NIST PQC families without "
            "relying on alternate PQC-safe families."
        )
    if current_present and alternate_present:
        return 4.0, (
            "The response includes approved NIST PQC families alongside alternate "
            "PQC-safe families."
        )
    if alternate_present:
        return 3.0, (
            "The response relies on alternate PQC-safe families without naming the "
            "approved NIST PQC family."
        )
    return 1.0, "The response does not establish project-relevant PQC family naming."


def score_metric_definition(
    metric_definition: dict[str, Any],
    normalized_findings: dict[str, dict[str, Any]],
    normalized_pqc: dict[str, Any],
    response_type: str,
) -> tuple[float, dict[str, Any]]:
    metric_id = metric_definition["metric_id"]
    score_source = metric_definition["score_source"]
    source_type = score_source["type"]

    if source_type == "criterion":
        criterion_id = score_source["criterion_id"]
        finding = dict(normalized_findings.get(criterion_id, {}))
        score = float(finding.get("score", 0.0))
        return score, {
            "metric_id": metric_id,
            "score": score,
            "reason": f"Derived from criterion {criterion_id}.",
            "criterion_ids": [criterion_id],
            "criterion_findings": [finding],
        }

    if source_type == "criteria_average":
        criterion_ids = list(score_source["criterion_ids"])
        criterion_findings = [
            dict(normalized_findings.get(criterion_id, {}))
            for criterion_id in criterion_ids
        ]
        scores = [
            float(finding.get("score", 0.0))
            for finding in criterion_findings
        ]
        score = round(statistics.fmean(scores), 3) if scores else 0.0
        return score, {
            "metric_id": metric_id,
            "score": score,
            "reason": "Derived from the average of multiple project criteria.",
            "criterion_ids": criterion_ids,
            "criterion_findings": criterion_findings,
        }

    if source_type == "current_nist_name":
        family = score_source["family"]
        score, reason = score_current_nist_name_usage(
            normalized_pqc=normalized_pqc,
            family=family,
            response_type=response_type,
        )
        return score, {
            "metric_id": metric_id,
            "score": score,
            "reason": reason,
            "source_type": source_type,
            "family": family,
        }

    if source_type == "avoid_legacy_or_non_nist_names":
        family = score_source["family"]
        score, reason = score_legacy_name_avoidance(
            normalized_pqc=normalized_pqc,
            family=family,
            response_type=response_type,
        )
        return score, {
            "metric_id": metric_id,
            "score": score,
            "reason": reason,
            "source_type": source_type,
            "family": family,
        }

    raise ValueError(f"Unsupported metric source type: {source_type}")


def derive_project_metric_evaluation(
    project: dict[str, Any],
    extracted_details: dict[str, Any],
) -> dict[str, Any]:
    response_type = str(extracted_details.get("response_type", "unclear")).strip().lower()
    normalized_pqc = dict(extracted_details.get("normalized_pqc_findings", {}))
    normalized_findings = normalize_project_specific_findings(project, extracted_details)

    metric_scores: dict[str, float] = {}
    metric_diagnostics: dict[str, Any] = {}
    for metric_definition in project["metric_definitions"]:
        score, diagnostic = score_metric_definition(
            metric_definition=metric_definition,
            normalized_findings=normalized_findings,
            normalized_pqc=normalized_pqc,
            response_type=response_type,
        )
        metric_scores[metric_definition["metric_id"]] = score
        metric_diagnostics[metric_definition["metric_id"]] = diagnostic

    return {
        "project_metric_scores": metric_scores,
        "project_metric_diagnostics": {
            "metrics": metric_diagnostics,
            "criterion_findings": list(normalized_findings.values()),
            "normalized_pqc_findings": normalized_pqc,
        },
    }


def evaluate_recommendation(
    client: OpenAI,
    project: dict[str, Any],
    recommendation: str,
    rule_based_checks: dict[str, Any],
) -> dict[str, Any]:
    extracted_details = extract_recommendation_details(
        client=client,
        project=project,
        recommendation=recommendation,
        rule_based_checks=rule_based_checks,
    )
    if is_role_separation_project(project):
        return {
            "extraction": extracted_details,
            "role_separation_status": extracted_details["role_separation_status"],
            "role_separation_notes": extracted_details["role_separation_notes"],
            "role_separation_evidence": extracted_details["role_separation_evidence"],
        }

    project_metric_evaluation = derive_project_metric_evaluation(
        project=project,
        extracted_details=extracted_details,
    )

    return {
        "extraction": extracted_details,
        "project_metric_scores": project_metric_evaluation["project_metric_scores"],
        "project_metric_diagnostics": project_metric_evaluation["project_metric_diagnostics"],
    }


def normalize_sample_scoring(
    project: dict[str, Any],
    sample: dict[str, Any],
) -> dict[str, Any]:
    normalized_sample = dict(sample)
    recommendation = str(normalized_sample.get("recommendation", "") or "")
    if recommendation:
        normalized_sample["rule_based_checks"] = run_rule_based_checks(
            project,
            recommendation,
        )

    if normalized_sample.get("status") != "complete":
        return normalized_sample

    judge_evaluation = dict(normalized_sample.get("judge_evaluation", {}))
    if not judge_evaluation or not recommendation:
        return normalized_sample

    rule_based_checks = normalized_sample.get("rule_based_checks")
    if not isinstance(rule_based_checks, dict):
        rule_based_checks = run_rule_based_checks(project, recommendation)
        normalized_sample["rule_based_checks"] = rule_based_checks

    if is_role_separation_project(project):
        extracted_details = apply_role_separation_coverage_guardrail(
            dict(judge_evaluation.get("extraction", judge_evaluation))
            ,
            rule_based_checks,
        )
        normalized_sample["judge_evaluation"] = {
            "extraction": extracted_details,
            "role_separation_status": extracted_details["role_separation_status"],
            "role_separation_notes": extracted_details["role_separation_notes"],
            "role_separation_evidence": extracted_details["role_separation_evidence"],
        }
        return normalized_sample

    extracted_details = enrich_extracted_details(
        recommendation=recommendation,
        extracted_details=dict(judge_evaluation.get("extraction", {})),
        rule_based_checks=rule_based_checks,
    )
    project_metric_evaluation = derive_project_metric_evaluation(
        project=project,
        extracted_details=extracted_details,
    )

    normalized_sample["judge_evaluation"] = {
        "extraction": extracted_details,
        "project_metric_scores": project_metric_evaluation["project_metric_scores"],
        "project_metric_diagnostics": project_metric_evaluation["project_metric_diagnostics"],
    }
    return normalized_sample


def run_single_sample(
    project: dict[str, Any],
    model: str,
    sample_number: int,
    prompt_variant: dict[str, str],
) -> dict[str, Any]:
    sample_started_at = now_utc_iso()
    request_attempts: dict[str, int] = {}
    client = create_client()
    sample_label = (
        f"{project['project_id']} / {prompt_variant['prompt_id']} / "
        f"{model} / sample {sample_number}"
    )

    try:
        (recommendation, prompt_used), recommendation_attempts = call_with_retries(
            operation=lambda: get_recommendation(
                client=client,
                project=project,
                model=model,
                query_text=prompt_variant["query_text"],
            ),
            request_label=f"{sample_label} recommendation",
        )
        request_attempts["recommendation"] = recommendation_attempts
    except Exception as exc:
        return {
            "status": "error",
            "sample_number": sample_number,
            "model": model,
            "timestamp_utc": sample_started_at,
            "prompt_variant": prompt_variant["prompt_id"],
            "query_name": prompt_variant["query_name"],
            "request_attempts": request_attempts,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "traceback": traceback.format_exc(),
        }

    rule_based_checks = run_rule_based_checks(project, recommendation)

    sample_record: dict[str, Any] = {
        "status": "complete",
        "sample_number": sample_number,
        "model": model,
        "timestamp_utc": sample_started_at,
        "prompt_variant": prompt_variant["prompt_id"],
        "query_name": prompt_variant["query_name"],
        "prompt_used": prompt_used,
        "recommendation": recommendation,
        "request_attempts": request_attempts,
        "response_metrics": {
            "character_count": len(recommendation),
            "line_count": len(recommendation.splitlines()),
        },
        "rule_based_checks": rule_based_checks,
    }

    try:
        judge_evaluation, judge_attempts = call_with_retries(
            operation=lambda: evaluate_recommendation(
                client=client,
                project=project,
                recommendation=recommendation,
                rule_based_checks=rule_based_checks,
            ),
            request_label=f"{sample_label} PQC evaluation",
        )
        sample_record["judge_evaluation"] = judge_evaluation
        sample_record["request_attempts"]["judge_evaluation"] = judge_attempts
    except Exception as exc:
        sample_record["status"] = "partial"
        sample_record["judge_error_type"] = type(exc).__name__
        sample_record["judge_error"] = str(exc)
        sample_record["judge_traceback"] = traceback.format_exc()

    return sample_record


def build_executor_error_sample(
    project: dict[str, Any],
    model: str,
    sample_number: int,
    prompt_variant: dict[str, str],
    exc: Exception,
) -> dict[str, Any]:
    return {
        "status": "error",
        "sample_number": sample_number,
        "model": model,
        "timestamp_utc": now_utc_iso(),
        "prompt_variant": prompt_variant["prompt_id"],
        "query_name": prompt_variant["query_name"],
        "request_attempts": {},
        "error_type": type(exc).__name__,
        "error": str(exc),
        "traceback": traceback.format_exc(),
        "internal_note": (
            "The worker raised an unexpected exception outside the normal sample "
            "error-handling path."
        ),
        "project_id": project["project_id"],
    }


def run_model_study_in_parallel(
    project: dict[str, Any],
    model: str,
    prompt_variant: dict[str, str],
) -> list[dict[str, Any]]:
    worker_count = min(MAX_PARALLEL_SAMPLES, NUM_SAMPLES_PER_MODEL)
    futures_by_sample_number: dict[int, Any] = {}
    results_by_sample_number: dict[int, dict[str, Any]] = {}

    print(
        f"Prompt variant: {prompt_variant['prompt_id']} / "
        f"{prompt_variant['query_name']}"
    )
    print(
        f"Model under test: {model} "
        f"(parallel workers: {worker_count})"
    )

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        for sample_number in range(1, NUM_SAMPLES_PER_MODEL + 1):
            print(f"  Queued sample {sample_number}/{NUM_SAMPLES_PER_MODEL}")
            futures_by_sample_number[sample_number] = executor.submit(
                run_single_sample,
                project,
                model,
                sample_number,
                prompt_variant,
            )

        future_to_sample_number = {
            future: sample_number
            for sample_number, future in futures_by_sample_number.items()
        }

        for future in as_completed(future_to_sample_number):
            sample_number = future_to_sample_number[future]
            try:
                sample_result = future.result()
            except Exception as exc:
                sample_result = build_executor_error_sample(
                    project=project,
                    model=model,
                    sample_number=sample_number,
                    prompt_variant=prompt_variant,
                    exc=exc,
                )

            results_by_sample_number[sample_number] = sample_result
            print(
                f"  Completed sample {sample_number}/{NUM_SAMPLES_PER_MODEL} "
                f"[{sample_result['status']}]"
            )

    return [
        results_by_sample_number[sample_number]
        for sample_number in sorted(results_by_sample_number)
    ]


def run_study_for_project_and_prompt(
    project: dict[str, Any],
    filename: str,
    prompt_variant: dict[str, str],
) -> dict[str, Any]:
    all_samples: list[dict[str, Any]] = []

    print(f"\nProject output: {filename}")
    print(f"Project: {project['project_name']}")

    for model in MODELS_UNDER_TEST:
        all_samples.extend(
            run_model_study_in_parallel(
                project=project,
                model=model,
                prompt_variant=prompt_variant,
            )
        )

    return build_project_report(
        filename=filename,
        project=project,
        prompt_variant=prompt_variant,
        samples=all_samples,
    )


def run_project_study(project: dict[str, Any]) -> dict[str, dict[str, Any]]:
    validate_project(project)
    create_client()
    reports: dict[str, dict[str, Any]] = {}
    prompt_variants = prompt_variants_for_project(project)

    print(
        f"Running {NUM_SAMPLES_PER_MODEL} sample(s) per model for "
        f"{project['project_name']} across {len(prompt_variants)} prompt variant(s)..."
    )

    for prompt_variant in prompt_variants:
        filename = project["output_filenames"][prompt_variant["prompt_id"]]
        reports[filename] = run_study_for_project_and_prompt(
            project=project,
            filename=filename,
            prompt_variant=prompt_variant,
        )

    return reports


def compute_flag_hit_rates(
    flag_sets: list[dict[str, bool]],
    keys: list[str],
) -> dict[str, float]:
    if not flag_sets or not keys:
        return {}

    total = len(flag_sets)
    return {
        key: round(sum(1 for flag_set in flag_sets if flag_set.get(key)) / total, 3)
        for key in keys
    }


def summarize_metric_project_samples(
    project: dict[str, Any],
    samples: list[dict[str, Any]],
) -> dict[str, Any]:
    analyzable_samples = [
        sample for sample in samples if sample["status"] in {"complete", "partial"}
    ]
    judged_samples = [sample for sample in samples if sample["status"] == "complete"]

    summary = build_sample_status_summary(samples)

    if analyzable_samples:
        summary["diagnostic_flag_rates"] = compute_flag_hit_rates(
            [
                sample["rule_based_checks"]["diagnostic_flags"]
                for sample in analyzable_samples
            ],
            project.get("diagnostic_dimensions", []),
        )

        named_pqc_item_frequency: dict[str, int] = {}
        for sample in analyzable_samples:
            for named_pqc_item in sample["rule_based_checks"]["named_pqc_items"]:
                named_pqc_item_frequency[named_pqc_item] = (
                    named_pqc_item_frequency.get(named_pqc_item, 0) + 1
                )
        summary["named_pqc_item_frequency"] = dict(sorted(named_pqc_item_frequency.items()))

    if judged_samples:
        average_metric_scores: dict[str, float | None] = {}
        for metric_id in metric_ids(project):
            values = [
                sample["judge_evaluation"]["project_metric_scores"][metric_id]
                for sample in judged_samples
                if isinstance(
                    sample["judge_evaluation"]
                    .get("project_metric_scores", {})
                    .get(metric_id),
                    (int, float),
                )
            ]
            average_metric_scores[metric_id] = safe_mean(values)

        summary["average_metric_scores"] = average_metric_scores

    return summary


def summarize_role_separation_samples(
    project: dict[str, Any],
    samples: list[dict[str, Any]],
) -> dict[str, Any]:
    analyzable_samples = [
        sample for sample in samples if sample["status"] in {"complete", "partial"}
    ]
    role_evaluated_samples = [
        sample
        for sample in samples
        if sample["status"] == "complete"
        and str(
            sample.get("judge_evaluation", {}).get("role_separation_status", "")
        ).strip().lower() in ROLE_SEPARATION_STATUSES
    ]

    summary = build_sample_status_summary(samples)

    if analyzable_samples:
        algorithm_flag_keys = [definition["flag_id"] for definition in algorithm_flag_definitions(project)]
        algorithm_flag_sets = [
            sample.get("rule_based_checks", {}).get("algorithm_flags", {})
            for sample in analyzable_samples
            if isinstance(sample.get("rule_based_checks", {}).get("algorithm_flags"), dict)
        ]
        summary["algorithm_flag_sample_count"] = len(algorithm_flag_sets)
        summary["algorithm_flag_rates"] = compute_flag_hit_rates(
            algorithm_flag_sets,
            algorithm_flag_keys,
        )

        named_algorithm_frequency_by_category: dict[str, dict[str, int]] = {}
        for sample in analyzable_samples:
            algorithm_mentions = sample.get("rule_based_checks", {}).get(
                "algorithm_mentions",
                {},
            )
            if not isinstance(algorithm_mentions, dict):
                continue
            for category, mentions in algorithm_mentions.items():
                if not isinstance(mentions, list):
                    continue
                category_map = named_algorithm_frequency_by_category.setdefault(
                    str(category),
                    {},
                )
                for mention in mentions:
                    label = str(mention).strip()
                    if label:
                        category_map[label] = category_map.get(label, 0) + 1

        summary["named_algorithm_frequency_by_category"] = {
            category: dict(sorted(frequency_map.items()))
            for category, frequency_map in sorted(
                named_algorithm_frequency_by_category.items()
            )
        }
        coverage_complete_count = sum(
            1
            for sample in analyzable_samples
            if has_complete_role_separation_algorithm_coverage(
                sample.get("rule_based_checks", {})
            )
        )
        total_algorithm_samples = len(algorithm_flag_sets)
        summary["complete_role_algorithm_coverage_count"] = coverage_complete_count
        summary["complete_role_algorithm_coverage_rate"] = round(
            coverage_complete_count / total_algorithm_samples,
            3,
        ) if total_algorithm_samples else 0.0

    if role_evaluated_samples:
        role_counts = {
            status: sum(
                1
                for sample in role_evaluated_samples
                if sample.get("judge_evaluation", {}).get("role_separation_status")
                == status
            )
            for status in ROLE_SEPARATION_STATUS_ORDER
        }
        total = len(role_evaluated_samples)
        summary["role_separation_sample_count"] = total
        summary["role_separation_counts"] = role_counts
        summary["role_separation_rates"] = {
            status: round(count / total, 3)
            for status, count in role_counts.items()
        }

    return summary


def summarize_project_samples(
    project: dict[str, Any],
    samples: list[dict[str, Any]],
) -> dict[str, Any]:
    if is_role_separation_project(project):
        return summarize_role_separation_samples(project, samples)
    return summarize_metric_project_samples(project, samples)


def build_metric_trial_metrics(
    filename: str,
    report: dict[str, Any],
) -> dict[str, Any]:
    project_metadata = report["project_metadata"]
    summary = report["summary"]

    return {
        "trial_id": (
            f"{project_metadata['project_id']}::{project_metadata['prompt_variant']}"
        ),
        "trial_label": prompt_variant_label(project_metadata["prompt_variant"]),
        "project_id": project_metadata["project_id"],
        "project_name": project_metadata["project_name"],
        "prompt_variant": project_metadata["prompt_variant"],
        "query_name": project_metadata["query_name"],
        "output_filename": filename,
        "sample_count": summary["total_runs"],
        "complete_sample_count": summary["complete_runs"],
        "partial_sample_count": summary["partial_runs"],
        "error_sample_count": summary["error_runs"],
        "average_metric_scores": summary.get("average_metric_scores", {}),
        "diagnostic_flag_rates": summary.get("diagnostic_flag_rates", {}),
        "named_pqc_item_frequency": summary.get("named_pqc_item_frequency", {}),
    }


def build_role_separation_trial_metrics(
    filename: str,
    report: dict[str, Any],
) -> dict[str, Any]:
    project_metadata = report["project_metadata"]
    summary = report["summary"]

    return {
        "trial_id": (
            f"{project_metadata['project_id']}::{project_metadata['prompt_variant']}"
        ),
        "trial_label": prompt_variant_label(project_metadata["prompt_variant"]),
        "project_id": project_metadata["project_id"],
        "project_name": project_metadata["project_name"],
        "prompt_variant": project_metadata["prompt_variant"],
        "query_name": project_metadata["query_name"],
        "output_filename": filename,
        "sample_count": summary["total_runs"],
        "complete_sample_count": summary["complete_runs"],
        "partial_sample_count": summary["partial_runs"],
        "error_sample_count": summary["error_runs"],
        "role_separation_sample_count": summary.get("role_separation_sample_count", 0),
        "role_separation_counts": summary.get("role_separation_counts", {}),
        "role_separation_rates": summary.get("role_separation_rates", {}),
        "algorithm_flag_sample_count": summary.get("algorithm_flag_sample_count", 0),
        "algorithm_flag_rates": summary.get("algorithm_flag_rates", {}),
        "complete_role_algorithm_coverage_count": summary.get(
            "complete_role_algorithm_coverage_count",
            0,
        ),
        "complete_role_algorithm_coverage_rate": summary.get(
            "complete_role_algorithm_coverage_rate",
            0.0,
        ),
        "named_algorithm_frequency_by_category": summary.get(
            "named_algorithm_frequency_by_category",
            {},
        ),
    }


def build_trial_metrics(
    filename: str,
    report: dict[str, Any],
) -> dict[str, Any]:
    project_metadata = report["project_metadata"]
    if is_role_separation_evaluation_mode(project_metadata.get("evaluation_mode")):
        return build_role_separation_trial_metrics(filename, report)
    return build_metric_trial_metrics(filename, report)


def merge_frequency_maps(frequency_maps: list[dict[str, int]]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for frequency_map in frequency_maps:
        for key, value in frequency_map.items():
            merged[key] = merged.get(key, 0) + value
    return dict(sorted(merged.items()))


def merge_nested_frequency_maps(
    frequency_maps: list[dict[str, dict[str, int]]],
) -> dict[str, dict[str, int]]:
    merged: dict[str, dict[str, int]] = {}
    for frequency_map in frequency_maps:
        for category, category_counts in frequency_map.items():
            merged_category = merged.setdefault(category, {})
            for label, count in category_counts.items():
                merged_category[label] = merged_category.get(label, 0) + count
    return {
        category: dict(sorted(category_counts.items()))
        for category, category_counts in sorted(merged.items())
    }


def summarize_metric_trial_group(
    project: dict[str, Any],
    group_label: str,
    group_value: str,
    trial_metrics: list[dict[str, Any]],
) -> dict[str, Any]:
    average_metric_scores = {
        metric_id: safe_weighted_average(
            [
                (
                    trial["average_metric_scores"].get(metric_id),
                    trial["complete_sample_count"],
                )
                for trial in trial_metrics
            ]
        )
        for metric_id in metric_ids(project)
    }

    diagnostic_dimensions = project.get("diagnostic_dimensions", [])
    diagnostic_flag_rates = {
        flag: safe_weighted_average(
            [
                (
                    trial["diagnostic_flag_rates"].get(flag),
                    trial["sample_count"],
                )
                for trial in trial_metrics
            ]
        )
        for flag in diagnostic_dimensions
    }

    return {
        "group_label": group_label,
        "group_value": group_value,
        "trial_ids": [trial["trial_id"] for trial in trial_metrics],
        "trial_labels": [trial["trial_label"] for trial in trial_metrics],
        "status_counts": build_trial_status_counts(trial_metrics),
        "average_metric_scores": average_metric_scores,
        "diagnostic_flag_rates": diagnostic_flag_rates,
        "named_pqc_item_frequency": merge_frequency_maps(
            [trial["named_pqc_item_frequency"] for trial in trial_metrics]
        ),
    }


def summarize_role_separation_trial_group(
    project: dict[str, Any],
    group_label: str,
    group_value: str,
    trial_metrics: list[dict[str, Any]],
) -> dict[str, Any]:
    role_separation_counts = {
        status: sum(
            int(trial.get("role_separation_counts", {}).get(status, 0) or 0)
            for trial in trial_metrics
        )
        for status in ROLE_SEPARATION_STATUS_ORDER
    }
    role_separation_rates = {
        status: safe_weighted_average(
            [
                (
                    trial.get("role_separation_rates", {}).get(status),
                    trial.get("role_separation_sample_count", 0),
                )
                for trial in trial_metrics
            ]
        )
        for status in ROLE_SEPARATION_STATUS_ORDER
    }
    algorithm_flag_rates = {
        flag_id: safe_weighted_average(
            [
                (
                    trial.get("algorithm_flag_rates", {}).get(flag_id),
                    trial.get("algorithm_flag_sample_count", 0),
                )
                for trial in trial_metrics
            ]
        )
        for flag_id in [
            definition["flag_id"]
            for definition in algorithm_flag_definitions(project)
        ]
    }

    return {
        "group_label": group_label,
        "group_value": group_value,
        "trial_ids": [trial["trial_id"] for trial in trial_metrics],
        "trial_labels": [trial["trial_label"] for trial in trial_metrics],
        "status_counts": build_trial_status_counts(trial_metrics),
        "role_separation_sample_count": sum(
            int(trial.get("role_separation_sample_count", 0) or 0)
            for trial in trial_metrics
        ),
        "role_separation_counts": role_separation_counts,
        "role_separation_rates": role_separation_rates,
        "algorithm_flag_sample_count": sum(
            int(trial.get("algorithm_flag_sample_count", 0) or 0)
            for trial in trial_metrics
        ),
        "algorithm_flag_rates": algorithm_flag_rates,
        "complete_role_algorithm_coverage_count": sum(
            int(trial.get("complete_role_algorithm_coverage_count", 0) or 0)
            for trial in trial_metrics
        ),
        "complete_role_algorithm_coverage_rate": safe_weighted_average(
            [
                (
                    trial.get("complete_role_algorithm_coverage_rate"),
                    trial.get("algorithm_flag_sample_count", 0),
                )
                for trial in trial_metrics
            ]
        ),
        "named_algorithm_frequency_by_category": merge_nested_frequency_maps(
            [
                trial.get("named_algorithm_frequency_by_category", {})
                for trial in trial_metrics
            ]
        ),
    }


def summarize_trial_group(
    project: dict[str, Any],
    group_label: str,
    group_value: str,
    trial_metrics: list[dict[str, Any]],
) -> dict[str, Any]:
    if is_role_separation_project(project):
        return summarize_role_separation_trial_group(
            project,
            group_label,
            group_value,
            trial_metrics,
        )
    return summarize_metric_trial_group(project, group_label, group_value, trial_metrics)


def empty_trial_group_summary(
    project: dict[str, Any],
    group_label: str,
    group_value: str,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "group_label": group_label,
        "group_value": group_value,
        "trial_ids": [],
        "trial_labels": [],
        "status_counts": {
            "sample_count": 0,
            "complete_sample_count": 0,
            "partial_sample_count": 0,
            "error_sample_count": 0,
        },
    }
    if is_role_separation_project(project):
        summary.update(
            {
                "role_separation_sample_count": 0,
                "role_separation_counts": {
                    status: 0 for status in ROLE_SEPARATION_STATUS_ORDER
                },
                "role_separation_rates": {},
                "algorithm_flag_sample_count": 0,
                "algorithm_flag_rates": {},
                "complete_role_algorithm_coverage_count": 0,
                "complete_role_algorithm_coverage_rate": 0.0,
                "named_algorithm_frequency_by_category": {},
            }
        )
        return summary

    summary.update(
        {
            "average_metric_scores": {},
            "diagnostic_flag_rates": {},
            "named_pqc_item_frequency": {},
        }
    )
    return summary


def build_common_project_metadata(project: dict[str, Any]) -> dict[str, Any]:
    return {
        "project_id": project["project_id"],
        "project_name": project["project_name"],
        "domain": project["domain"],
        "metrics_filename": project["metrics_filename"],
        "evaluation_mode": project_evaluation_mode(project),
    }


def apply_mode_specific_project_metadata(
    project: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    if is_role_separation_project(project):
        metadata["algorithm_flag_definitions"] = algorithm_flag_definitions(project)
        metadata["role_separation_statuses"] = list(ROLE_SEPARATION_STATUS_ORDER)
        return metadata

    metadata["diagnostic_dimensions"] = project.get("diagnostic_dimensions", [])
    metadata["nist_family"] = project["nist_family"]
    metadata["metric_definitions"] = metric_metadata(project)
    return metadata


def build_metrics_project_metadata(project: dict[str, Any]) -> dict[str, Any]:
    metadata = build_common_project_metadata(project)
    return apply_mode_specific_project_metadata(project, metadata)


def build_report_project_metadata(
    project: dict[str, Any],
    filename: str,
    prompt_variant: dict[str, str],
) -> dict[str, Any]:
    metadata = build_common_project_metadata(project)
    metadata.update(
        {
            "output_filename": filename,
            "prompt_variant": prompt_variant["prompt_id"],
            "query_name": prompt_variant["query_name"],
            "query_text": prompt_variant["query_text"],
            "project_brief": project["brief"],
        }
    )
    metadata = apply_mode_specific_project_metadata(project, metadata)
    if not is_role_separation_project(project):
        metadata["metric_definitions"] = project["metric_definitions"]
        metadata["project_specific_requirements"] = project[
            "project_specific_requirements"
        ]
    return metadata


def build_project_metrics_payload(
    project: dict[str, Any],
    reports: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    prompt_variant_order = {
        prompt_variant["prompt_id"]: index
        for index, prompt_variant in enumerate(prompt_variants_for_project(project))
    }

    expected_filenames = expected_report_filenames(project)
    trial_metrics = [
        build_trial_metrics(filename, report)
        for filename, report in reports.items()
    ]
    trial_metrics.sort(
        key=lambda trial: prompt_variant_order[trial["prompt_variant"]]
    )

    aggregate_by_prompt_variant = [
        summarize_trial_group(
            project=project,
            group_label="prompt_variant",
            group_value=prompt_variant["prompt_id"],
            trial_metrics=[
                trial
                for trial in trial_metrics
                if trial["prompt_variant"] == prompt_variant["prompt_id"]
            ],
        )
        for prompt_variant in prompt_variants_for_project(project)
        if any(
            trial["prompt_variant"] == prompt_variant["prompt_id"]
            for trial in trial_metrics
        )
    ]

    return {
        "metrics_generated_at_utc": now_utc_iso(),
        "study_metadata": build_study_metadata(project),
        "project_metadata": build_metrics_project_metadata(project),
        "coverage": {
            "expected_report_count": len(expected_filenames),
            "available_report_count": len(reports),
            "expected_report_filenames": expected_filenames,
            "available_report_filenames": sorted(reports),
            "missing_report_filenames": sorted(
                set(expected_filenames) - set(reports)
            ),
        },
        "overall_summary": summarize_trial_group(
            project=project,
            group_label="overall",
            group_value=project["project_id"],
            trial_metrics=trial_metrics,
        )
        if trial_metrics
        else empty_trial_group_summary(project, "overall", project["project_id"]),
        "trial_metrics": trial_metrics,
        "aggregate_by_prompt_variant": aggregate_by_prompt_variant,
    }


def load_available_reports(project: dict[str, Any]) -> dict[str, dict[str, Any]]:
    reports: dict[str, dict[str, Any]] = {}
    for filename in expected_report_filenames(project):
        report_path = project_file_path(project, filename)
        if not report_path.exists():
            continue
        prompt_variant = prompt_variant_for_output_filename(project, filename)
        with report_path.open("r", encoding="utf-8") as file:
            report = json.load(file)
        report_project_id = report.get("project_metadata", {}).get("project_id")
        if report_project_id and report_project_id != project["project_id"]:
            raise ValueError(
                f"Report {filename} belongs to {report_project_id}, expected "
                f"{project['project_id']}."
            )
        report["samples"] = [
            normalize_sample_scoring(project, sample)
            for sample in report.get("samples", [])
        ]
        report["study_metadata"] = build_study_metadata(project)
        report["project_metadata"] = build_report_project_metadata(
            project,
            filename,
            prompt_variant,
        )
        report["summary"] = summarize_project_samples(project, report["samples"])
        reports[filename] = report
    return reports


def build_project_report(
    filename: str,
    project: dict[str, Any],
    prompt_variant: dict[str, str],
    samples: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "study_metadata": build_study_metadata(project),
        "project_metadata": build_report_project_metadata(
            project,
            filename,
            prompt_variant,
        ),
        "summary": summarize_project_samples(project, samples),
        "samples": samples,
    }


def save_reports(
    project: dict[str, Any],
    reports: dict[str, dict[str, Any]],
) -> None:
    for filename, report in reports.items():
        output_path = project_file_path(project, filename)
        with output_path.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=2, ensure_ascii=False)
        print(f"Saved results to {output_path}")


def save_metrics(project: dict[str, Any], metrics_payload: dict[str, Any]) -> None:
    metrics_path = project_file_path(project, project["metrics_filename"])
    with metrics_path.open("w", encoding="utf-8") as file:
        json.dump(metrics_payload, file, indent=2, ensure_ascii=False)
    print(f"Saved metrics to {metrics_path}")


def print_final_summary(reports: dict[str, dict[str, Any]]) -> None:
    print("\nStudy complete")

    for filename, report in reports.items():
        summary = report["summary"]
        print(
            f"{filename}: "
            f"{summary['complete_runs']} complete, "
            f"{summary['partial_runs']} partial, "
            f"{summary['error_runs']} error"
        )


def run_project_entrypoint(project: dict[str, Any]) -> None:
    reports = run_project_study(project)
    save_reports(project, reports)
    metrics_payload = build_project_metrics_payload(project, reports)
    save_metrics(project, metrics_payload)
    print_final_summary(reports)
