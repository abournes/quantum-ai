from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent

STUDY_ID = "nist-pqc-coding-benchmark"
PROMPT_VERSION = "2026-05-01-a"
RUBRIC_VERSION = "coding-scaffold-v1"

CODING_BENCHMARK_EVALUATION_MODE = "code_generation_pqc_scaffold"

PROMPT_VARIANT_LABELS = {
    "standard": "Standard",
    "pqc": "PQC",
    "nist_pqc": "NIST-Aware PQC",
}

REQUIRED_PROJECT_KEYS = (
    "project_id",
    "project_name",
    "domain",
    "base_dir",
    "evaluation_mode",
    "metrics_filename",
    "output_filenames",
    "prompt_variants",
    "brief",
    "coding_task_brief",
    "fixture_filename",
    "task_filename",
)


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def prompt_variant_label(prompt_variant_id: str) -> str:
    return PROMPT_VARIANT_LABELS.get(
        prompt_variant_id,
        prompt_variant_id.replace("_", " ").title(),
    )


def project_file_path(project: dict[str, Any], filename: str) -> Path:
    return Path(project["base_dir"]) / filename


def fixture_path(project: dict[str, Any]) -> Path:
    return project_file_path(project, str(project["fixture_filename"]))


def task_path(project: dict[str, Any]) -> Path:
    return project_file_path(project, str(project["task_filename"]))


def metrics_path(project: dict[str, Any]) -> Path:
    return project_file_path(project, str(project["metrics_filename"]))


def prompt_variants_for_project(project: dict[str, Any]) -> list[dict[str, str]]:
    return [dict(prompt_variant) for prompt_variant in project["prompt_variants"]]


def expected_report_filenames(project: dict[str, Any]) -> list[str]:
    output_filenames = dict(project["output_filenames"])
    return [
        str(output_filenames[prompt_id])
        for prompt_id in PROMPT_VARIANT_LABELS
        if prompt_id in output_filenames
    ]


def load_fixture_source(project: dict[str, Any]) -> str:
    return fixture_path(project).read_text(encoding="utf-8")


def load_task_text(project: dict[str, Any]) -> str:
    return task_path(project).read_text(encoding="utf-8")


def validate_project(project: dict[str, Any]) -> None:
    missing_keys = [key for key in REQUIRED_PROJECT_KEYS if key not in project]
    if missing_keys:
        raise ValueError(
            "Coding project is missing required keys: " + ", ".join(missing_keys)
        )

    if str(project["evaluation_mode"]) != CODING_BENCHMARK_EVALUATION_MODE:
        raise ValueError(
            "Unsupported coding evaluation mode: "
            f"{project['evaluation_mode']!r}."
        )

    base_dir = Path(project["base_dir"])
    if not base_dir.exists():
        raise ValueError(f"Coding project base_dir does not exist: {base_dir}")

    prompt_variants = prompt_variants_for_project(project)
    prompt_ids = [str(prompt_variant.get("prompt_id", "")).strip() for prompt_variant in prompt_variants]
    expected_prompt_ids = list(PROMPT_VARIANT_LABELS)
    if prompt_ids != expected_prompt_ids:
        raise ValueError(
            "Coding project prompt_variants must be ordered as: "
            + ", ".join(expected_prompt_ids)
        )

    for prompt_variant in prompt_variants:
        for key in ("prompt_id", "query_name", "query_text"):
            value = str(prompt_variant.get(key, "")).strip()
            if not value:
                raise ValueError(
                    "Coding prompt variant is missing a non-empty "
                    f"{key!r}: {prompt_variant!r}"
                )

    output_filenames = dict(project["output_filenames"])
    if list(output_filenames) != expected_prompt_ids:
        raise ValueError(
            "Coding project output_filenames must be ordered as: "
            + ", ".join(expected_prompt_ids)
        )

    for prompt_id, filename in output_filenames.items():
        if not str(filename).endswith(".json"):
            raise ValueError(
                f"Output filename for {prompt_id!r} must end with .json: {filename!r}"
            )

    for required_path in (fixture_path(project), task_path(project)):
        if not required_path.exists():
            raise ValueError(f"Required coding scaffold file is missing: {required_path}")


def build_study_metadata(project: dict[str, Any]) -> dict[str, Any]:
    return {
        "study_id": STUDY_ID,
        "generated_at_utc": now_utc_iso(),
        "prompt_version": PROMPT_VERSION,
        "rubric_version": RUBRIC_VERSION,
        "evaluation_mode": project["evaluation_mode"],
        "project_id": project["project_id"],
    }


def build_project_metadata(project: dict[str, Any]) -> dict[str, Any]:
    return {
        "project_id": project["project_id"],
        "project_name": project["project_name"],
        "domain": project["domain"],
        "evaluation_mode": project["evaluation_mode"],
        "metrics_filename": project["metrics_filename"],
        "fixture_filename": project["fixture_filename"],
        "task_filename": project["task_filename"],
        "prompt_variants": prompt_variants_for_project(project),
    }


def load_available_reports(project: dict[str, Any]) -> dict[str, dict[str, Any]]:
    validate_project(project)
    reports: dict[str, dict[str, Any]] = {}
    for filename in expected_report_filenames(project):
        report_path = project_file_path(project, filename)
        if not report_path.exists():
            continue
        with report_path.open("r", encoding="utf-8") as file:
            reports[filename] = json.load(file)
    return reports


def build_project_report(*args: Any, **kwargs: Any) -> dict[str, Any]:
    raise NotImplementedError(
        "Coding benchmark report generation is not implemented yet."
    )


def generate_code_candidate(*args: Any, **kwargs: Any) -> dict[str, Any]:
    raise NotImplementedError(
        "Coding benchmark code generation is not implemented yet."
    )


def evaluate_code_candidate(*args: Any, **kwargs: Any) -> dict[str, Any]:
    raise NotImplementedError(
        "Coding benchmark evaluation is not implemented yet."
    )


def build_project_metrics_payload(*args: Any, **kwargs: Any) -> dict[str, Any]:
    raise NotImplementedError(
        "Coding benchmark metrics generation is not implemented yet."
    )


def save_reports(*args: Any, **kwargs: Any) -> None:
    raise NotImplementedError("Coding benchmark report persistence is not implemented yet.")


def save_metrics(*args: Any, **kwargs: Any) -> None:
    raise NotImplementedError("Coding benchmark metrics persistence is not implemented yet.")


def scaffold_status_message(project: dict[str, Any], action: str) -> str:
    expected_reports = ", ".join(expected_report_filenames(project))
    available_reports = ", ".join(load_available_reports(project)) or "none"
    return "\n".join(
        [
            f"{action} is not implemented yet for the coding benchmark scaffold.",
            f"Project: {project['project_name']}",
            f"Fixture: {fixture_path(project)}",
            f"Task brief: {task_path(project)}",
            f"Future metrics file: {metrics_path(project)}",
            f"Expected future report files: {expected_reports}",
            f"Currently available report files: {available_reports}",
        ]
    )


def run_project_entrypoint(project: dict[str, Any]) -> None:
    validate_project(project)
    raise SystemExit(scaffold_status_message(project, "Benchmark execution"))
