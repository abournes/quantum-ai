from __future__ import annotations

import argparse
import sys
from pathlib import Path

CODING_DIR = Path(__file__).resolve().parent
if str(CODING_DIR) not in sys.path:
    sys.path.insert(0, str(CODING_DIR))

import benchmark_logic
from medication import PROJECT as MEDICATION_PROJECT
from messaging import PROJECT as MESSAGING_PROJECT
from signing import PROJECT as SIGNING_PROJECT

PROJECTS: tuple[dict[str, object], ...] = (
    MESSAGING_PROJECT,
    MEDICATION_PROJECT,
    SIGNING_PROJECT,
)

PROJECTS_BY_ID: dict[str, dict[str, object]] = {
    str(project["project_id"]): project for project in PROJECTS
}

PROJECT_SELECTOR_MAP = {
    "messaging": str(MESSAGING_PROJECT["project_id"]),
    "medication": str(MEDICATION_PROJECT["project_id"]),
    "signing": str(SIGNING_PROJECT["project_id"]),
    **{
        str(project["project_id"]): str(project["project_id"])
        for project in PROJECTS
    },
}


def supported_project_selectors() -> list[str]:
    return sorted(PROJECT_SELECTOR_MAP)


def get_project(project_selector: str) -> dict[str, object]:
    project_id = PROJECT_SELECTOR_MAP.get(project_selector.strip().lower())
    if not project_id:
        supported = ", ".join(supported_project_selectors())
        raise ValueError(
            f"Unknown project selector: {project_selector}. "
            f"Use one of: {supported}"
        )
    return PROJECTS_BY_ID[project_id]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Display coding benchmark scaffold status for one project."
    )
    parser.add_argument(
        "project",
        help=(
            "Project selector. Supported values: "
            + ", ".join(supported_project_selectors())
        ),
    )
    return parser.parse_args()


def show_metrics_scaffold(project: dict[str, object]) -> None:
    benchmark_logic.validate_project(project)
    raise SystemExit(
        benchmark_logic.scaffold_status_message(project, "Metrics dashboard")
    )


if __name__ == "__main__":
    args = parse_args()
    try:
        project = get_project(args.project)
    except ValueError as exc:
        raise SystemExit(str(exc))

    show_metrics_scaffold(project)
