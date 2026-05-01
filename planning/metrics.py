from __future__ import annotations

import argparse
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MPLCONFIGDIR = BASE_DIR / ".matplotlib"
MPLCONFIGDIR.mkdir(exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(MPLCONFIGDIR))

import matplotlib.pyplot as plt

import benchmark_logic
from medication import PROJECT as MEDICATION_PROJECT
from messaging import PROJECT as MESSAGING_PROJECT
from signing import PROJECT as SIGNING_PROJECT

METRIC_COLORS = [
    "#4C78A8",
    "#F58518",
    "#54A24B",
    "#E45756",
    "#72B7B2",
    "#EECA3B",
]

ROLE_STATUS_COLORS = {
    "pass": "#2A9D8F",
    "fail": "#E76F51",
    "unclear": "#E9C46A",
}

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
        description="Display benchmark metrics for one project."
    )
    parser.add_argument(
        "project",
        help=(
            "Project selector. Supported values: "
            + ", ".join(supported_project_selectors())
        ),
    )
    return parser.parse_args()


def metric_label_map(metric_definitions: list[dict[str, object]]) -> dict[str, str]:
    return {
        str(metric["metric_id"]): str(metric["label"])
        for metric in metric_definitions
    }


def metric_color_map(metric_definitions: list[dict[str, object]]) -> dict[str, str]:
    return {
        str(metric["metric_id"]): METRIC_COLORS[index % len(METRIC_COLORS)]
        for index, metric in enumerate(metric_definitions)
    }


def algorithm_flag_label_map(
    flag_definitions: list[dict[str, object]],
) -> dict[str, str]:
    return {
        str(flag_definition["flag_id"]): str(flag_definition["label"])
        for flag_definition in flag_definitions
    }


def require_algorithm_flag_definitions(
    project_metadata: dict[str, object],
) -> list[dict[str, object]]:
    algorithm_flag_definitions = list(
        project_metadata.get("algorithm_flag_definitions", [])
    )
    if not algorithm_flag_definitions:
        raise ValueError(
            "Project metadata is missing algorithm_flag_definitions for the "
            "role-separation dashboard."
        )
    return algorithm_flag_definitions


def algorithm_flag_definitions_for_prefix(
    algorithm_flag_definitions: list[dict[str, object]],
    prefix: str,
) -> list[dict[str, object]]:
    return [
        flag_definition
        for flag_definition in algorithm_flag_definitions
        if str(flag_definition["flag_id"]).startswith(prefix)
    ]


def refresh_metrics(project: dict[str, object]) -> dict[str, object]:
    benchmark_logic.validate_project(project)
    reports = benchmark_logic.load_available_reports(project)
    metrics_payload = benchmark_logic.build_project_metrics_payload(project, reports)
    benchmark_logic.save_metrics(project, metrics_payload)
    return metrics_payload


def finalize_figure(
    fig: plt.Figure,
    title: str,
    project_name: str,
    coverage: dict[str, object],
) -> None:
    available_report_count = int(coverage.get("available_report_count", 0))
    expected_report_count = int(coverage.get("expected_report_count", 0))
    missing_report_filenames = list(coverage.get("missing_report_filenames", []))

    fig.suptitle(
        f"{title} [{project_name}] "
        f"({available_report_count}/{expected_report_count} reports available)",
        fontsize=15,
    )
    if missing_report_filenames:
        fig.text(
            0.01,
            0.01,
            "Missing reports: " + ", ".join(missing_report_filenames),
            fontsize=9,
        )
        fig.tight_layout(rect=(0, 0.03, 1, 0.95))
    else:
        fig.tight_layout(rect=(0, 0.03, 1, 0.95))


def plot_role_separation_by_prompt_variant(
    ax: plt.Axes,
    prompt_variant_summaries: list[dict[str, object]],
    subject: str,
) -> None:
    labels = [
        benchmark_logic.prompt_variant_label(str(summary["group_value"]))
        for summary in prompt_variant_summaries
    ]
    x_positions = list(range(len(prompt_variant_summaries)))
    statuses = benchmark_logic.ROLE_SEPARATION_STATUS_ORDER
    width = 0.24

    for index, status in enumerate(statuses):
        values = [
            float(summary.get("role_separation_rates", {}).get(status, 0.0) or 0.0)
            for summary in prompt_variant_summaries
        ]
        ax.bar(
            [
                position + (index - (len(statuses) - 1) / 2) * width
                for position in x_positions
            ],
            values,
            width=width,
            label=status.title(),
            color=ROLE_STATUS_COLORS[status],
        )

    ax.set_title(f"{subject} Role-Separation Status by Prompt Variant")
    ax.set_ylabel("Rate")
    ax.set_ylim(0, 1.05)
    ax.set_xticks(x_positions)
    ax.set_xticklabels(labels)
    ax.grid(axis="y", alpha=0.25)
    ax.legend(loc="upper left")


def plot_algorithm_flags_by_prompt_variant(
    ax: plt.Axes,
    prompt_variant_summaries: list[dict[str, object]],
    algorithm_flag_definitions: list[dict[str, object]],
    title: str,
) -> None:
    labels = [
        benchmark_logic.prompt_variant_label(str(summary["group_value"]))
        for summary in prompt_variant_summaries
    ]
    x_positions = list(range(len(prompt_variant_summaries)))
    flag_labels = algorithm_flag_label_map(algorithm_flag_definitions)
    flag_ids = [str(flag_definition["flag_id"]) for flag_definition in algorithm_flag_definitions]
    width = 0.1 if flag_ids else 0.5

    for index, flag_id in enumerate(flag_ids):
        values = [
            float(summary.get("algorithm_flag_rates", {}).get(flag_id, 0.0) or 0.0)
            for summary in prompt_variant_summaries
        ]
        ax.bar(
            [
                position + (index - (len(flag_ids) - 1) / 2) * width
                for position in x_positions
            ],
            values,
            width=width,
            label=flag_labels[flag_id],
            color=METRIC_COLORS[index % len(METRIC_COLORS)],
        )

    ax.set_title(title)
    ax.set_ylabel("Rate")
    ax.set_ylim(0, 1.05)
    ax.set_xticks(x_positions)
    ax.set_xticklabels(labels)
    ax.grid(axis="y", alpha=0.25)
    ax.legend(loc="upper left")


def role_separation_subject_label(project: dict[str, object]) -> str:
    subject = str(project.get("role_separation_subject", "")).strip()
    return subject.title() if subject else "Project"


def show_role_separation_dashboard(
    project: dict[str, object],
    metrics_payload: dict[str, object],
) -> None:
    prompt_variant_summaries = list(metrics_payload.get("aggregate_by_prompt_variant", []))
    project_metadata = dict(metrics_payload.get("project_metadata", {}))
    coverage = dict(metrics_payload.get("coverage", {}))
    project_name = str(project_metadata.get("project_name", project["project_name"]))
    algorithm_flag_definitions = require_algorithm_flag_definitions(project_metadata)
    subject = role_separation_subject_label(project)
    algorithm_flag_groups = [
        (
            "kem_",
            f"{subject} KEM Algorithm Rates by Prompt Variant",
            (14, 7),
        ),
        (
            "signature_",
            f"{subject} Signature Algorithm Rates by Prompt Variant",
            (14, 7),
        ),
        (
            "dem_",
            f"{subject} DEM Algorithm Rates by Prompt Variant",
            (12, 7),
        ),
    ]

    figure, ax = plt.subplots(figsize=(12, 7))
    plot_role_separation_by_prompt_variant(ax, prompt_variant_summaries, subject)
    finalize_figure(
        figure,
        f"{subject} Role-Separation Status by Prompt Variant",
        project_name,
        coverage,
    )
    plt.show()

    for prefix, title, figsize in algorithm_flag_groups:
        category_definitions = algorithm_flag_definitions_for_prefix(
            algorithm_flag_definitions,
            prefix,
        )
        if not category_definitions:
            continue

        figure, ax = plt.subplots(figsize=figsize)
        plot_algorithm_flags_by_prompt_variant(
            ax,
            prompt_variant_summaries,
            category_definitions,
            title,
        )
        finalize_figure(
            figure,
            title,
            project_name,
            coverage,
        )
        plt.show()


def show_metrics_dashboard(
    project: dict[str, object],
    metrics_payload: dict[str, object],
) -> None:
    trial_metrics = list(metrics_payload.get("trial_metrics", []))
    if not trial_metrics:
        print(
            "No report data found for "
            f"{project['project_name']}. Run that project script first."
        )
        return

    prompt_variant_summaries = list(metrics_payload.get("aggregate_by_prompt_variant", []))
    project_metadata = dict(metrics_payload.get("project_metadata", {}))
    coverage = dict(metrics_payload.get("coverage", {}))
    evaluation_mode = str(
        project_metadata.get(
            "evaluation_mode",
            benchmark_logic.ROLE_SEPARATION_EVALUATION_MODE,
        )
    )

    if benchmark_logic.is_role_separation_evaluation_mode(evaluation_mode):
        show_role_separation_dashboard(project, metrics_payload)
        return

    raise ValueError(
        f"Unsupported evaluation mode in metrics payload: {evaluation_mode}"
    )


if __name__ == "__main__":
    args = parse_args()
    try:
        project = get_project(args.project)
    except ValueError as exc:
        raise SystemExit(str(exc))

    metrics = refresh_metrics(project)
    show_metrics_dashboard(project, metrics)
