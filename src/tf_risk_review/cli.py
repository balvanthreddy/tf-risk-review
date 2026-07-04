"""Command-line interface.

Exit codes are the contract with CI:
  0 — review passed (no findings at/above the fail threshold)
  1 — review failed the gate
  2 — usage or execution error (bad plan JSON, missing OPA, bad config)

The LLM summary and the GitHub comment are best-effort: their failures
warn but never change the exit code — a flaky LLM endpoint must not block
infrastructure delivery, and a review that can't post still prints.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from tf_risk_review import __version__
from tf_risk_review.config import ConfigError, ReviewConfig, load_config
from tf_risk_review.models import Report, Severity
from tf_risk_review.parser import PlanParseError, load_plan, plan_terraform_version
from tf_risk_review.policy.opa import OpaError, evaluate_rego
from tf_risk_review.render.json_out import render_json
from tf_risk_review.render.markdown import render_markdown
from tf_risk_review.render.text import render_text
from tf_risk_review.rules.engine import run_rules
from tf_risk_review.summary.llm import SummaryError, build_client, summarize


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tf-risk-review",
        description="Risk review for terraform plan output",
    )
    parser.add_argument("--version", action="version", version=f"tf-risk-review {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    review = sub.add_parser("review", help="Review a plan JSON file")
    review.add_argument("plan", type=Path, help="terraform show -json output")
    review.add_argument("--config", type=Path, default=None, help="Path to .tf-risk-review.yaml")
    review.add_argument(
        "--format", choices=("text", "markdown", "json"), default="text", dest="fmt"
    )
    review.add_argument("--output", type=Path, default=None, help="Write the report here too")
    review.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "never"),
        default=None,
        help="Override the configured fail threshold",
    )
    review.add_argument(
        "--rego-dir", type=Path, default=None, help="Directory of Rego policies (requires opa)"
    )
    review.add_argument(
        "--summarize",
        action="store_true",
        help="Add an advisory AI summary (TF_RISK_REVIEW_LLM_* env vars)",
    )
    review.add_argument(
        "--github-comment",
        action="store_true",
        help="Upsert the report as a PR comment (GitHub Actions environment)",
    )
    return parser


def _review(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
        changes = load_plan(args.plan)
    except (ConfigError, PlanParseError) as exc:
        print(f"tf-risk-review: {exc}", file=sys.stderr)
        return 2

    if args.fail_on is not None:
        config.fail_on = None if args.fail_on == "never" else Severity.parse(args.fail_on)

    findings = run_rules(changes, config)

    if args.rego_dir is not None:
        try:
            findings.extend(evaluate_rego(args.plan, args.rego_dir))
        except OpaError as exc:
            # Configured policy that cannot run is an error, not a skip.
            print(f"tf-risk-review: {exc}", file=sys.stderr)
            return 2
        findings.sort(key=lambda f: (-int(f.severity), f.address, f.rule_id))

    report = Report(
        findings=findings,
        changes=changes,
        terraform_version=plan_terraform_version(args.plan),
    )

    if args.summarize and report.findings:
        try:
            client = build_client()
            if client is None:
                print(
                    "tf-risk-review: --summarize set but "
                    "TF_RISK_REVIEW_LLM_PROVIDER=none; skipping",
                    file=sys.stderr,
                )
            else:
                report.summary_text = summarize(report, client)
        except SummaryError as exc:
            print(f"tf-risk-review: summary skipped: {exc}", file=sys.stderr)

    renderer = {"text": render_text, "markdown": render_markdown, "json": render_json}[args.fmt]
    output = renderer(report, config.fail_on)
    print(output)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")

    if args.github_comment:
        _post_comment(report, config)

    if config.fail_on is not None and report.fails_at(config.fail_on):
        return 1
    return 0


def _post_comment(report: Report, config: ReviewConfig) -> None:
    from tf_risk_review.github import GitHubError, detect_pr_number, upsert_pr_comment

    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    pr_number = detect_pr_number()
    if not token or not repo or pr_number is None:
        print(
            "tf-risk-review: --github-comment needs GITHUB_TOKEN, GITHUB_REPOSITORY, and a "
            "pull_request event; skipping comment",
            file=sys.stderr,
        )
        return
    try:
        outcome = upsert_pr_comment(render_markdown(report, config.fail_on), repo, pr_number, token)
        print(f"tf-risk-review: PR comment {outcome}", file=sys.stderr)
    except GitHubError as exc:
        print(f"tf-risk-review: comment failed: {exc}", file=sys.stderr)


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "review":
        raise SystemExit(_review(args))
    raise SystemExit(2)  # pragma: no cover - argparse enforces valid commands


if __name__ == "__main__":
    main()
