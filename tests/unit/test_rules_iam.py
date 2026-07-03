from __future__ import annotations

import json

from tests.factories import change
from tf_sentry.models import Action, Severity
from tf_sentry.rules.iam import (
    AdminPolicyAttachment,
    OpenTrustPolicy,
    StaticAccessKey,
    WildcardPolicy,
)


def _policy(*statements: dict) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


class TestWildcardPolicy:
    def test_star_on_star_is_critical(self) -> None:
        [finding] = WildcardPolicy().check(
            change(
                "aws_iam_policy",
                Action.CREATE,
                after={"policy": _policy({"Effect": "Allow", "Action": "*", "Resource": "*"})},
            )
        )
        assert finding.severity is Severity.CRITICAL
        assert "full admin" in finding.title

    def test_wildcard_action_scoped_resource_is_high(self) -> None:
        [finding] = WildcardPolicy().check(
            change(
                "aws_iam_policy",
                Action.CREATE,
                after={
                    "policy": _policy(
                        {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b/*"}
                    )
                },
            )
        )
        assert finding.severity is Severity.HIGH

    def test_notaction_flagged(self) -> None:
        [finding] = WildcardPolicy().check(
            change(
                "aws_iam_policy",
                Action.CREATE,
                after={
                    "policy": _policy({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
                },
            )
        )
        assert "NotAction" in finding.title

    def test_write_actions_on_star_resource_flagged(self) -> None:
        [finding] = WildcardPolicy().check(
            change(
                "aws_iam_policy",
                Action.CREATE,
                after={
                    "policy": _policy(
                        {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "*"}
                    )
                },
            )
        )
        assert "Resource: *" in finding.title

    def test_scoped_readonly_policy_clean(self) -> None:
        assert (
            WildcardPolicy().check(
                change(
                    "aws_iam_policy",
                    Action.CREATE,
                    after={
                        "policy": _policy(
                            {
                                "Effect": "Allow",
                                "Action": ["s3:GetObject", "s3:ListBucket"],
                                "Resource": "*",
                            }
                        )
                    },
                )
            )
            == []
        )

    def test_deny_statements_ignored(self) -> None:
        assert (
            WildcardPolicy().check(
                change(
                    "aws_iam_policy",
                    Action.CREATE,
                    after={"policy": _policy({"Effect": "Deny", "Action": "*", "Resource": "*"})},
                )
            )
            == []
        )

    def test_unchanged_policy_on_update_ignored(self) -> None:
        policy = _policy({"Effect": "Allow", "Action": "*", "Resource": "*"})
        assert (
            WildcardPolicy().check(
                change(
                    "aws_iam_policy",
                    Action.UPDATE,
                    before={"policy": policy, "name": "a"},
                    after={"policy": policy, "name": "b"},
                )
            )
            == []
        )

    def test_malformed_policy_json_does_not_crash(self) -> None:
        assert (
            WildcardPolicy().check(
                change("aws_iam_policy", Action.CREATE, after={"policy": "{not json"})
            )
            == []
        )


class TestOpenTrustPolicy:
    def test_star_principal_flagged(self) -> None:
        [finding] = OpenTrustPolicy().check(
            change(
                "aws_iam_role",
                Action.CREATE,
                after={
                    "assume_role_policy": _policy(
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "*"},
                            "Action": "sts:AssumeRole",
                        }
                    )
                },
            )
        )
        assert finding.rule_id == "IAM002"
        assert finding.severity is Severity.CRITICAL

    def test_star_principal_with_condition_allowed(self) -> None:
        assert (
            OpenTrustPolicy().check(
                change(
                    "aws_iam_role",
                    Action.CREATE,
                    after={
                        "assume_role_policy": _policy(
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "*"},
                                "Action": "sts:AssumeRole",
                                "Condition": {"StringEquals": {"sts:ExternalId": "expected-id"}},
                            }
                        )
                    },
                )
            )
            == []
        )

    def test_scoped_principal_clean(self) -> None:
        assert (
            OpenTrustPolicy().check(
                change(
                    "aws_iam_role",
                    Action.CREATE,
                    after={
                        "assume_role_policy": _policy(
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        )
                    },
                )
            )
            == []
        )


class TestAdminAttachment:
    def test_administrator_access_flagged(self) -> None:
        [finding] = AdminPolicyAttachment().check(
            change(
                "aws_iam_role_policy_attachment",
                Action.CREATE,
                after={"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
            )
        )
        assert finding.rule_id == "IAM003"

    def test_scoped_managed_policy_clean(self) -> None:
        assert (
            AdminPolicyAttachment().check(
                change(
                    "aws_iam_role_policy_attachment",
                    Action.CREATE,
                    after={"policy_arn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"},
                )
            )
            == []
        )


class TestStaticAccessKey:
    def test_creation_flagged(self) -> None:
        [finding] = StaticAccessKey().check(
            change("aws_iam_access_key", Action.CREATE, after={"user": "bot"})
        )
        assert finding.rule_id == "IAM004"
        assert "bot" in finding.evidence
