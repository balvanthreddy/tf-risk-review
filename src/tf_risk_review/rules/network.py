"""Network exposure rules."""

from __future__ import annotations

from typing import Any

from tf_risk_review.models import Action, Finding, ResourceChange, Severity
from tf_risk_review.rules.base import ResourceRule

_CHANGE_ACTIONS = (Action.CREATE, Action.UPDATE, Action.REPLACE)
_WORLD = ("0.0.0.0/0", "::/0")

# Ports where world-open ingress is an incident, not a webserver.
_SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    5432: "PostgreSQL",
    3306: "MySQL",
    1433: "SQL Server",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    2379: "etcd",
    5601: "Kibana",
}


def _covers_sensitive_port(from_port: int, to_port: int, protocol: str) -> list[str]:
    if protocol in ("-1", "all"):
        return ["all protocols/ports"]
    if from_port == 0 and to_port in (0, 65535):
        return ["all ports"]
    return [
        f"{port} ({name})"
        for port, name in _SENSITIVE_PORTS.items()
        if from_port <= port <= to_port
    ]


class OpenIngress(ResourceRule):
    """NET001: security group ingress open to the world.

    CRITICAL when a sensitive port (SSH, RDP, databases) or everything is
    exposed; HIGH otherwise — 0.0.0.0/0 on 443 behind a public ALB is a
    decision, not automatically a defect.
    """

    id = "NET001"
    default_severity = Severity.HIGH

    def check(self, change: ResourceChange) -> list[Finding]:
        if change.action not in _CHANGE_ACTIONS:
            return []

        rules: list[dict[str, Any]] = []
        if change.resource_type == "aws_security_group":
            ingress = change.after_value("ingress")
            if isinstance(ingress, list):
                rules = [r for r in ingress if isinstance(r, dict)]
        elif change.resource_type == "aws_vpc_security_group_ingress_rule":
            rules = [
                {
                    "cidr_blocks": [
                        c
                        for c in (
                            change.after_value("cidr_ipv4"),
                            change.after_value("cidr_ipv6"),
                        )
                        if c
                    ],
                    "from_port": change.after_value("from_port"),
                    "to_port": change.after_value("to_port"),
                    "protocol": change.after_value("ip_protocol"),
                }
            ]
        else:
            return []

        findings: list[Finding] = []
        for rule in rules:
            cidrs = list(rule.get("cidr_blocks") or []) + list(rule.get("ipv6_cidr_blocks") or [])
            world = [c for c in cidrs if c in _WORLD]
            if not world:
                continue
            from_port = int(rule.get("from_port") or 0)
            to_port = int(rule.get("to_port") or 0)
            protocol = str(rule.get("protocol") or "")
            sensitive = _covers_sensitive_port(from_port, to_port, protocol)
            port_desc = (
                "all traffic" if protocol in ("-1", "all") else f"ports {from_port}-{to_port}"
            )

            finding = self.finding(
                change,
                title=f"Ingress open to the internet: {port_desc}",
                detail=(
                    f"Source {', '.join(world)} exposes {', '.join(sensitive)} to every "
                    "host on the internet."
                    if sensitive
                    else f"Source {', '.join(world)} allows {port_desc} from any host."
                ),
                evidence=f"cidr={world} from_port={from_port} to_port={to_port} proto={protocol}",
                remediation=(
                    "Restrict to known CIDRs, a bastion/VPN source security group, or "
                    "put the service behind a load balancer and keep the instance "
                    "group private."
                ),
            )
            if sensitive:
                finding = Finding(
                    rule_id=finding.rule_id,
                    severity=Severity.CRITICAL,
                    address=finding.address,
                    title=finding.title,
                    detail=finding.detail,
                    evidence=finding.evidence,
                    remediation=finding.remediation,
                )
            findings.append(finding)
        return findings


class PubliclyAccessibleDatabase(ResourceRule):
    """NET002: a database instance flagged publicly accessible."""

    id = "NET002"
    default_severity = Severity.HIGH

    _TYPES = frozenset({"aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster"})

    def check(self, change: ResourceChange) -> list[Finding]:
        if change.action not in _CHANGE_ACTIONS or change.resource_type not in self._TYPES:
            return []
        if change.after_value("publicly_accessible") is not True:
            return []
        if change.action is Action.UPDATE and not change.changed("publicly_accessible"):
            return []
        return [
            self.finding(
                change,
                title="Database publicly accessible",
                detail=(
                    "publicly_accessible=true gives the database a public endpoint; "
                    "reachability then depends only on security group rules holding."
                ),
                evidence="publicly_accessible: true",
                remediation=(
                    "Keep databases in private subnets; reach them via VPN, SSM, or a "
                    "bastion. If external access is a hard requirement, restrict "
                    "source CIDRs and enforce TLS."
                ),
            )
        ]
