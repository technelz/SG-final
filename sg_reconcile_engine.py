#!/usr/bin/env python3
"""
================================================================================
Enterprise AWS Security Group Reconciliation Engine
================================================================================

Purpose:
- Compare source AWS security groups against target AWS security groups.
- Build a dependency-aware graph of SG relationships.
- Produce Terraform-like execution planning.
- Support safe dry-run/report-only/apply execution.
- Create missing SG shells first, then reconcile rules, then sync tags.
================================================================================
"""

from __future__ import annotations

import sys
import json
import argparse
import re
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Set, DefaultDict
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


DEFAULT_REPORT_DIR = "sg_reports"
DEFAULT_ROLLBACK_DIR = "rollback"
DEFAULT_MAX_PREVIEW_ITEMS = 25

SYSTEM_TAG_KEYS_TO_IGNORE = {
    "aws:cloudformation:logical-id",
    "aws:cloudformation:stack-id",
    "aws:cloudformation:stack-name",
}

CFN_LOGICAL_ID_KEY = "aws:cloudformation:logical-id"
CFN_STACK_NAME_KEY = "aws:cloudformation:stack-name"

BOTO_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 10})


def log(msg: str) -> None:
    print(msg, file=sys.stdout, flush=True)


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def now_stamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def ensure_dir(path: str) -> None:
    if path:
        os.makedirs(path, exist_ok=True)


def write_json(path: str, data: Any) -> None:
    parent = os.path.dirname(path)
    if parent:
        ensure_dir(parent)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def tag_dict(tags: Optional[List[Dict[str, str]]]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for tag in tags or []:
        key = tag.get("Key")
        value = tag.get("Value")
        if key:
            result[key] = value or ""
    return result


def clean_tags_for_copy(tags: Optional[List[Dict[str, str]]]) -> List[Dict[str, str]]:
    cleaned: List[Dict[str, str]] = []
    for tag in tags or []:
        key = tag.get("Key")
        value = tag.get("Value")
        if not key:
            continue
        if key in SYSTEM_TAG_KEYS_TO_IGNORE:
            continue
        if key.startswith("aws:"):
            continue
        cleaned.append({"Key": key, "Value": value or ""})
    return cleaned


def normalize_text(value: Optional[str]) -> str:
    if not value:
        return ""
    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-+", "-", value)
    return value.strip("-")


def normalize_sg_name(name: Optional[str]) -> str:
    if not name:
        return ""
    value = normalize_text(name)
    value = re.sub(r"\b(prod|production|prd|dr|dev|qa|uat|test|stage|staging)\b", "", value)
    value = re.sub(r"\b\d{12}\b", "", value)
    value = re.sub(r"\bsg-[a-f0-9]{8,17}\b", "", value)
    value = re.sub(r"-[a-z0-9]{8,16}$", "", value)
    value = re.sub(r"-+", "-", value)
    return value.strip("-")


def get_tag_value(sg: Dict[str, Any], key: str) -> Optional[str]:
    return tag_dict(sg.get("Tags", [])).get(key)


def group_name(sg: Dict[str, Any]) -> str:
    return sg.get("GroupName") or ""


def group_id(sg: Dict[str, Any]) -> str:
    return sg.get("GroupId") or ""


def group_description(sg: Dict[str, Any]) -> str:
    return sg.get("Description") or ""


def is_default_sg(sg: Dict[str, Any]) -> bool:
    return group_name(sg) == "default"
def canonicalize_rule(rule: Dict[str, Any]) -> str:
    canonical = {
        "IpProtocol": rule.get("IpProtocol"),
        "FromPort": rule.get("FromPort"),
        "ToPort": rule.get("ToPort"),

        "IpRanges": sorted(
            [
                {
                    "CidrIp": r.get("CidrIp"),
                    "Description": r.get("Description"),
                }
                for r in rule.get("IpRanges", []) or []
            ],
            key=lambda x: json.dumps(x, sort_keys=True),
        ),

        "Ipv6Ranges": sorted(
            [
                {
                    "CidrIpv6": r.get("CidrIpv6"),
                    "Description": r.get("Description"),
                }
                for r in rule.get("Ipv6Ranges", []) or []
            ],
            key=lambda x: json.dumps(x, sort_keys=True),
        ),

        "PrefixListIds": sorted(
            [
                {
                    "PrefixListId": r.get("PrefixListId"),
                    "Description": r.get("Description"),
                }
                for r in rule.get("PrefixListIds", []) or []
            ],
            key=lambda x: json.dumps(x, sort_keys=True),
        ),

        "UserIdGroupPairs": sorted(
            [
                {
                    "GroupId": p.get("GroupId"),
                    "Description": p.get("Description"),
                }
                for p in rule.get("UserIdGroupPairs", []) or []
            ],
            key=lambda x: json.dumps(x, sort_keys=True),
        ),
    }

    return json.dumps(canonical, sort_keys=True)
def split_rule_diff(existing: List[Dict[str, Any]], desired: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    existing_map = {canonicalize_rule(rule): rule for rule in existing or []}
    desired_map = {canonicalize_rule(rule): rule for rule in desired or []}
    to_add = [desired_map[key] for key in desired_map.keys() - existing_map.keys()]
    to_remove = [existing_map[key] for key in existing_map.keys() - desired_map.keys()]
    return to_add, to_remove


@dataclass
class Args:
    json_path: Optional[str]
    source_profile: Optional[str]
    source_region: Optional[str]
    source_vpc_id: Optional[str]
    target_profile: Optional[str]
    target_region: Optional[str]
    target_vpc_id: str
    dry_run: bool
    report_only: bool
    yes: bool
    allow_legacy: bool
    allow_unresolved_dependencies: bool
    revoke_extra_rules: bool
    no_create_missing: bool
    no_sync_tags: bool
    report_path: str
    rollback_dir: str
    max_preview_items: int
    workers: int


@dataclass
class SgMatch:
    source_name: str
    source_id: str
    source_description: str
    target_name: Optional[str]
    target_id: Optional[str]
    canonical_name: str
    match_confidence: str
    matched_via: str
    strict_reason: str
    legacy_reason: Optional[str] = None
    ambiguous: bool = False
    ambiguous_candidates: List[str] = field(default_factory=list)


@dataclass
class RuleDependencyIssue:
    source_group_name: str
    source_group_id: str
    direction: str
    referenced_source_group_id: Optional[str]
    referenced_group_name: Optional[str]
    rule: Dict[str, Any]
    reason: str


@dataclass
class SgDrift:
    group_name: str
    source_group_id: str
    target_group_id: str
    missing_ingress: List[Dict[str, Any]]
    extra_ingress: List[Dict[str, Any]]
    missing_egress: List[Dict[str, Any]]
    extra_egress: List[Dict[str, Any]]
    tag_drift: bool
    tag_diff_count: int
    description_drift: bool
    match: SgMatch


@dataclass
class SgPlan:
    matches: List[SgMatch]
    drifts: List[SgDrift]
    missing: List[SgMatch]
    unresolved_dependencies: List[RuleDependencyIssue]
    duplicate_canonical_keys: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.matches)

    @property
    def strict_matches(self) -> int:
        return len([m for m in self.matches if m.target_id and m.match_confidence == "strict"])

    @property
    def legacy_matches(self) -> int:
        return len([m for m in self.matches if m.target_id and m.match_confidence == "legacy"])

    @property
    def missing_count(self) -> int:
        return len(self.missing)

    @property
    def drift_count(self) -> int:
        return len(self.drifts)

    @property
    def unresolved_dependency_count(self) -> int:
        return len(self.unresolved_dependencies)

    @property
    def in_sync_count(self) -> int:
        return max(self.total - self.missing_count - self.drift_count, 0)


@dataclass
class RollbackAction:
    operation: str
    payload: Dict[str, Any]


@dataclass
class ExecutionContext:
    ec2: Any
    target_vpc_id: str
    sg_id_map: Dict[str, str] = field(default_factory=dict)
    created_sgs: Set[str] = field(default_factory=set)
    failed_nodes: Set[str] = field(default_factory=set)
    rollback_actions: List[RollbackAction] = field(default_factory=list)


@dataclass
class SgGraphNode:
    sg_id: str
    sg_name: str
    account: str
    vpc_id: str
    depends_on: Set[str] = field(default_factory=set)
    dependents: Set[str] = field(default_factory=set)


class SgGraph:
    def __init__(self) -> None:
        self.nodes: Dict[str, SgGraphNode] = {}

    def add_node(self, node: SgGraphNode) -> None:
        self.nodes[node.sg_id] = node

    def add_edge(self, from_sg: str, to_sg: str) -> None:
        if from_sg not in self.nodes or to_sg not in self.nodes:
            return
        self.nodes[from_sg].depends_on.add(to_sg)
        self.nodes[to_sg].dependents.add(from_sg)


@dataclass
class ExecutionStep:
    action: str
    sg_id: str
    sg_name: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TerraformLikePlan:
    create: List[ExecutionStep] = field(default_factory=list)
    update: List[ExecutionStep] = field(default_factory=list)
    delete: List[ExecutionStep] = field(default_factory=list)
    skip: List[ExecutionStep] = field(default_factory=list)
    order: List[str] = field(default_factory=list)
    cycles: List[List[str]] = field(default_factory=list)


def build_ec2_client(profile: Optional[str], region: str) -> Any:
    session = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
    return session.client("ec2", config=BOTO_CONFIG)


def load_source_groups(json_path: Optional[str]) -> List[Dict[str, Any]]:
    if not json_path:
        raise ValueError("--json-path is required")
    data = read_json(json_path)
    if isinstance(data, dict) and "SecurityGroups" in data:
        groups = data["SecurityGroups"]
    elif isinstance(data, list):
        groups = data
    else:
        raise ValueError("Source JSON must be AWS describe-security-groups output or a list")
    return [sg for sg in groups if not is_default_sg(sg)]


def fetch_security_groups(ec2: Any, vpc_id: Optional[str]) -> List[Dict[str, Any]]:
    filters = []
    if vpc_id:
        filters.append({"Name": "vpc-id", "Values": [vpc_id]})
    groups: List[Dict[str, Any]] = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate(Filters=filters):
        for sg in page.get("SecurityGroups", []):
            if not is_default_sg(sg):
                groups.append(sg)
    return groups


def build_duplicate_canonical_index(groups: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    index: Dict[str, List[str]] = defaultdict(list)
    for sg in groups:
        canonical = normalize_sg_name(group_name(sg))
        if canonical:
            index[canonical].append(group_id(sg))
    return {k: v for k, v in index.items() if len(v) > 1}


def match_security_groups(source_groups: List[Dict[str, Any]], target_groups: List[Dict[str, Any]], allow_legacy: bool = False) -> Tuple[List[SgMatch], List[SgMatch], Dict[str, List[str]]]:
    target_by_exact_name = {group_name(sg): sg for sg in target_groups if group_name(sg)}
    target_by_cfn = {}
    for sg in target_groups:
        logical_id = get_tag_value(sg, CFN_LOGICAL_ID_KEY)
        stack_name = get_tag_value(sg, CFN_STACK_NAME_KEY)
        if logical_id and stack_name:
            target_by_cfn[(stack_name, logical_id)] = sg
    canonical_index: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for sg in target_groups:
        canonical_index[normalize_sg_name(group_name(sg))].append(sg)
    duplicates = build_duplicate_canonical_index(target_groups)
    matches, missing = [], []
    for src in source_groups:
        src_name, src_id, src_desc = group_name(src), group_id(src), group_description(src)
        canonical = normalize_sg_name(src_name)
        target = None
        confidence, matched_via, strict_reason, legacy_reason = "missing", "none", "", None
        ambiguous, ambiguous_candidates = False, []
        if src_name in target_by_exact_name:
            target = target_by_exact_name[src_name]
            confidence, matched_via, strict_reason = "strict", "exact_name", "Exact GroupName match"
        else:
            src_logical_id, src_stack_name = get_tag_value(src, CFN_LOGICAL_ID_KEY), get_tag_value(src, CFN_STACK_NAME_KEY)
            if src_logical_id and src_stack_name and (src_stack_name, src_logical_id) in target_by_cfn:
                target = target_by_cfn[(src_stack_name, src_logical_id)]
                confidence, matched_via, strict_reason = "strict", "cloudformation_tags", "CloudFormation stack-name/logical-id match"
        if not target and allow_legacy:
            candidates = canonical_index.get(canonical, [])
            if len(candidates) == 1:
                target = candidates[0]
                confidence, matched_via, strict_reason, legacy_reason = "legacy", "normalized_name", "No strict match", "Single normalized-name candidate"
            elif len(candidates) > 1:
                ambiguous, ambiguous_candidates = True, [group_id(c) for c in candidates]
                confidence, matched_via, strict_reason, legacy_reason = "ambiguous", "normalized_name", "Multiple normalized-name candidates", "Ambiguous normalized match blocked"
        record = SgMatch(src_name, src_id, src_desc, group_name(target) if target else None, group_id(target) if target else None, canonical, confidence, matched_via, strict_reason, legacy_reason, ambiguous, ambiguous_candidates)
        matches.append(record)
        if not target:
            missing.append(record)
    return matches, missing, duplicates


def build_source_to_target_id_map(matches: List[SgMatch]) -> Dict[str, str]:
    return {m.source_id: m.target_id for m in matches if m.source_id and m.target_id}


def rewrite_user_id_group_pairs(permissions: List[Dict[str, Any]], id_map: Dict[str, str]) -> Tuple[List[Dict[str, Any]], List[RuleDependencyIssue]]:
    rewritten, issues = [], []
    for rule in permissions or []:
        new_rule = dict(rule)
        new_pairs = []
        for pair in rule.get("UserIdGroupPairs", []) or []:
            ref = pair.get("GroupId")
            if not ref:
                continue
            if ref in id_map:
                new_pair = dict(pair)
                new_pair["GroupId"] = id_map[ref]
                new_pair.pop("GroupName", None)
                new_pairs.append(new_pair)
            else:
                issues.append(RuleDependencyIssue("unknown", "unknown", "unknown", ref, pair.get("GroupName"), rule, "Referenced SG has no target mapping"))
        if new_pairs:
            new_rule["UserIdGroupPairs"] = new_pairs
        else:
            new_rule.pop("UserIdGroupPairs", None)
        rewritten.append(new_rule)
    return rewritten, issues


def rewrite_rules_for_source_group(sg: Dict[str, Any], id_map: Dict[str, str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[RuleDependencyIssue]]:
    ingress, i_issues = rewrite_user_id_group_pairs(sg.get("IpPermissions", []) or [], id_map)
    egress, e_issues = rewrite_user_id_group_pairs(sg.get("IpPermissionsEgress", []) or [], id_map)
    for issue in i_issues:
        issue.source_group_name, issue.source_group_id, issue.direction = group_name(sg), group_id(sg), "ingress"
    for issue in e_issues:
        issue.source_group_name, issue.source_group_id, issue.direction = group_name(sg), group_id(sg), "egress"
    return ingress, egress, i_issues + e_issues


def compare_tags(source: Dict[str, Any], target: Dict[str, Any]) -> Tuple[bool, int]:
    src_tags = {k: v for k, v in tag_dict(source.get("Tags", [])).items() if k not in SYSTEM_TAG_KEYS_TO_IGNORE and not k.startswith("aws:")}
    tgt_tags = {k: v for k, v in tag_dict(target.get("Tags", [])).items() if k not in SYSTEM_TAG_KEYS_TO_IGNORE and not k.startswith("aws:")}
    diff_keys = set(src_tags.keys()) ^ set(tgt_tags.keys())
    changed = {k for k in set(src_tags.keys()) & set(tgt_tags.keys()) if src_tags[k] != tgt_tags[k]}
    count = len(diff_keys) + len(changed)
    return count > 0, count


def detect_security_group_drifts(
    source_groups: List[Dict[str, Any]],
    target_groups: List[Dict[str, Any]],
    matches: List[SgMatch],
) -> Tuple[List[SgDrift], List[RuleDependencyIssue]]:

    source_by_id = {
        group_id(sg): sg
        for sg in source_groups
        if group_id(sg)
    }

    target_by_id = {
        group_id(sg): sg
        for sg in target_groups
        if group_id(sg)
    }

    id_map = build_source_to_target_id_map(matches)

    drifts: List[SgDrift] = []
    unresolved: List[RuleDependencyIssue] = []

    for match in matches:
        if not match.target_id:
            continue

        source = source_by_id.get(match.source_id)
        target = target_by_id.get(match.target_id)

        if not source or not target:
            continue

        desired_ingress, desired_egress, issues = rewrite_rules_for_source_group(
            source,
            id_map,
        )

        unresolved.extend(issues)

        missing_ingress, extra_ingress = split_rule_diff(
            target.get("IpPermissions", []) or [],
            desired_ingress,
        )

        missing_egress, extra_egress = split_rule_diff(
            target.get("IpPermissionsEgress", []) or [],
            desired_egress,
        )

        # Policy:
        # Extra target rules are acceptable.
        # The target only needs to contain everything required by source.
        extra_ingress = []
        extra_egress = []

        tag_drift, tag_diff_count = compare_tags(source, target)
        description_drift = group_description(source) != group_description(target)

        has_drift = any(
            [
                missing_ingress,
                missing_egress,
                tag_drift,
                description_drift,
            ]
        )

        if has_drift:
            drifts.append(
                SgDrift(
                    group_name=match.source_name,
                    source_group_id=match.source_id,
                    target_group_id=match.target_id,
                    missing_ingress=missing_ingress,
                    extra_ingress=extra_ingress,
                    missing_egress=missing_egress,
                    extra_egress=extra_egress,
                    tag_drift=tag_drift,
                    tag_diff_count=tag_diff_count,
                    description_drift=description_drift,
                    match=match,
                )
            )

    return drifts, unresolved


def build_plan(source_groups: List[Dict[str, Any]], target_groups: List[Dict[str, Any]], allow_legacy: bool) -> SgPlan:
    matches, missing, duplicates = match_security_groups(source_groups, target_groups, allow_legacy)
    drifts, unresolved = detect_security_group_drifts(source_groups, target_groups, matches)
    return SgPlan(matches, drifts, missing, unresolved, duplicates)


def build_dependency_graph(plan: SgPlan, source_groups: List[Dict[str, Any]], target_groups: List[Dict[str, Any]]) -> SgGraph:
    graph = SgGraph()
    source_by_id = {group_id(sg): sg for sg in source_groups if group_id(sg)}
    for match in plan.matches:
        src = source_by_id.get(match.source_id)
        if src:
            graph.add_node(SgGraphNode(match.source_id, match.source_name, "source", src.get("VpcId", "source")))
    for match in plan.matches:
        src = source_by_id.get(match.source_id)
        if not src:
            continue
        permissions = (src.get("IpPermissions", []) or []) + (src.get("IpPermissionsEgress", []) or [])
        for rule in permissions:
            for pair in rule.get("UserIdGroupPairs", []) or []:
                ref_id = pair.get("GroupId")
                if ref_id and ref_id in graph.nodes:
                    graph.add_edge(match.source_id, ref_id)
    return graph


def topo_sort(graph: SgGraph) -> Tuple[List[str], List[List[str]]]:
    in_degree: Dict[str, int] = defaultdict(int)
    for node in graph.nodes.values():
        in_degree[node.sg_id] = 0
    for node in graph.nodes.values():
        for _dep in node.depends_on:
            in_degree[node.sg_id] += 1
    queue = deque([node_id for node_id, degree in in_degree.items() if degree == 0])
    ordered, visited = [], set()
    while queue:
        current = queue.popleft()
        ordered.append(current)
        visited.add(current)
        for dependent in graph.nodes[current].dependents:
            in_degree[dependent] -= 1
            if in_degree[dependent] == 0:
                queue.append(dependent)
    remaining = [node_id for node_id in graph.nodes if node_id not in visited]
    cycles = []
    if remaining:
        cycles.append(remaining)
        ordered.extend(remaining)
    return ordered, cycles


def build_terraform_like_plan(plan: SgPlan, graph: SgGraph, source_groups: List[Dict[str, Any]], target_groups: List[Dict[str, Any]]) -> TerraformLikePlan:
    source_map = {group_id(sg): sg for sg in source_groups if group_id(sg)}
    ordered, cycles = topo_sort(graph)
    tf_plan = TerraformLikePlan(order=ordered, cycles=cycles)
    matched_targets = {m.source_id: m.target_id for m in plan.matches if m.source_id and m.target_id}
    drift_by_source_id = {d.source_group_id: d for d in plan.drifts}
    for sg_id in ordered:
        src = source_map.get(sg_id)
        if not src:
            continue
        target_id = matched_targets.get(sg_id)
        if not target_id:
            tf_plan.create.append(ExecutionStep("CREATE", sg_id, group_name(src), {"reason": "missing in target", "source_description": group_description(src), "source_vpc_id": src.get("VpcId")}))
            continue
        drift = drift_by_source_id.get(sg_id)
        if drift:
            tf_plan.update.append(ExecutionStep("UPDATE", sg_id, group_name(src), {"target_group_id": target_id, "missing_ingress": len(drift.missing_ingress), "extra_ingress": len(drift.extra_ingress), "missing_egress": len(drift.missing_egress), "extra_egress": len(drift.extra_egress), "tag_drift": drift.tag_drift, "tag_diff_count": drift.tag_diff_count, "description_drift": drift.description_drift}))
        else:
            tf_plan.skip.append(ExecutionStep("SKIP", sg_id, group_name(src), {"reason": "already in sync", "target_group_id": target_id}))
    return tf_plan


def print_plan_summary(plan: SgPlan) -> None:
    log("\n================ SECURITY GROUP PLAN SUMMARY ================")
    log(f"Total source SGs            : {plan.total}")
    log(f"Strict matches              : {plan.strict_matches}")
    log(f"Legacy normalized matches   : {plan.legacy_matches}")
    log(f"Missing in target           : {plan.missing_count}")
    log(f"Drifted SGs                 : {plan.drift_count}")
    log(f"Unresolved dependencies     : {plan.unresolved_dependency_count}")
    log(f"In sync                     : {plan.in_sync_count}")
    log("============================================================\n")


def render_match_preview(plan: SgPlan, limit: int = DEFAULT_MAX_PREVIEW_ITEMS) -> None:
    log("================ MATCH PREVIEW ================")
    for idx, match in enumerate(plan.matches[:limit], start=1):
        log(f"{idx:03d}. {match.source_name} ({match.source_id}) -> {match.target_name or 'MISSING'} ({match.target_id or '-'}) [{match.match_confidence}/{match.matched_via}]")
    if len(plan.matches) > limit:
        log(f"... truncated {len(plan.matches) - limit} additional match record(s)")
    log("===============================================\n")


def print_terraform_like_plan(tf_plan: TerraformLikePlan) -> None:
    log("\n================ TERRAFORM-LIKE EXECUTION PLAN ================")
    log("\n[ORDER]")
    for idx, sg_id in enumerate(tf_plan.order, start=1):
        log(f" {idx:03d}. {sg_id}")
    if tf_plan.cycles:
        log("\n[WARNING] Dependency cycle(s) detected:")
        for cycle in tf_plan.cycles:
            log(f" - CYCLE: {' -> '.join(cycle)}")
    for title, symbol, steps in [("CREATE", "+", tf_plan.create), ("UPDATE", "~", tf_plan.update), ("DELETE", "-", tf_plan.delete), ("SKIP", "=", tf_plan.skip)]:
        log(f"\n[{title}]")
        if not steps:
            log(" none")
        for step in steps:
            log(f" {symbol} {step.action} {step.sg_name} ({step.sg_id}) :: {step.details}")
    log("\n===============================================================\n")


def plan_to_dict(plan: SgPlan) -> Dict[str, Any]:
    return {"summary": {"total": plan.total, "strict_matches": plan.strict_matches, "legacy_matches": plan.legacy_matches, "missing": plan.missing_count, "drifted": plan.drift_count, "unresolved_dependencies": plan.unresolved_dependency_count, "in_sync": plan.in_sync_count}, "matches": [asdict(m) for m in plan.matches], "missing": [asdict(m) for m in plan.missing], "drifts": [asdict(d) for d in plan.drifts], "unresolved_dependencies": [asdict(i) for i in plan.unresolved_dependencies], "duplicate_canonical_keys": plan.duplicate_canonical_keys}


def terraform_plan_to_dict(tf_plan: TerraformLikePlan) -> Dict[str, Any]:
    return {"order": tf_plan.order, "cycles": tf_plan.cycles, "create": [asdict(step) for step in tf_plan.create], "update": [asdict(step) for step in tf_plan.update], "delete": [asdict(step) for step in tf_plan.delete], "skip": [asdict(step) for step in tf_plan.skip], "summary": {"create": len(tf_plan.create), "update": len(tf_plan.update), "delete": len(tf_plan.delete), "skip": len(tf_plan.skip), "cycles": len(tf_plan.cycles)}}


def render_full_plan(source_groups: List[Dict[str, Any]], target_groups: List[Dict[str, Any]], allow_legacy: bool, max_preview_items: int) -> Tuple[SgPlan, SgGraph, TerraformLikePlan]:
    sg_plan = build_plan(source_groups, target_groups, allow_legacy)
    graph = build_dependency_graph(sg_plan, source_groups, target_groups)
    tf_plan = build_terraform_like_plan(sg_plan, graph, source_groups, target_groups)
    print_plan_summary(sg_plan)
    render_match_preview(sg_plan, limit=max_preview_items)
    print_terraform_like_plan(tf_plan)
    return sg_plan, graph, tf_plan


def find_existing_sg_by_group_name(ec2: Any, vpc_id: str, group_name_value: str) -> Optional[str]:
    try:
        resp = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": [group_name_value]}])
        groups = resp.get("SecurityGroups", [])
        if groups:
            return groups[0].get("GroupId")
    except ClientError as exc:
        eprint(f"[WARN] Could not lookup existing SG {group_name_value}: {exc}")
    return None


def create_sg_shell(context: ExecutionContext, source_sg: Dict[str, Any], dry_run: bool) -> Optional[str]:
    name = group_name(source_sg)
    desc = group_description(source_sg) or f"Replicated security group: {name}"
    if dry_run:
        log(f"[DRY-RUN] Would create SG shell: {name}")
        return f"dryrun-{group_id(source_sg)}"
    try:
        resp = context.ec2.create_security_group(GroupName=name, Description=desc[:255], VpcId=context.target_vpc_id, TagSpecifications=[{"ResourceType": "security-group", "Tags": clean_tags_for_copy(source_sg.get("Tags", []))}])
        target_id = resp["GroupId"]
        context.created_sgs.add(target_id)
        context.rollback_actions.append(RollbackAction("delete_security_group", {"GroupId": target_id}))
        log(f"[CREATE] Created SG shell: {name} -> {target_id}")
        return target_id
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "InvalidGroup.Duplicate":
            existing_id = find_existing_sg_by_group_name(context.ec2, context.target_vpc_id, name)
            if existing_id:
                log(f"[INFO] SG already exists: {name} -> {existing_id}")
                return existing_id
        eprint(f"[ERROR] Failed creating SG shell {name}: {exc}")
        context.failed_nodes.add(group_id(source_sg))
        return None


def safe_authorize_ingress(context: ExecutionContext, group_id_value: str, permissions: List[Dict[str, Any]], dry_run: bool) -> None:
    if not permissions:
        return
    if dry_run:
        log(f"[DRY-RUN] Would authorize {len(permissions)} ingress rule block(s) on {group_id_value}")
        return
    try:
        context.ec2.authorize_security_group_ingress(GroupId=group_id_value, IpPermissions=permissions)
        context.rollback_actions.append(RollbackAction("revoke_security_group_ingress", {"GroupId": group_id_value, "IpPermissions": permissions}))
        log(f"[INGRESS] Added {len(permissions)} ingress rule block(s) on {group_id_value}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidPermission.Duplicate":
            log(f"[INFO] Duplicate ingress ignored on {group_id_value}")
            return
        raise


def safe_authorize_egress(context: ExecutionContext, group_id_value: str, permissions: List[Dict[str, Any]], dry_run: bool) -> None:
    if not permissions:
        return
    if dry_run:
        log(f"[DRY-RUN] Would authorize {len(permissions)} egress rule block(s) on {group_id_value}")
        return
    try:
        context.ec2.authorize_security_group_egress(GroupId=group_id_value, IpPermissions=permissions)
        context.rollback_actions.append(RollbackAction("revoke_security_group_egress", {"GroupId": group_id_value, "IpPermissions": permissions}))
        log(f"[EGRESS] Added {len(permissions)} egress rule block(s) on {group_id_value}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidPermission.Duplicate":
            log(f"[INFO] Duplicate egress ignored on {group_id_value}")
            return
        raise


def safe_revoke_ingress(context: ExecutionContext, group_id_value: str, permissions: List[Dict[str, Any]], dry_run: bool) -> None:
    if not permissions:
        return
    if dry_run:
        log(f"[DRY-RUN] Would revoke {len(permissions)} ingress rule block(s) on {group_id_value}")
        return
    try:
        context.ec2.revoke_security_group_ingress(GroupId=group_id_value, IpPermissions=permissions)
        context.rollback_actions.append(RollbackAction("authorize_security_group_ingress", {"GroupId": group_id_value, "IpPermissions": permissions}))
        log(f"[INGRESS] Revoked {len(permissions)} extra ingress rule block(s) on {group_id_value}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidPermission.NotFound":
            log(f"[INFO] Ingress rule already absent on {group_id_value}")
            return
        raise


def safe_revoke_egress(context: ExecutionContext, group_id_value: str, permissions: List[Dict[str, Any]], dry_run: bool) -> None:
    if not permissions:
        return
    if dry_run:
        log(f"[DRY-RUN] Would revoke {len(permissions)} egress rule block(s) on {group_id_value}")
        return
    try:
        context.ec2.revoke_security_group_egress(GroupId=group_id_value, IpPermissions=permissions)
        context.rollback_actions.append(RollbackAction("authorize_security_group_egress", {"GroupId": group_id_value, "IpPermissions": permissions}))
        log(f"[EGRESS] Revoked {len(permissions)} extra egress rule block(s) on {group_id_value}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidPermission.NotFound":
            log(f"[INFO] Egress rule already absent on {group_id_value}")
            return
        raise


def sync_tags(context: ExecutionContext, target_group_id: str, source_sg: Dict[str, Any], dry_run: bool) -> None:
    tags = clean_tags_for_copy(source_sg.get("Tags", []))
    if not tags:
        return
    if dry_run:
        log(f"[DRY-RUN] Would sync {len(tags)} tag(s) on {target_group_id}")
        return
    context.ec2.create_tags(Resources=[target_group_id], Tags=tags)
    log(f"[TAGS] Synced {len(tags)} tag(s) on {target_group_id}")


def ensure_sg_shells_from_graph(context: ExecutionContext, graph: SgGraph, plan: SgPlan, source_groups: List[Dict[str, Any]], dry_run: bool, no_create_missing: bool) -> None:
    source_by_id = {group_id(sg): sg for sg in source_groups if group_id(sg)}
    for match in plan.matches:
        if match.target_id:
            context.sg_id_map[match.source_id] = match.target_id
    if no_create_missing:
        log("[INFO] Missing SG shell creation disabled.")
        return
    ordered, cycles = topo_sort(graph)
    if cycles:
        log("[WARN] Cycle(s) detected. Shell-first creation will continue safely.")
    for src_id in ordered:
        if src_id in context.sg_id_map:
            continue
        source_sg = source_by_id.get(src_id)
        if not source_sg:
            continue
        target_id = create_sg_shell(context, source_sg, dry_run)
        if target_id:
            context.sg_id_map[src_id] = target_id
        else:
            context.failed_nodes.add(src_id)


def apply_rules_from_plan(
    context: ExecutionContext,
    plan: SgPlan,
    source_groups: List[Dict[str, Any]],
    target_groups: List[Dict[str, Any]],
    dry_run: bool,
    revoke_extra_rules: bool,
    allow_unresolved_dependencies: bool,
) -> None:
    source_by_id = {
        group_id(sg): sg
        for sg in source_groups
        if group_id(sg)
    }

    target_by_id = {
        group_id(sg): sg
        for sg in target_groups
        if group_id(sg)
    }

    unresolved_all: List[RuleDependencyIssue] = []

    for match in plan.matches:
        src_id = match.source_id

        if src_id in context.failed_nodes:
            log(f"[SKIP] Skipping failed source SG: {match.source_name} ({src_id})")
            continue

        target_id = context.sg_id_map.get(src_id) or match.target_id

        if not target_id:
            log(f"[SKIP] No target SG for {match.source_name} ({src_id})")
            continue

        source_sg = source_by_id.get(src_id)

        if not source_sg:
            continue

        target_sg = target_by_id.get(target_id)

        if not target_sg and not dry_run:
            try:
                resp = context.ec2.describe_security_groups(GroupIds=[target_id])
                target_sg = resp["SecurityGroups"][0]
            except ClientError as exc:
                eprint(f"[ERROR] Could not refresh target SG {target_id}: {exc}")
                context.failed_nodes.add(src_id)
                continue

        if dry_run and not target_sg:
            target_sg = {
                "GroupId": target_id,
                "IpPermissions": [],
                "IpPermissionsEgress": [],
            }

        desired_ingress, desired_egress, issues = rewrite_rules_for_source_group(
            source_sg,
            context.sg_id_map,
        )

        if issues:
            unresolved_all.extend(issues)

            if not allow_unresolved_dependencies:
                eprint(
                    f"[BLOCKED] {match.source_name} has unresolved SG reference dependencies."
                )
                context.failed_nodes.add(src_id)
                continue

        ingress_to_add, ingress_to_remove = split_rule_diff(
            target_sg.get("IpPermissions", []) or [],
            desired_ingress,
        )

        egress_to_add, egress_to_remove = split_rule_diff(
            target_sg.get("IpPermissionsEgress", []) or [],
            desired_egress,
        )

        try:
            # Source-required-only mode:
            # Add only rules that exist in source but are missing in target.
            safe_authorize_ingress(
                context,
                target_id,
                ingress_to_add,
                dry_run,
            )

            safe_authorize_egress(
                context,
                target_id,
                egress_to_add,
                dry_run,
            )

            # Extra target rules are intentionally tolerated.
            # Do not revoke ingress_to_remove or egress_to_remove.
            if revoke_extra_rules:
                log(
                    f"[INFO] --revoke-extra-rules ignored for {match.source_name}; "
                    "extra target rules are allowed by policy."
                )

        except ClientError as exc:
            eprint(
                f"[ERROR] Rule reconciliation failed for "
                f"{match.source_name} ({target_id}): {exc}"
            )
            context.failed_nodes.add(src_id)

    if unresolved_all:
        log(f"[WARN] Total unresolved rule dependencies observed: {len(unresolved_all)}")

def apply_tags_final_pass(
    context: ExecutionContext,
    plan: SgPlan,
    source_groups: List[Dict[str, Any]],
    dry_run: bool,
    no_sync_tags: bool,
) -> None:
    if no_sync_tags:
        log("[INFO] Tag sync disabled.")
        return

    source_by_id = {
        group_id(sg): sg
        for sg in source_groups
        if group_id(sg)
    }

    drift_by_source_id = {
        drift.source_group_id: drift
        for drift in plan.drifts
    }

    for match in plan.matches:
        src_id = match.source_id

        if src_id in context.failed_nodes:
            continue

        target_id = context.sg_id_map.get(src_id) or match.target_id
        source_sg = source_by_id.get(src_id)

        if not target_id or not source_sg:
            continue

        drift = drift_by_source_id.get(src_id)
        target_was_created = target_id in context.created_sgs

        should_sync_tags = target_was_created or (drift is not None and drift.tag_drift)

        if not should_sync_tags:
            log(f"[SKIP] Tags already in sync for {match.source_name} ({target_id})")
            continue

        try:
            sync_tags(
                context=context,
                target_group_id=target_id,
                source_sg=source_sg,
                dry_run=dry_run,
            )
        except ClientError as exc:
            eprint(f"[ERROR] Tag sync failed for {match.source_name} ({target_id}): {exc}")
            context.failed_nodes.add(src_id)

def execute_reconciliation(context: ExecutionContext, sg_plan: SgPlan, graph: SgGraph, source_groups: List[Dict[str, Any]], target_groups: List[Dict[str, Any]], args: Args) -> None:
    log("\n================ EXECUTION START ================")
    ensure_sg_shells_from_graph(context, graph, sg_plan, source_groups, args.dry_run, args.no_create_missing)
    apply_rules_from_plan(context, sg_plan, source_groups, target_groups, args.dry_run, args.revoke_extra_rules, args.allow_unresolved_dependencies)
    apply_tags_final_pass(context, sg_plan, source_groups, args.dry_run, args.no_sync_tags)
    log("================ EXECUTION COMPLETE ================\n")


def write_rollback_journal(context: ExecutionContext, rollback_dir: str) -> Optional[str]:
    if not context.rollback_actions:
        return None
    ensure_dir(rollback_dir)
    path = os.path.join(rollback_dir, f"rollback_journal_{now_stamp()}.json")
    write_json(path, {"created_at_utc": datetime.utcnow().isoformat(), "rollback_actions": [asdict(a) for a in context.rollback_actions]})
    return path


def parse_args() -> Args:
    parser = argparse.ArgumentParser(description="Enterprise AWS Security Group Reconciliation Engine")
    parser.add_argument("--json-path", required=True, help="Path to source/prod SG export JSON")
    parser.add_argument("--source-profile", default=None)
    parser.add_argument("--source-region", default=None)
    parser.add_argument("--source-vpc-id", default=None)
    parser.add_argument("--target-profile", default=None)
    parser.add_argument("--target-region", required=True)
    parser.add_argument("--target-vpc-id", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--yes", action="store_true")
    mode.add_argument("--report-only", action="store_true")
    parser.add_argument("--allow-legacy", action="store_true")
    parser.add_argument("--allow-unresolved-dependencies", action="store_true")
    parser.add_argument("--revoke-extra-rules", action="store_true")
    parser.add_argument("--no-create-missing", action="store_true")
    parser.add_argument("--no-sync-tags", action="store_true")
    parser.add_argument("--report-path", default="")
    parser.add_argument("--rollback-dir", default=DEFAULT_ROLLBACK_DIR)
    parser.add_argument("--max-preview-items", type=int, default=DEFAULT_MAX_PREVIEW_ITEMS)
    parser.add_argument("--workers", type=int, default=4)
    ns = parser.parse_args()
    if not ns.dry_run and not ns.yes and not ns.report_only:
        ns.dry_run = True
    return Args(ns.json_path, ns.source_profile, ns.source_region, ns.source_vpc_id, ns.target_profile, ns.target_region, ns.target_vpc_id, ns.dry_run, ns.report_only, ns.yes, ns.allow_legacy, ns.allow_unresolved_dependencies, ns.revoke_extra_rules, ns.no_create_missing, ns.no_sync_tags, ns.report_path, ns.rollback_dir, ns.max_preview_items, ns.workers)


def build_report_payload(args: Args, sg_plan: SgPlan, tf_plan: TerraformLikePlan, context: Optional[ExecutionContext]) -> Dict[str, Any]:
    return {"created_at_utc": datetime.utcnow().isoformat(), "mode": {"dry_run": args.dry_run, "yes": args.yes, "report_only": args.report_only}, "target": {"profile": args.target_profile, "region": args.target_region, "vpc_id": args.target_vpc_id}, "options": {"allow_legacy": args.allow_legacy, "allow_unresolved_dependencies": args.allow_unresolved_dependencies, "revoke_extra_rules": args.revoke_extra_rules, "no_create_missing": args.no_create_missing, "no_sync_tags": args.no_sync_tags}, "sg_plan": plan_to_dict(sg_plan), "terraform_like_plan": terraform_plan_to_dict(tf_plan), "execution": {"created_sgs": sorted(list(context.created_sgs)) if context else [], "failed_nodes": sorted(list(context.failed_nodes)) if context else [], "sg_id_map": context.sg_id_map if context else {}, "rollback_actions_count": len(context.rollback_actions) if context else 0}}


def resolve_report_path(args: Args) -> str:
    if args.report_path:
        return args.report_path
    ensure_dir(DEFAULT_REPORT_DIR)
    mode = "dryrun" if args.dry_run else "apply" if args.yes else "report"
    return os.path.join(DEFAULT_REPORT_DIR, f"sg_reconcile_{mode}_{args.target_profile or 'default'}_{args.target_region}_{now_stamp()}.json")


def validate_execution_safety(args: Args, sg_plan: SgPlan) -> None:
    if args.yes and not args.target_vpc_id:
        raise ValueError("--target-vpc-id is required for apply mode")
    if args.yes and sg_plan.unresolved_dependencies and not args.allow_unresolved_dependencies:
        raise ValueError("Unresolved SG rule dependencies exist. Review report or use --allow-unresolved-dependencies only if acceptable.")
    ambiguous = [m for m in sg_plan.matches if m.ambiguous]
    if args.yes and ambiguous:
        raise ValueError(f"{len(ambiguous)} ambiguous SG match(es) detected. Apply is blocked.")


def main() -> int:
    args = parse_args()
    log("\n============================================================")
    log(" Enterprise AWS Security Group Reconciliation Engine")
    log("============================================================")
    log(f"[MODE] dry_run={args.dry_run}, yes={args.yes}, report_only={args.report_only}")
    log(f"[TARGET] profile={args.target_profile}, region={args.target_region}, vpc={args.target_vpc_id}")
    try:
        source_groups = load_source_groups(args.json_path)
        log(f"[SOURCE] Loaded {len(source_groups)} non-default source SG(s) from {args.json_path}")
        target_ec2 = build_ec2_client(args.target_profile, args.target_region)
        target_groups = fetch_security_groups(target_ec2, args.target_vpc_id)
        log(f"[TARGET] Loaded {len(target_groups)} non-default target SG(s) from live AWS")
        sg_plan, graph, tf_plan = render_full_plan(source_groups, target_groups, args.allow_legacy, args.max_preview_items)
        validate_execution_safety(args, sg_plan)
        context: Optional[ExecutionContext] = None
        if args.report_only:
            log("[REPORT-ONLY] No AWS changes will be attempted.")
        else:
            context = ExecutionContext(ec2=target_ec2, target_vpc_id=args.target_vpc_id)
            execute_reconciliation(context, sg_plan, graph, source_groups, target_groups, args)
            rollback_path = write_rollback_journal(context, args.rollback_dir)
            if rollback_path:
                log(f"[ROLLBACK] Journal written: {rollback_path}")
        report_payload = build_report_payload(args, sg_plan, tf_plan, context)
        report_path = resolve_report_path(args)
        write_json(report_path, report_payload)
        log(f"[REPORT] Written: {report_path}")
        log("\n[DONE] SG reconciliation completed.")
        return 0
    except KeyboardInterrupt:
        eprint("\n[ABORTED] Interrupted by user.")
        return 130
    except Exception as exc:
        eprint(f"\n[FATAL] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
