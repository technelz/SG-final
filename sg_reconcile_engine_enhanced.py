#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, ProfileNotFound

BOTO_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 10})
REPORT_DIR = "sg_reports"
ROLLBACK_DIR = "rollback"
CFN_LOGICAL = "aws:cloudformation:logical-id"
IGNORE_TAGS = {CFN_LOGICAL, "aws:cloudformation:stack-id", "aws:cloudformation:stack-name"}
ENV_TOKENS = {"prod", "production", "prd", "dr", "dev", "qa", "uat", "test", "stage", "staging"}
ROLE_TAG_KEYS = {"name", "application", "app", "service", "purpose", "component", "role", "tier", "networktype", "network-type"}
REGION_RE = re.compile(r"(?<=\.)(?:af|ap|ca|eu|il|me|mx|sa|us|cn|us-gov)-[a-z0-9-]+-\d+(?=\.)")
CFN_TRAILING_HASH_RE = re.compile(r"^(?P<base>.+)-(?P<hash>[a-z0-9]{8,})$", re.I)
CFN_STACK_PREFIX_RE = re.compile(r"^stack-[a-z0-9]{8,}-(?P<base>.+)$", re.I)
AZ_SUFFIX_RE = re.compile(r"(?:^|[-_])(az)?[a-z]$", re.I)


def log(x): print(x, flush=True)
def err(x): print(x, file=sys.stderr, flush=True)
def stamp(): return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
def ensure(path):
    if path: os.makedirs(path, exist_ok=True)
def dump(path, data):
    ensure(os.path.dirname(path));
    with open(path, "w", encoding="utf-8") as handle: json.dump(data, handle, indent=2, default=str)
def load(path):
    path = os.path.abspath(path); log(f"[INFO] Resolved info file: {path}")
    with open(path, encoding="utf-8") as handle: data = json.load(handle)
    if not isinstance(data, dict): raise ValueError("Info file must contain a JSON object")
    return data
def tags(x): return {t["Key"]: t.get("Value", "") for t in x or [] if t.get("Key")}
def gname(s): return s.get("GroupName", "")
def gid(s): return s.get("GroupId", "")
def desc(s): return s.get("Description", "")
def tag(s, key): return tags(s.get("Tags")).get(key)
def norm(v): return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", (v or "").lower().strip())).strip("-")
def semantic(v): return "-".join(t for t in norm(v).split("-") if t and t not in ENV_TOKENS)
def norm_name(v):
    x = norm(v); x = re.sub(r"\b(?:sg-[a-f0-9]{8,17}|\d{12})\b", "", x)
    return "-".join(t for t in x.split("-") if t and t not in ENV_TOKENS)
def exact_name(v): return (v or "").strip().lower().replace("\u2011", "-").replace("\u2013", "-").replace("\u2014", "-")
def cfn_stem(v):
    value = exact_name(v); trailing = CFN_TRAILING_HASH_RE.match(value)
    if not trailing: return ""
    base = trailing.group("base"); stack = CFN_STACK_PREFIX_RE.match(base)
    return norm(stack.group("base") if stack else base)
def directory_sg(v): return bool(re.match(r"^d-[0-9a-z]{8,}_(controllers|workers)$", (v or "").lower()))
def clean_tags(s): return [{"Key": k, "Value": v} for k, v in tags(s.get("Tags")).items() if not k.startswith("aws:") and k not in IGNORE_TAGS]
def port(v):
    try: return int(v) if v is not None else None
    except Exception: return v


@dataclass
class Args:
    info_file: str; source_profile: Optional[str]; source_region: str; source_vpc_id: str
    target_profile: Optional[str]; target_region: str; target_vpc_id: str
    dry_run: bool; report_only: bool; yes: bool; allow_legacy: bool
    allow_unresolved_dependencies: bool; no_create_missing: bool; no_sync_tags: bool
    report_path: str; rollback_dir: str

@dataclass
class Match:
    source_name: str; source_id: str; target_name: Optional[str]; target_id: Optional[str]
    canonical_name: str; confidence: str; matched_via: str; reason: str
    ambiguous: bool = False; candidates: List[str] = field(default_factory=list)

@dataclass
class Resolution:
    source_type: str; source_value: str; target_value: Optional[str]
    action: str; confidence: str; method: str; reason: str
    source_object_id: Optional[str] = None; target_object_id: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Issue:
    source_group_name: str; source_group_id: str; direction: str; dependency_type: str
    referenced_source_id: str; reason: str; rule: Dict[str, Any]
    resolution: Optional[Resolution] = None

@dataclass
class Drift:
    group_name: str; source_group_id: str; target_group_id: str
    missing_ingress: List[Dict[str, Any]]; missing_egress: List[Dict[str, Any]]
    tolerated_extra_ingress_count: int; tolerated_extra_egress_count: int; match: Match

@dataclass
class Plan:
    matches: List[Match]; missing: List[Match]; drifts: List[Drift]; unresolved: List[Issue]
    duplicate_keys: Dict[str, List[str]]; source_total: int; excluded_directory: int; evaluated: int
    resolutions: List[Resolution] = field(default_factory=list)

@dataclass
class Rollback:
    operation: str; payload: Dict[str, Any]

@dataclass
class SubnetInfo:
    subnet_id: str; cidr: str; ipv6_cidrs: List[str]; identity: str
    tag_identity: Tuple[Tuple[str, str], ...]; route_fingerprint: Tuple[str, ...]
    available_zone: str

@dataclass
class NetworkInventory:
    vpc_id: str; primary_ipv4: Optional[str]; ipv4_cidrs: List[str]; ipv6_cidrs: List[str]
    subnets: Dict[str, SubnetInfo]; route_destinations: Dict[str, Set[str]]

@dataclass
class NetworkMaps:
    subnet_map: Dict[str, str]; subnet_methods: Dict[str, str]
    vpc_cidr_map: Dict[str, str]; issues: List[Dict[str, Any]]

@dataclass
class Context:
    ec2: Any; target_vpc_id: str; prefix_map: Dict[str, str]; source_network: NetworkInventory
    target_network: NetworkInventory; network_maps: NetworkMaps
    sg_map: Dict[str, str] = field(default_factory=dict); created: Set[str] = field(default_factory=set)
    failed: Set[str] = field(default_factory=set); rollback: List[Rollback] = field(default_factory=list)
    resolutions: List[Resolution] = field(default_factory=list)


def session(profile, region): return boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
def credential_method(s):
    c = s.get_credentials(); return getattr(c, "method", "none") if c else "none"
def validate_identity(profile, region, expected, role):
    try:
        sess = session(profile, region); method = credential_method(sess)
        log(f"[AUTH] validating {role}: profile={profile or 'environment/default-chain'}, credential_source={method}")
        actual = sess.client("sts", config=BOTO_CONFIG).get_caller_identity()["Account"]
    except (ClientError, ProfileNotFound) as ex:
        raise RuntimeError(f"{role} authentication failed for profile={profile or 'environment/default-chain'}: {ex}") from ex
    if expected and str(expected) != actual: raise RuntimeError(f"{role} account mismatch: expected={expected}, actual={actual}")
    log(f"[IDENTITY] {role} account={actual} ({'validated' if expected else 'discovered'})")
    return actual
def ec2(profile, region): return session(profile, region).client("ec2", config=BOTO_CONFIG)
def fetch_sgs(client, vpc):
    out, defaults = [], 0
    for page in client.get_paginator("describe_security_groups").paginate(Filters=[{"Name": "vpc-id", "Values": [vpc]}]):
        for sg in page.get("SecurityGroups", []):
            if gname(sg) == "default": defaults += 1
            else: out.append(sg)
    return out, defaults
def fetch_prefixes(client):
    out = []
    for page in client.get_paginator("describe_managed_prefix_lists").paginate(): out += page.get("PrefixLists", [])
    return out


def subnet_identity(subnet):
    t = tags(subnet.get("Tags")); name = t.get("Name", "")
    base = AZ_SUFFIX_RE.sub("", semantic(name)).strip("-_")
    return base
def subnet_tag_identity(subnet):
    return tuple(sorted((norm(k), semantic(v)) for k, v in tags(subnet.get("Tags")).items() if norm(k) in ROLE_TAG_KEYS and v and norm(k) != "name"))
def route_type(route):
    if route.get("GatewayId", "").startswith("igw-"): return "internet_gateway"
    if route.get("NatGatewayId"): return "nat_gateway"
    if route.get("TransitGatewayId"): return "transit_gateway"
    if route.get("VpcPeeringConnectionId"): return "vpc_peering"
    if route.get("EgressOnlyInternetGatewayId"): return "egress_only_igw"
    if route.get("NetworkInterfaceId"): return "network_interface"
    if route.get("GatewayId", "").startswith("vpce-"): return "gateway_endpoint"
    if route.get("LocalGatewayId"): return "local_gateway"
    if route.get("CarrierGatewayId"): return "carrier_gateway"
    if route.get("GatewayId") == "local": return "local"
    return "other"
def route_destination(route): return route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock") or route.get("DestinationPrefixListId")

def fetch_network_inventory(client, vpc_id):
    vpcs = client.describe_vpcs(VpcIds=[vpc_id]).get("Vpcs", [])
    if len(vpcs) != 1: raise RuntimeError(f"VPC not found or not unique: {vpc_id}")
    vpc = vpcs[0]
    ipv4 = sorted({x.get("CidrBlock") for x in vpc.get("CidrBlockAssociationSet", []) if x.get("CidrBlockState", {}).get("State") == "associated" and x.get("CidrBlock")})
    if vpc.get("CidrBlock"): ipv4 = sorted(set(ipv4 + [vpc["CidrBlock"]]))
    ipv6 = sorted({x.get("Ipv6CidrBlock") for x in vpc.get("Ipv6CidrBlockAssociationSet", []) if x.get("Ipv6CidrBlockState", {}).get("State") == "associated" and x.get("Ipv6CidrBlock")})
    subs = []
    for page in client.get_paginator("describe_subnets").paginate(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]): subs += page.get("Subnets", [])
    rts = client.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get("RouteTables", [])
    explicit, main = {}, None
    for rt in rts:
        for assoc in rt.get("Associations", []):
            if assoc.get("SubnetId"): explicit[assoc["SubnetId"]] = rt
            if assoc.get("Main"): main = rt
    subnet_map, destinations = {}, defaultdict(set)
    for s in subs:
        rt = explicit.get(s["SubnetId"]) or main or {"Routes": []}
        fp = tuple(sorted({route_type(r) for r in rt.get("Routes", []) if route_type(r) != "local" and r.get("State", "active") == "active"}))
        for r in rt.get("Routes", []):
            d = route_destination(r)
            if d and r.get("State", "active") == "active": destinations[d].add(route_type(r))
        subnet_map[s["SubnetId"]] = SubnetInfo(s["SubnetId"], s.get("CidrBlock", ""), sorted(x.get("Ipv6CidrBlock") for x in s.get("Ipv6CidrBlockAssociationSet", []) if x.get("Ipv6CidrBlock")), subnet_identity(s), subnet_tag_identity(s), fp, s.get("AvailabilityZone", ""))
    return NetworkInventory(vpc_id, vpc.get("CidrBlock"), ipv4, ipv6, subnet_map, dict(destinations))


def pair_vpc_cidrs(src, tgt):
    mapping, issues = {}, []
    def pair_family(source_values, target_values, primary_source=None, primary_target=None):
        if primary_source and primary_target: mapping[primary_source] = primary_target
        remaining_s = [x for x in source_values if x not in mapping]
        remaining_t = [x for x in target_values if x not in mapping.values()]
        for s in remaining_s:
            sn = ipaddress.ip_network(s)
            cands = [t for t in remaining_t if ipaddress.ip_network(t).version == sn.version and ipaddress.ip_network(t).prefixlen == sn.prefixlen]
            if len(cands) == 1: mapping[s] = cands[0]; remaining_t.remove(cands[0])
            else: issues.append({"type": "vpc_cidr", "source": s, "reason": "no unique target CIDR with same address family and prefix length", "candidates": cands})
    pair_family(src.ipv4_cidrs, tgt.ipv4_cidrs, src.primary_ipv4, tgt.primary_ipv4)
    pair_family(src.ipv6_cidrs, tgt.ipv6_cidrs)
    return mapping, issues

def build_network_maps(src, tgt):
    mapping, methods, issues, used = {}, {}, [], set()
    targets = list(tgt.subnets.values())
    for sid, s in sorted(src.subnets.items()):
        candidates = [t for t in targets if t.subnet_id not in used and bool(s.cidr) == bool(t.cidr)]
        if s.tag_identity:
            strong = [t for t in candidates if t.tag_identity == s.tag_identity and t.route_fingerprint == s.route_fingerprint]
            if len(strong) == 1: candidates, method = strong, "purpose_tags_and_route_role"
            else: method = ""
        else: method = ""
        if not method and s.identity:
            named = [t for t in candidates if t.identity == s.identity and t.route_fingerprint == s.route_fingerprint]
            if len(named) == 1: candidates, method = named, "normalized_name_and_route_role"
        if not method:
            structural = [t for t in candidates if t.route_fingerprint == s.route_fingerprint and (not s.cidr or ipaddress.ip_network(t.cidr).prefixlen == ipaddress.ip_network(s.cidr).prefixlen)]
            if len(structural) == 1: candidates, method = structural, "unique_route_role_and_prefix"
        if method and len(candidates) == 1:
            mapping[sid] = candidates[0].subnet_id; methods[sid] = method; used.add(candidates[0].subnet_id)
        else:
            issues.append({"type": "subnet", "source": sid, "reason": "no deterministic target subnet equivalent", "candidates": [x.subnet_id for x in candidates]})
    vpc_map, vpc_issues = pair_vpc_cidrs(src, tgt); issues += vpc_issues
    return NetworkMaps(mapping, methods, vpc_map, issues)


def translate_relative(value, source_container, target_container):
    n, s, t = ipaddress.ip_network(value, strict=False), ipaddress.ip_network(source_container, strict=False), ipaddress.ip_network(target_container, strict=False)
    if n.version != s.version or s.version != t.version or not n.subnet_of(s): return None
    offset = int(n.network_address) - int(s.network_address)
    target_start = int(t.network_address) + offset
    try: candidate = ipaddress.ip_network((target_start, n.prefixlen), strict=False)
    except ValueError: return None
    return str(candidate) if candidate.subnet_of(t) and int(candidate.network_address) == target_start else None

def most_specific_container(value, entries):
    n = ipaddress.ip_network(value, strict=False); found = []
    for object_id, cidr in entries:
        try:
            container = ipaddress.ip_network(cidr, strict=False)
            if n.version == container.version and n.subnet_of(container): found.append((container.prefixlen, object_id, cidr))
        except ValueError: pass
    return max(found) if found else None

def compatible_external_route(cidr, src, tgt):
    def best(inv):
        n = ipaddress.ip_network(cidr, strict=False); found = []
        for d, kinds in inv.route_destinations.items():
            try:
                route = ipaddress.ip_network(d, strict=False)
                if route.version == n.version and n.subnet_of(route): found.append((route.prefixlen, kinds, d))
            except ValueError: pass
        return max(found, default=None, key=lambda x: x[0])
    a, b = best(src), best(tgt)
    return a and b and a[1] == b[1]

def resolve_cidr(value, src, tgt, maps):
    try: network = ipaddress.ip_network(value, strict=False)
    except ValueError: return Resolution("cidr", value, None, "FLAG", "LOW", "invalid_cidr", "CIDR is invalid")
    universal = (network.version == 4 and str(network) == "0.0.0.0/0") or (network.version == 6 and str(network) == "::/0")
    if universal: return Resolution("cidr", value, str(network), "PRESERVE", "HIGH", "universal_cidr", "Universal CIDR preserves the same network scope")
    subnet_entries = []
    for sid, s in src.subnets.items():
        if s.cidr: subnet_entries.append((sid, s.cidr))
        subnet_entries += [(sid, x) for x in s.ipv6_cidrs]
    hit = most_specific_container(str(network), subnet_entries)
    if hit:
        _, source_sid, source_cidr = hit; target_sid = maps.subnet_map.get(source_sid)
        if not target_sid: return Resolution("cidr", value, None, "FLAG", "LOW", "source_subnet_unmapped", "Containing source subnet has no deterministic DR equivalent", source_sid)
        ts = tgt.subnets[target_sid]; target_candidates = [ts.cidr] + ts.ipv6_cidrs
        target_container = next((x for x in target_candidates if ipaddress.ip_network(x).version == network.version), None)
        translated = translate_relative(str(network), source_cidr, target_container) if target_container else None
        if not translated: return Resolution("cidr", value, None, "FLAG", "LOW", "subnet_translation_does_not_fit", "Relative CIDR does not fit the mapped target subnet", source_sid, target_sid)
        return Resolution("cidr", value, translated, "TRANSLATE", "HIGH", "mapped_subnet_relative_offset", "CIDR translated through a unique semantic subnet mapping", source_sid, target_sid, {"subnet_match_method": maps.subnet_methods.get(source_sid)})
    hit = most_specific_container(str(network), [(x, x) for x in src.ipv4_cidrs + src.ipv6_cidrs])
    if hit:
        _, source_vpc_cidr, _ = hit; target_vpc_cidr = maps.vpc_cidr_map.get(source_vpc_cidr)
        if not target_vpc_cidr: return Resolution("cidr", value, None, "FLAG", "LOW", "source_vpc_cidr_unmapped", "Containing source VPC CIDR has no unique target association", source_vpc_cidr)
        translated = translate_relative(str(network), source_vpc_cidr, target_vpc_cidr)
        if not translated: return Resolution("cidr", value, None, "FLAG", "LOW", "vpc_translation_does_not_fit", "Relative CIDR does not fit the mapped target VPC CIDR", source_vpc_cidr, target_vpc_cidr)
        return Resolution("cidr", value, translated, "TRANSLATE", "HIGH", "mapped_vpc_relative_offset", "CIDR translated through the corresponding VPC CIDR association", source_vpc_cidr, target_vpc_cidr)
    if compatible_external_route(str(network), src, tgt):
        return Resolution("cidr", value, str(network), "PRESERVE", "HIGH", "shared_external_routed_network", "Compatible source and target routing evidence supports the same external CIDR")
    return Resolution("cidr", value, None, "FLAG", "LOW", "external_network_unresolved", "No deterministic target network relationship was discovered")


def prefix_name(v):
    x = (v or "").strip().lower(); return REGION_RE.sub("{region}", x) if x.startswith("com.amazonaws.") else x
def prefix_semantic(v): return semantic(v)
def referenced_prefixes(groups): return {x["PrefixListId"] for s in groups for r in s.get("IpPermissions", []) + s.get("IpPermissionsEgress", []) for x in r.get("PrefixListIds", []) if x.get("PrefixListId")}
def prefix_tag_identity(p): return tuple(sorted((norm(k), prefix_semantic(v)) for k, v in tags(p.get("Tags")).items() if norm(k) in ROLE_TAG_KEYS and v))
def map_prefixes(source, target, referenced):
    sb = {p["PrefixListId"]: p for p in source if p.get("PrefixListId")}; tb = {p["PrefixListId"]: p for p in target if p.get("PrefixListId")}
    mapping, issues = {}, []
    for sid in sorted(referenced):
        p = sb.get(sid)
        if not p: issues.append({"source_prefix_list_id": sid, "reason": "metadata not returned", "candidates": []}); continue
        if sid in tb: mapping[sid] = sid; continue
        fam = (p.get("AddressFamily") or "").lower(); pool = [x for x in target if (x.get("AddressFamily") or "").lower() == fam]
        if p.get("OwnerId") == "AWS": pool = [x for x in pool if x.get("OwnerId") == "AWS" and prefix_name(x.get("PrefixListName")) == prefix_name(p.get("PrefixListName"))]; method = "aws_service_name"
        else:
            exact = [x for x in pool if x.get("OwnerId") != "AWS" and (x.get("PrefixListName") or "").lower() == (p.get("PrefixListName") or "").lower()]
            if len(exact) == 1: pool, method = exact, "exact_name"
            else:
                pool = [x for x in pool if x.get("OwnerId") != "AWS" and prefix_semantic(x.get("PrefixListName")) == prefix_semantic(p.get("PrefixListName"))]; method = "environment_normalized_name"
                if len(pool) > 1 and prefix_tag_identity(p):
                    tagged = [x for x in pool if prefix_tag_identity(x) == prefix_tag_identity(p)]
                    if len(tagged) == 1: pool, method = tagged, "purpose_tags"
        if len(pool) == 1: mapping[sid] = pool[0]["PrefixListId"]; log(f"[PREFIX-LIST-AUTO] {sid} -> {mapping[sid]} via {method}")
        else: issues.append({"source_prefix_list_id": sid, "source_prefix_list_name": p.get("PrefixListName"), "reason": f"{'ambiguous' if pool else 'no'} automatic match via {method}", "candidates": [x["PrefixListId"] for x in pool]})
    return mapping, issues


def atomic_permission(proto, fp, tp, typ, value):
    obj = {"IpProtocol": proto}
    if proto != "-1":
        if fp is not None: obj["FromPort"] = fp
        if tp is not None: obj["ToPort"] = tp
    field_name, key = {"cidr": ("IpRanges", "CidrIp"), "ipv6": ("Ipv6Ranges", "CidrIpv6"), "prefix-list": ("PrefixListIds", "PrefixListId"), "sg": ("UserIdGroupPairs", "GroupId")}[typ]
    obj[field_name] = [{key: value}]; return obj
def atomic(rule):
    proto = rule.get("IpProtocol"); fp, tp = port(rule.get("FromPort")), port(rule.get("ToPort"))
    if proto == "-1": fp = tp = None
    out = []
    for field_name, key, typ in [("IpRanges", "CidrIp", "cidr"), ("Ipv6Ranges", "CidrIpv6", "ipv6"), ("PrefixListIds", "PrefixListId", "prefix-list"), ("UserIdGroupPairs", "GroupId", "sg")]:
        for item in rule.get(field_name, []) or []:
            if item.get(key): out.append(((proto, fp, tp, typ, item[key]), atomic_permission(proto, fp, tp, typ, item[key])))
    return out
def amap(rules): return {k: v for rule in rules or [] for k, v in atomic(rule)}
def diff(existing, desired):
    a, b = amap(existing), amap(desired); order = lambda k: json.dumps(k)
    return [b[k] for k in sorted(b.keys() - a.keys(), key=order)], [a[k] for k in sorted(a.keys() - b.keys(), key=order)]
def ref_identity(s):
    if not s: return "unknown"
    logical = tag(s, CFN_LOGICAL)
    if logical: return "logical:" + norm(logical)
    stem = cfn_stem(gname(s)); return "stem:" + stem if stem else "name:" + norm_name(gname(s))
def fingerprint(s, byid, prefix_map, source_side):
    result = set()
    for direction, rules in [("ingress", s.get("IpPermissions", [])), ("egress", s.get("IpPermissionsEgress", []))]:
        for rule in rules:
            for key, _ in atomic(rule):
                proto, fp, tp, typ, value = key
                if typ == "prefix-list" and source_side: value = prefix_map.get(value, value)
                if typ == "sg": value = ref_identity(byid.get(value))
                if typ in {"cidr", "ipv6"}: value = "network-source"
                result.add((direction, proto, fp, tp, typ, value))
    return result


def duplicate_index(groups):
    values = defaultdict(list)
    for sg in groups: values[norm_name(gname(sg))].append(gid(sg))
    return {k: v for k, v in values.items() if k and len(v) > 1}
def match_sgs(source, target, allow_legacy, prefix_map):
    sb, tb, used = {gid(x): x for x in source}, {gid(x): x for x in target}, set(); excluded = 0
    exact, logical, stems, normalized = defaultdict(list), defaultdict(list), defaultdict(list), defaultdict(list)
    for t in target:
        exact[exact_name(gname(t))].append(t); normalized[norm_name(gname(t))].append(t)
        if tag(t, CFN_LOGICAL): logical[norm(tag(t, CFN_LOGICAL))].append(t)
        if cfn_stem(gname(t)): stems[cfn_stem(gname(t))].append(t)
    sf = {gid(x): fingerprint(x, sb, prefix_map, True) for x in source}; tf = {gid(x): fingerprint(x, tb, prefix_map, False) for x in target}
    matches, missing = [], []
    available = lambda xs: [x for x in xs if gid(x) not in used]
    functional = lambda sid, xs: [x for x in available(xs) if sf.get(sid, set()).issubset(tf.get(gid(x), set()))]
    for s in source:
        if directory_sg(gname(s)): excluded += 1; continue
        sid = gid(s); candidate = None; via = "none"; reason = ""; confidence = "missing"; ambiguous = False; cands = []
        xs = available(exact[exact_name(gname(s))])
        if len(xs) == 1: candidate, via, reason, confidence = xs[0], "exact_name", "unique exact name", "strict"
        elif len(xs) > 1:
            xs = functional(sid, xs)
            if len(xs) == 1: candidate, via, reason, confidence = xs[0], "exact_name_and_function", "exact name disambiguated by rule shape", "strict"
            elif len(xs) > 1: ambiguous, cands, via, confidence = True, [gid(x) for x in xs], "exact_name_and_function", "ambiguous"
        if not candidate and not ambiguous and tag(s, CFN_LOGICAL):
            xs = functional(sid, logical[norm(tag(s, CFN_LOGICAL))])
            if len(xs) == 1: candidate, via, reason, confidence = xs[0], "logical_id_and_function", "logical ID plus rule shape", "strict"
            elif len(xs) > 1: ambiguous, cands, via, confidence = True, [gid(x) for x in xs], "logical_id_and_function", "ambiguous"
        stem = cfn_stem(gname(s))
        if not candidate and not ambiguous and stem:
            xs = available(stems[stem])
            if len(xs) == 1: candidate, via, reason, confidence = xs[0], "unique_generated_name_stem", f"unique stable generated-name stem '{stem}'; rules evaluated separately", "strict"
            elif len(xs) > 1:
                narrowed = functional(sid, xs)
                if len(narrowed) == 1: candidate, via, reason, confidence = narrowed[0], "generated_name_stem_and_function", "duplicate generated stem disambiguated by rule shape", "strict"
                else: ambiguous, cands, via, confidence = True, [gid(x) for x in (narrowed or xs)], "generated_name_stem", "ambiguous"
        if not candidate and not ambiguous:
            xs = functional(sid, target)
            if len(xs) == 1: candidate, via, reason, confidence = xs[0], "unique_functional_match", "unique target containing source rule shape", "strict"
            elif len(xs) > 1:
                narrowed = [x for x in xs if norm_name(gname(x)) == norm_name(gname(s))]
                if len(narrowed) == 1: candidate, via, reason, confidence = narrowed[0], "normalized_name_and_function", "functional candidates narrowed by normalized name", "strict"
                else: ambiguous, cands, via, confidence = True, [gid(x) for x in (narrowed or xs)], "functional_match", "ambiguous"
        if not candidate and not ambiguous and allow_legacy:
            xs = functional(sid, normalized[norm_name(gname(s))])
            if len(xs) == 1: candidate, via, reason, confidence = xs[0], "legacy_normalized_name_and_function", "normalized name plus rule shape", "legacy"
            elif len(xs) > 1: ambiguous, cands, via, confidence = True, [gid(x) for x in xs], "legacy_normalized_name_and_function", "ambiguous"
        if candidate: used.add(gid(candidate))
        m = Match(gname(s), sid, gname(candidate) if candidate else None, gid(candidate) if candidate else None, norm_name(gname(s)), confidence, via, reason, ambiguous, cands)
        matches.append(m)
        if not candidate: missing.append(m)
    return matches, missing, duplicate_index(target), excluded


def rewrite(s, sg_map, prefix_map, src_net, tgt_net, network_maps):
    issues, resolutions = [], []
    def one(rules, direction):
        out = []
        for rule in rules:
            for key, permission in atomic(rule):
                typ, value, mapped = key[3], key[4], value if False else None
                resolution = None
                if typ == "sg": mapped = sg_map.get(value); resolution = Resolution(typ, value, mapped, "TRANSLATE" if mapped else "FLAG", "HIGH" if mapped else "LOW", "security_group_map", "Unique SG mapping" if mapped else "No approved target SG mapping")
                elif typ == "prefix-list": mapped = prefix_map.get(value); resolution = Resolution(typ, value, mapped, "TRANSLATE" if mapped else "FLAG", "HIGH" if mapped else "LOW", "prefix_list_map", "Unique prefix-list mapping" if mapped else "No approved target prefix-list mapping")
                else:
                    resolution = resolve_cidr(value, src_net, tgt_net, network_maps); resolution.source_type = typ; mapped = resolution.target_value
                resolutions.append(resolution)
                if resolution.confidence != "HIGH" or not mapped:
                    issues.append(Issue(gname(s), gid(s), direction, typ, value, resolution.reason, permission, resolution)); continue
                out.append(atomic_permission(key[0], key[1], key[2], typ, mapped))
        return out
    return one(s.get("IpPermissions", []), "ingress"), one(s.get("IpPermissionsEgress", []), "egress"), issues, resolutions

def build_plan(source, target, allow_legacy, prefix_map, src_net, tgt_net, network_maps):
    matches, missing, dupes, excluded = match_sgs(source, target, allow_legacy, prefix_map)
    sb, tb = {gid(x): x for x in source}, {gid(x): x for x in target}; sg_map = {m.source_id: m.target_id for m in matches if m.target_id and not m.ambiguous}
    drifts, unresolved, resolutions = [], [], []
    for m in matches:
        if not m.target_id: continue
        ing, egr, issues, resolved = rewrite(sb[m.source_id], sg_map, prefix_map, src_net, tgt_net, network_maps); unresolved += issues; resolutions += resolved
        mi, xi = diff(tb[m.target_id].get("IpPermissions", []), ing); me, xe = diff(tb[m.target_id].get("IpPermissionsEgress", []), egr)
        if mi or me: drifts.append(Drift(m.source_name, m.source_id, m.target_id, mi, me, len(xi), len(xe), m))
    return Plan(matches, missing, drifts, unresolved, dupes, len(source), excluded, len(source)-excluded, resolutions)

def graph_order(plan, source):
    nodes = {m.source_id for m in plan.matches}; deps = {x: set() for x in nodes}; rev = {x: set() for x in nodes}; sb = {gid(x): x for x in source}
    for sid in nodes:
        for rule in sb[sid].get("IpPermissions", []) + sb[sid].get("IpPermissionsEgress", []):
            for pair in rule.get("UserIdGroupPairs", []):
                ref = pair.get("GroupId")
                if ref in nodes: deps[sid].add(ref); rev[ref].add(sid)
    q = deque(sorted(x for x in nodes if not deps[x])); order = []
    while q:
        x = q.popleft(); order.append(x)
        for y in sorted(rev[x]):
            deps[y].discard(x)
            if not deps[y]: q.append(y)
    remaining = sorted(nodes - set(order)); return order + remaining, remaining


def find_sg(client, vpc, name):
    values = client.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc]}, {"Name": "group-name", "Values": [name]}]).get("SecurityGroups", [])
    return gid(values[0]) if values else None
def create_shell(ctx, s, dry, copy_tags):
    if dry: log(f"[DRY-RUN] Would create SG shell: {gname(s)}"); return "dryrun-" + gid(s)
    req = {"GroupName": gname(s), "Description": (desc(s) or "Replicated security group")[:255], "VpcId": ctx.target_vpc_id}
    if copy_tags and clean_tags(s): req["TagSpecifications"] = [{"ResourceType": "security-group", "Tags": clean_tags(s)}]
    try:
        tid = ctx.ec2.create_security_group(**req)["GroupId"]; ctx.created.add(tid); ctx.rollback.append(Rollback("delete_security_group", {"GroupId": tid})); log(f"[CREATE] {gname(s)} -> {tid}"); return tid
    except ClientError as ex:
        if ex.response.get("Error", {}).get("Code") == "InvalidGroup.Duplicate":
            tid = find_sg(ctx.ec2, ctx.target_vpc_id, gname(s))
            if tid: return tid
        ctx.failed.add(gid(s)); err(f"[ERROR] create failed for {gname(s)}: {ex}"); return None
def authorize(ctx, tid, perms, direction, dry):
    if not perms: return
    if dry: log(f"[DRY-RUN] Would add {len(perms)} {direction} atomic rule(s) on {tid}"); return
    method = ctx.ec2.authorize_security_group_ingress if direction == "ingress" else ctx.ec2.authorize_security_group_egress
    undo = "revoke_security_group_ingress" if direction == "ingress" else "revoke_security_group_egress"
    for permission in perms:
        try: method(GroupId=tid, IpPermissions=[permission]); ctx.rollback.append(Rollback(undo, {"GroupId": tid, "IpPermissions": [permission]}))
        except ClientError as ex:
            if ex.response.get("Error", {}).get("Code") != "InvalidPermission.Duplicate": raise
def execute(ctx, plan, source, args):
    sb = {gid(x): x for x in source}; ctx.sg_map.update({m.source_id: m.target_id for m in plan.matches if m.target_id and not m.ambiguous})
    order, cycles = graph_order(plan, source)
    if cycles: log(f"[WARN] {len(cycles)} dependency-cycle node(s); shells will still precede rules")
    if not args.no_create_missing:
        for sid in order:
            if sid not in ctx.sg_map:
                tid = create_shell(ctx, sb[sid], args.dry_run, not args.no_sync_tags)
                if tid: ctx.sg_map[sid] = tid
    for m in plan.matches:
        tid = ctx.sg_map.get(m.source_id)
        if not tid or m.source_id in ctx.failed: continue
        ing, egr, issues, resolutions = rewrite(sb[m.source_id], ctx.sg_map, ctx.prefix_map, ctx.source_network, ctx.target_network, ctx.network_maps); ctx.resolutions += resolutions
        if issues and not args.allow_unresolved_dependencies:
            err(f"[BLOCKED] {m.source_name}: {len(issues)} unresolved or low-confidence atomic source(s)"); ctx.failed.add(m.source_id); continue
        current = {"IpPermissions": [], "IpPermissionsEgress": []} if args.dry_run and tid.startswith("dryrun-") else ctx.ec2.describe_security_groups(GroupIds=[tid])["SecurityGroups"][0]
        ai, _ = diff(current.get("IpPermissions", []), ing); ae, _ = diff(current.get("IpPermissionsEgress", []), egr)
        try: authorize(ctx, tid, ai, "ingress", args.dry_run); authorize(ctx, tid, ae, "egress", args.dry_run)
        except ClientError as ex: ctx.failed.add(m.source_id); err(f"[ERROR] reconciliation failed for {m.source_name}: {ex}")


def rule_summary(permission):
    proto = permission.get("IpProtocol", "unknown")
    if proto == "-1": service = "all protocols"
    else:
        fp, tp = permission.get("FromPort"), permission.get("ToPort"); service = f"{proto} {fp}" if fp == tp else f"{proto} {fp}-{tp}"
    sources = [x.get("CidrIp") for x in permission.get("IpRanges", []) if x.get("CidrIp")] + [x.get("CidrIpv6") for x in permission.get("Ipv6Ranges", []) if x.get("CidrIpv6")] + [x.get("PrefixListId") for x in permission.get("PrefixListIds", []) if x.get("PrefixListId")] + [x.get("GroupId") for x in permission.get("UserIdGroupPairs", []) if x.get("GroupId")]
    return {"service": service, "sources": sources or ["unknown"], "raw": permission}
def plan_dict(plan, default_count):
    matched = [x for x in plan.matches if x.target_id]; ambiguous = [x for x in plan.matches if x.ambiguous]; drift_ids = {x.source_group_id for x in plan.drifts}; in_sync = [x for x in matched if x.source_id not in drift_ids]
    resolution_counts = defaultdict(int)
    for r in plan.resolutions: resolution_counts[f"{r.action}:{r.confidence}:{r.method}"] += 1
    return {
        "executive_summary": {"overall_status": "DRIFT_DETECTED" if plan.missing or plan.drifts or plan.unresolved else "IN_SYNC", "source_total_non_default": plan.source_total, "excluded_directory": plan.excluded_directory, "excluded_default_at_collection": default_count, "evaluated": plan.evaluated, "matched": len(matched), "missing": len([x for x in plan.missing if not x.ambiguous]), "ambiguous": len(ambiguous), "drifted": len(plan.drifts), "unresolved_dependency_rules": len(plan.unresolved), "in_sync": len(in_sync)},
        "match_method_breakdown": dict(sorted((k, sum(1 for m in plan.matches if m.matched_via == k)) for k in {m.matched_via for m in plan.matches})),
        "network_resolution_breakdown": dict(sorted(resolution_counts.items())),
        "missing_security_groups": [asdict(x) for x in plan.missing],
        "drifted_security_groups": [{"source_name": d.group_name, "source_id": d.source_group_id, "target_name": d.match.target_name, "target_id": d.target_group_id, "matched_via": d.match.matched_via, "missing_ingress_rules": [rule_summary(x) for x in d.missing_ingress], "missing_egress_rules": [rule_summary(x) for x in d.missing_egress], "tolerated_extra_ingress": d.tolerated_extra_ingress_count, "tolerated_extra_egress": d.tolerated_extra_egress_count} for d in plan.drifts],
        "unresolved_sources": [{**asdict(x), "rule": rule_summary(x.rule)} for x in plan.unresolved],
        "network_resolutions": [asdict(x) for x in plan.resolutions],
        "security_group_mappings": [asdict(x) for x in matched],
        "fully_synchronized_groups": [asdict(x) for x in in_sync],
        "duplicate_canonical_keys": plan.duplicate_keys,
    }
def markdown_report(payload):
    plan, lines = payload["sg_plan"], ["# AWS Security Group Reconciliation Report", "", f"Generated: {payload['created_at_utc']}", ""]
    s = plan["executive_summary"]; lines += ["## Executive Summary", "", f"**Overall status:** `{s['overall_status']}`", ""]
    for key, label in [("source_total_non_default", "Source SGs excluding default"), ("evaluated", "Evaluated"), ("matched", "Matched"), ("in_sync", "Fully synchronized"), ("missing", "Missing"), ("ambiguous", "Ambiguous"), ("drifted", "Drifted"), ("unresolved_dependency_rules", "Suppressed unresolved/low-confidence rule sources")]: lines.append(f"- {label}: **{s[key]}**")
    lines += ["", "## Network Mapping", "", f"- Source VPC CIDRs: `{payload['network_translation']['source_vpc_cidrs']}`", f"- Target VPC CIDRs: `{payload['network_translation']['target_vpc_cidrs']}`", f"- Deterministic subnet mappings: **{len(payload['network_translation']['subnet_map'])}**", f"- Network mapping issues: **{len(payload['network_translation']['mapping_issues'])}**", ""]
    lines += ["## Network Resolution Breakdown", ""]
    for key, count in plan["network_resolution_breakdown"].items(): lines.append(f"- `{key}`: **{count}**")
    lines += ["", f"## Drifted Security Groups ({len(plan['drifted_security_groups'])})", ""]
    if not plan["drifted_security_groups"]: lines += ["None.", ""]
    for i, d in enumerate(plan["drifted_security_groups"], 1):
        lines += [f"### {i}. {d['source_name']}", f"- Source: `{d['source_id']}`", f"- Target: **{d['target_name']}** (`{d['target_id']}`)", f"- Match method: `{d['matched_via']}`"]
        for direction in ("ingress", "egress"):
            rules = d[f"missing_{direction}_rules"]
            for r in rules: lines.append(f"- Missing {direction}: `{r['service']}` from/to {', '.join('`'+x+'`' for x in r['sources'])}")
        lines.append("")
    unresolved = plan["unresolved_sources"]; lines += [f"## Suppressed Unresolved or Low-Confidence Sources ({len(unresolved)})", ""]
    if not unresolved: lines += ["None.", ""]
    for x in unresolved: lines.append(f"- **{x['source_group_name']}** `{x['direction']}` `{x['dependency_type']}` `{x['referenced_source_id']}`: {x['reason']}")
    lines += ["", "## Safety Policy", "", "- Only HIGH-confidence source resolutions are eligible for synchronization.", "- Ambiguous network and SG mappings are blocked.", "- Existing target-only rules are tolerated and are not removed.", "- CIDR translation is derived from live VPC, subnet, and routing metadata.", ""]
    return "\n".join(lines)


def parse():
    p = argparse.ArgumentParser(description="Enterprise AWS Security Group Reconciliation Engine")
    p.add_argument("--info-file", required=True); p.add_argument("--source-profile"); p.add_argument("--source-region"); p.add_argument("--source-vpc-id"); p.add_argument("--target-profile"); p.add_argument("--target-region"); p.add_argument("--target-vpc-id")
    mode = p.add_mutually_exclusive_group(); mode.add_argument("--dry-run", action="store_true"); mode.add_argument("--yes", action="store_true"); mode.add_argument("--report-only", action="store_true")
    p.add_argument("--allow-legacy", action="store_true"); p.add_argument("--allow-unresolved-dependencies", action="store_true"); p.add_argument("--no-create-missing", action="store_true"); p.add_argument("--no-sync-tags", action="store_true"); p.add_argument("--report-path", default=""); p.add_argument("--rollback-dir", default=ROLLBACK_DIR)
    n = p.parse_args(); info = load(n.info_file); s, t = info.get("source", {}), info.get("target", {})
    if not n.dry_run and not n.yes and not n.report_only: n.dry_run = True
    vals = [n.info_file, n.source_profile or s.get("profile"), n.source_region or s.get("region"), n.source_vpc_id or s.get("vpc_id"), n.target_profile or t.get("profile"), n.target_region or t.get("region"), n.target_vpc_id or t.get("vpc_id"), n.dry_run, n.report_only, n.yes, n.allow_legacy, n.allow_unresolved_dependencies, n.no_create_missing, n.no_sync_tags, n.report_path, n.rollback_dir]
    if not all([vals[2], vals[3], vals[5], vals[6]]): raise ValueError("source/target region and VPC ID are required")
    return Args(*vals), info

def main():
    try:
        args, info = parse(); sconf, tconf = info.get("source", {}), info.get("target", {})
        log("\n============================================================\n Enterprise AWS Security Group Reconciliation Engine\n============================================================")
        log(f"[MODE] dry_run={args.dry_run}, yes={args.yes}, report_only={args.report_only}")
        source_account = validate_identity(args.source_profile, args.source_region, sconf.get("account_id"), "source")
        target_account = validate_identity(args.target_profile, args.target_region, tconf.get("account_id"), "target")
        if source_account == target_account and args.source_vpc_id == args.target_vpc_id and args.source_region == args.target_region: raise RuntimeError("source and target resolve to the same account, region, and VPC")
        se, te = ec2(args.source_profile, args.source_region), ec2(args.target_profile, args.target_region)
        source_sgs, source_defaults = fetch_sgs(se, args.source_vpc_id); target_sgs, target_defaults = fetch_sgs(te, args.target_vpc_id)
        source_net, target_net = fetch_network_inventory(se, args.source_vpc_id), fetch_network_inventory(te, args.target_vpc_id)
        network_maps = build_network_maps(source_net, target_net)
        prefix_map, prefix_issues = map_prefixes(fetch_prefixes(se), fetch_prefixes(te), referenced_prefixes(source_sgs))
        plan = build_plan(source_sgs, target_sgs, args.allow_legacy, prefix_map, source_net, target_net, network_maps)
        if args.yes and any(x.ambiguous for x in plan.matches): raise RuntimeError("apply blocked: ambiguous SG matches exist")
        ctx, validation, rollback_path = None, {"enabled": False, "status": "NOT_RUN"}, None
        if not args.report_only:
            ctx = Context(te, args.target_vpc_id, prefix_map, source_net, target_net, network_maps); execute(ctx, plan, source_sgs, args)
            if args.yes:
                if ctx.rollback:
                    rollback_path = os.path.join(args.rollback_dir, f"sg_rollback_{stamp()}.json"); dump(rollback_path, {"created_at_utc": datetime.now(timezone.utc).isoformat(), "target": {"account_id": target_account, "region": args.target_region, "vpc_id": args.target_vpc_id}, "actions": [asdict(x) for x in reversed(ctx.rollback)]})
                refreshed, _ = fetch_sgs(te, args.target_vpc_id); validation_plan = build_plan(source_sgs, refreshed, args.allow_legacy, prefix_map, source_net, target_net, network_maps)
                passed = not validation_plan.missing and not validation_plan.drifts and not validation_plan.unresolved and not ctx.failed
                validation = {"enabled": True, "status": "PASSED" if passed else "FAILED", "passed": passed, "sg_plan": plan_dict(validation_plan, source_defaults)}
        report = args.report_path or os.path.join(REPORT_DIR, f"sg_reconcile_{'apply' if args.yes else 'dryrun' if args.dry_run else 'report'}_{stamp()}.json")
        payload = {
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "source": {"profile": args.source_profile, "account_id": source_account, "region": args.source_region, "vpc_id": args.source_vpc_id},
            "target": {"profile": args.target_profile, "account_id": target_account, "region": args.target_region, "vpc_id": args.target_vpc_id},
            "policy": {"high_confidence_only": True, "ambiguous_mappings_blocked": True, "source_required_only": True, "target_extra_rules_tolerated": True, "target_rules_never_removed": True, "generated_name_matching": {"unique_stem_establishes_identity": True, "functional_shape_used_for_duplicate_disambiguation": True, "rule_drift_evaluated_after_identity_matching": True}},
            "network_translation": {"source_vpc_cidrs": source_net.ipv4_cidrs + source_net.ipv6_cidrs, "target_vpc_cidrs": target_net.ipv4_cidrs + target_net.ipv6_cidrs, "vpc_cidr_map": network_maps.vpc_cidr_map, "subnet_map": network_maps.subnet_map, "subnet_match_methods": network_maps.subnet_methods, "mapping_issues": network_maps.issues},
            "prefix_lists": {"id_map": prefix_map, "mapping_issues": prefix_issues},
            "sg_plan": plan_dict(plan, source_defaults),
            "execution": {"created_sgs": sorted(ctx.created) if ctx else [], "failed_nodes": sorted(ctx.failed) if ctx else [], "sg_id_map": ctx.sg_map if ctx else {}, "rollback_path": rollback_path},
            "post_apply_validation": validation,
            "collection": {"target_default_sgs_excluded": target_defaults},
        }
        dump(report, payload); markdown_path = os.path.splitext(report)[0] + ".md"; ensure(os.path.dirname(markdown_path))
        with open(markdown_path, "w", encoding="utf-8") as handle: handle.write(markdown_report(payload))
        log(f"[REPORT-JSON] Written: {report}"); log(f"[REPORT-MARKDOWN] Written: {markdown_path}")
        if args.dry_run: log("[SAFE MODE] No AWS changes were made. Use --yes only after reviewing both reports.")
        return 2 if ctx and ctx.failed else 0
    except KeyboardInterrupt: err("[ABORTED]"); return 130
    except Exception as ex: err(f"[FATAL] {ex}"); return 1

if __name__ == "__main__": raise SystemExit(main())
