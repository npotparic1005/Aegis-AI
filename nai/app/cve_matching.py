"""Conservative CVE candidate filtering, not vulnerability verification.

Use CPE product/version conditions when present. Only ordinary dotted numeric
versions are ordered; vendor-specific versions and complex/negated conditions
remain unverified. Description text is a fallback for explicit exclusion bounds,
never proof that a vulnerability applies.
"""

from __future__ import annotations

import re
from urllib.parse import unquote


_ALIASES = {
    "redis key-value store": "redis",
    "postgresql db": "postgresql",
    "node.js express framework": "express", 
    "apache httpd": "apache http server",
}


def product_name(value: str) -> str:
    normalized = " ".join(value.lower().strip().split())
    return _ALIASES.get(normalized, normalized)


def simple_cpe(value: str) -> tuple[str, ...] | None:
    """Read simple Nmap URI / CPE 2.3 names; leave complex bindings unknown."""
    if value.startswith("cpe:/"):
        fields = [unquote(part) or "*" for part in value[5:].split(":")]
        if not 3 <= len(fields) <= 7:
            return None
        fields += ["*"] * (11 - len(fields))
    elif value.startswith("cpe:2.3:"):
        fields = value[8:].split(":")
        if len(fields) != 11:
            return None
    else:
        return None
    if not all(re.fullmatch(r"[A-Za-z0-9._+\-]+|\*", field) for field in fields):
        return None
    return tuple(fields)


def exact_cpe_query(cpes: list[str]) -> str | None:
    names = set()
    for value in cpes:
        fields = simple_cpe(value)
        if fields and fields[0] == "a" and all(part not in {"*", "-"} for part in fields[1:4]):
            names.add("cpe:2.3:" + ":".join(fields))
    return next(iter(names)) if len(names) == 1 else None


def numeric_compare(left: str, right: str) -> int | None:
    if not all(re.fullmatch(r"\d+(?:\.\d+)*", value) for value in (left, right)):
        return None
    a, b = [int(x) for x in left.split(".")], [int(x) for x in right.split(".")]
    width = max(len(a), len(b))
    a += [0] * (width - len(a))
    b += [0] * (width - len(b))
    return (a > b) - (a < b)


def _version_matches(match: dict, observed: str) -> bool | None:
    fields = simple_cpe(match.get("criteria", ""))
    if not fields or not observed or not re.fullmatch(r"[\w.+-]+", observed):
        return None
    outcomes = []
    if fields[3] not in {"*", "-"}:
        comparison = numeric_compare(observed, fields[3])
        outcomes.append(True if observed == fields[3] else
                        comparison == 0 if comparison is not None else None)
    elif fields[3] == "-":
        return None
    bounds = {"versionStartIncluding": lambda n: n >= 0,
              "versionStartExcluding": lambda n: n > 0,
              "versionEndIncluding": lambda n: n <= 0,
              "versionEndExcluding": lambda n: n < 0}
    for key, predicate in bounds.items():
        if key in match:
            comparison = numeric_compare(observed, match[key])
            outcomes.append(predicate(comparison) if comparison is not None else None)
    if False in outcomes:
        return False
    if None in outcomes or not outcomes:
        return None
    return True


def _configuration_matches(configurations: list) -> tuple[list[dict], bool]:
    matches = []
    negated = False

    def walk(node):
        nonlocal negated
        if not isinstance(node, dict):
            return
        negated |= bool(node.get("negate"))
        matches.extend(node.get("cpeMatch", []))
        for key in ("nodes", "children"):
            for child in node.get(key, []):
                walk(child)

    for configuration in configurations:
        walk(configuration)
    return matches, negated


def classify_cve(cve: dict, product: str, version: str, cpes: list[str]) -> dict:
    def result(assessment, basis, reason):
        return {"assessment": assessment, "match_basis": basis, "reason": reason}

    if cve.get("vulnStatus", "").lower() == "rejected":
        return result("excluded", "rejected_record", "NVD marks this CVE record rejected.")
    observed_cpes = [fields for value in cpes if (fields := simple_cpe(value)) and fields[0] == "a"]
    versions = {fields[3] for fields in observed_cpes if fields[3] not in {"*", "-"}}
    observed_version = next(iter(versions)) if len(versions) == 1 else version.strip()
    matches, negated = _configuration_matches(cve.get("configurations", []))
    if negated:
        return result("candidate", "unverified_configuration",
                      "Negated CPE conditions require manual interpretation; applicability is unverified.")
    if matches:
        if not any(match.get("vulnerable") for match in matches):
            return result("candidate", "unverified_configuration",
                          "No vulnerable-product assertion is available in these CPE conditions.")
        relevant = []
        unknown_identity = False
        for match in matches:
            if not match.get("vulnerable", False):
                continue  # platform prerequisite, not a vulnerable product assertion
            fields = simple_cpe(match.get("criteria", ""))
            if not fields or fields[0] == "*" or fields[2] == "*":
                unknown_identity = True
                continue
            if fields[0] != "a":
                continue
            if observed_cpes:
                if any(fields[:3] == observed[:3] for observed in observed_cpes):
                    relevant.append(match)
                elif any(fields[2] == observed[2] for observed in observed_cpes):
                    unknown_identity = True  # vendor rename/alias is not resolved here
            else:
                name = fields[2].replace("_", " ")
                if fields[1:3] == ("apache", "http_server"):
                    name = "apache http server"
                if product_name(name) == product_name(product):
                    relevant.append(match)
        if relevant:
            outcomes = [_version_matches(match, observed_version) for match in relevant]
            if True in outcomes:
                return result("candidate", "product_version",
                              "A vulnerable CPE product/version condition matches. Platform, configuration, "
                              "component role and exploit prerequisites are not verified.")
            if None in outcomes or unknown_identity:
                # A wildcard product CPE supplies no version evidence. Consult
                # the same narrow prose fallback used for unenriched records,
                # but never override explicit/complex CPE version conditions.
                unbounded = all(simple_cpe(m.get("criteria", ""))[3] == "*"
                                and not any(k.startswith("version") for k in m) for m in relevant)
                if unbounded and not unknown_identity:
                    exclusion = _description_exclusion(cve, product, observed_version)
                    if exclusion:
                        return exclusion
                return result("candidate", "product_only",
                              "Product identity matches, but the observed version or CPE conditions "
                              "cannot establish version applicability.")
            return result("excluded", "version_mismatch",
                          f"Observed version {observed_version!r} is outside the returned vulnerable version conditions.")
        if not unknown_identity:
            return result("excluded", "product_mismatch",
                          "Returned vulnerable CPE products do not match the observed application.")
        return result("candidate", "unverified_configuration",
                      "Product identity cannot be resolved from these CPE conditions; applicability is unverified.")

    return _description_exclusion(cve, product, observed_version) or result(
        "candidate", "keyword_only",
        "Keyword search match only; no usable affected-product/version conditions establish applicability.")


def _description_exclusion(cve: dict, product: str, observed_version: str) -> dict | None:
    """Only an unambiguous numeric upper bound can exclude a prose match."""
    description = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    # Multiple versions may describe disjoint affected branches or exceptions.
    # Do not exclude a record by selecting just one bound from that prose.
    prose_versions = set(re.findall(r"(?<![\w.])\d+\.\d+(?:\.\d+)*(?![\w.])", description))
    names = {product.strip(), product_name(product)} - {""}
    for name in names:
        pattern = (rf"\b{re.escape(name)}\s+(?:versions?\s+)?"
                   r"(before|prior to|through)\s+(\d+(?:\.\d+)*)(?![\w.])")
        for bound in re.finditer(pattern, description, re.I):
            if prose_versions - {bound[2]}:
                continue
            comparison = numeric_compare(observed_version, bound[2])
            if comparison is not None and (comparison > 0 or (comparison == 0 and bound[1].lower() != "through")):
                return {"assessment": "excluded", "match_basis": "description_version_mismatch",
                        "reason": f"Description specifies {name} {bound[1]} {bound[2]}; observed version is {observed_version}."}
    return None
