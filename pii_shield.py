import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple


PII_PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "PHONE": re.compile(r"\b(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,3}\)?[\s.-]?)?\d{3}[\s.-]?\d{2,4}\b"),
    "IBAN": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "IP": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "SSN_FR": re.compile(r"\b\d{13}\b"),
}

REDACTED = "[REDACTED]"
PII_WEIGHTS = {
    "EMAIL": 2,
    "PHONE": 2,
    "IBAN": 4,
    "IP": 1,
    "CREDIT_CARD": 5,
    "SSN_FR": 5,
}


@dataclass
class Finding:
    label: str
    value: str
    start: int
    end: int


def is_valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if not 0 <= int(part) <= 255:
            return False
    return True


def luhn_check(number: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for idx, digit in enumerate(digits):
        if idx % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def detect_pii(
    text: str,
    extra_patterns: Dict[str, str],
    allowlist: List[str],
    allowlist_regex: List[re.Pattern[str]],
) -> List[Finding]:
    findings: List[Finding] = []
    patterns = dict(PII_PATTERNS)
    for label, raw in extra_patterns.items():
        patterns[label] = re.compile(raw)

    for label, regex in patterns.items():
        for match in regex.finditer(text):
            value = match.group(0)
            if label == "IP" and not is_valid_ipv4(value):
                continue
            if label == "CREDIT_CARD" and not luhn_check(value):
                continue
            if value in allowlist:
                continue
            if any(rule.search(value) for rule in allowlist_regex):
                continue
            findings.append(Finding(label, value, match.start(), match.end()))
    return findings


def mask_value(value: str, visible: int = 2) -> str:
    if len(value) <= visible:
        return "*" * len(value)
    return value[:visible] + "*" * (len(value) - visible)


def hash_value(value: str, salt: str) -> str:
    digest = hashlib.sha256((salt + value).encode("utf-8")).hexdigest()
    return f"hash_{digest[:12]}"


def anonymize_value(
    label: str,
    value: str,
    mode: str,
    visible: int,
    salt: str,
    token_map: Dict[str, str],
    policies: Dict[str, str],
) -> str:
    effective_mode = policies.get(label, mode)
    if effective_mode == "remove":
        return REDACTED
    if effective_mode == "hash":
        return hash_value(value, salt)
    if effective_mode == "token":
        if value not in token_map:
            token_map[value] = hash_value(value, salt).replace("hash_", "tok_")
        return token_map[value]
    return mask_value(value, visible)


def anonymize_text(
    text: str,
    mode: str,
    visible: int,
    salt: str,
    token_map: Dict[str, str],
    extra_patterns: Dict[str, str],
    allowlist: List[str],
    allowlist_regex: List[re.Pattern[str]],
    policies: Dict[str, str],
) -> Tuple[str, List[Finding]]:
    findings = detect_pii(text, extra_patterns, allowlist, allowlist_regex)
    if not findings:
        return text, findings

    output = text
    for finding in sorted(findings, key=lambda f: f.start, reverse=True):
        replacement = anonymize_value(finding.label, finding.value, mode, visible, salt, token_map, policies)
        output = output[:finding.start] + replacement + output[finding.end:]
    return output, findings


def anonymize_record(
    record: Dict[str, object],
    fields: List[str],
    mode: str,
    visible: int,
    salt: str,
    token_map: Dict[str, str],
    extra_patterns: Dict[str, str],
    allowlist: List[str],
    allowlist_regex: List[re.Pattern[str]],
    policies: Dict[str, str],
) -> Tuple[Dict[str, object], List[Finding]]:
    findings: List[Finding] = []
    cleaned = dict(record)
    for field in fields:
        value = cleaned.get(field)
        if isinstance(value, str):
            cleaned_value, field_findings = anonymize_text(
                value,
                mode,
                visible,
                salt,
                token_map,
                extra_patterns,
                allowlist,
                allowlist_regex,
                policies,
            )
            cleaned[field] = cleaned_value
            findings.extend(field_findings)
    return cleaned, findings


def load_records(input_path: str | None) -> List[Dict[str, object]]:
    if input_path is None:
        return [
            {"id": "evt-001", "message": "Client: jean.dupont@email.com, tel: 06 12 34 56 78"},
            {"id": "evt-002", "message": "IBAN: FR1420041010050500013M02606, facture #9842"},
            {"id": "evt-003", "message": "Connexion depuis 192.168.10.24"},
        ]
    with open(input_path, "r", encoding="utf-8") as handle:
        raw = handle.read().strip()
    if not raw:
        return []
    if raw.startswith("["):
        return json.loads(raw)
    records = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))
    return records


def write_output(records: List[Dict[str, object]], output_path: str | None) -> None:
    payload = json.dumps(records, ensure_ascii=True, indent=2)
    if output_path is None:
        print(payload)
        return
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(payload)


def write_audit(audits: List[Dict[str, object]], audit_path: str | None) -> None:
    if audit_path is None:
        return
    payload = json.dumps(audits, ensure_ascii=True, indent=2)
    with open(audit_path, "w", encoding="utf-8") as handle:
        handle.write(payload)


def compute_risk_score(types: List[str], weights: Dict[str, int]) -> int:
    score = 0
    for label in types:
        score += weights.get(label, 1)
    return score


def process_records(
    records: Iterable[Dict[str, object]],
    fields: List[str],
    mode: str,
    visible: int,
    salt: str,
    extra_patterns: Dict[str, str],
    allowlist: List[str],
    allowlist_regex: List[re.Pattern[str]],
    policies: Dict[str, str],
    weights: Dict[str, int],
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]], Dict[str, object]]:
    processed: List[Dict[str, object]] = []
    audits: List[Dict[str, object]] = []
    token_map: Dict[str, str] = {}
    counters: Dict[str, object] = {"records": 0, "pii_total": 0, "pii_by_type": {}}
    for idx, record in enumerate(records):
        cleaned, findings = anonymize_record(
            record,
            fields,
            mode,
            visible,
            salt,
            token_map,
            extra_patterns,
            allowlist,
            allowlist_regex,
            policies,
        )
        pii_types = sorted({f.label for f in findings})
        risk_score = compute_risk_score(pii_types, weights)
        processed.append(
            {
                **cleaned,
                "pii_count": len(findings),
                "pii_types": pii_types,
                "pii_risk": risk_score,
            }
        )
        audits.append(
            {
                "id": record.get("id", f"evt-{idx:04d}"),
                "pii_count": len(findings),
                "pii_types": pii_types,
                "pii_preview": [mask_value(f.value, 2) for f in findings[:5]],
            }
        )
        counters["records"] += 1
        counters["pii_total"] += len(findings)
        for label in pii_types:
            counters["pii_by_type"][label] = counters["pii_by_type"].get(label, 0) + 1
    return processed, audits, counters


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PII Shield - detect and anonymize PII in text fields")
    parser.add_argument("--input", help="Path to JSON or JSONL input")
    parser.add_argument("--output", help="Path to JSON output")
    parser.add_argument("--audit", help="Path to audit JSON output")
    parser.add_argument("--config", help="Path to config JSON (extra patterns, allowlist)")
    parser.add_argument("--stats", help="Path to stats JSON output")
    parser.add_argument("--fields", default="message", help="Comma-separated fields to scan")
    parser.add_argument("--mode", choices=["mask", "hash", "token", "remove"], default="mask")
    parser.add_argument("--visible", type=int, default=2, help="Visible chars for mask mode")
    parser.add_argument("--salt", default="pii-shield", help="Salt for hash/token")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    fields = [f.strip() for f in args.fields.split(",") if f.strip()]
    extra_patterns: Dict[str, str] = {}
    allowlist: List[str] = []
    allowlist_regex: List[re.Pattern[str]] = []
    policies: Dict[str, str] = {}
    weights: Dict[str, int] = dict(PII_WEIGHTS)
    if args.config:
        with open(args.config, "r", encoding="utf-8") as handle:
            config = json.load(handle)
        extra_patterns = {str(k): str(v) for k, v in config.get("patterns", {}).items()}
        allowlist = [str(item) for item in config.get("allowlist", [])]
        allowlist_regex = [re.compile(str(item)) for item in config.get("allowlist_regex", [])]
        policies = {str(k): str(v) for k, v in config.get("policies", {}).items()}
        weights.update({str(k): int(v) for k, v in config.get("weights", {}).items()})
    records = load_records(args.input)
    processed, audits, counters = process_records(
        records,
        fields,
        args.mode,
        args.visible,
        args.salt,
        extra_patterns,
        allowlist,
        allowlist_regex,
        policies,
        weights,
    )
    write_output(processed, args.output)
    write_audit(audits, args.audit)
    if args.stats:
        with open(args.stats, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(counters, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
