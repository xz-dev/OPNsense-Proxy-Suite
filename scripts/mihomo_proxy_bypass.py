#!/usr/local/bin/python3

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BLOCK_BEGIN = "# BEGIN OPNsense Proxy Endpoint DIRECT"
BLOCK_END = "# END OPNsense Proxy Endpoint DIRECT"
SNIFFER_BLOCK_BEGIN = "# BEGIN OPNsense Proxy Endpoint SNIFFER BYPASS"
SNIFFER_BLOCK_END = "# END OPNsense Proxy Endpoint SNIFFER BYPASS"
DEFAULT_CONFIG = Path("/usr/local/etc/clash/config.yaml")


def yaml_scalar(yaml: str, key: str, default: str = "") -> str:
    match = re.search(
        rf"^{re.escape(key)}\s*:\s*(?:\"([^\"\r\n]*)\"|'([^'\r\n]*)'|([^#\r\n]*))\s*(?:#.*)?$",
        yaml,
        re.MULTILINE,
    )
    if not match:
        return default
    return next((value.strip() for value in match.groups() if value), "")


def api_base_url(yaml: str) -> str:
    controller = yaml_scalar(yaml, "external-controller", "127.0.0.1:9090")
    match = re.fullmatch(r"(?:\[([^]]+)\]|([^:]*)):(\d+)", controller)
    if not match:
        raise ValueError(f"unsupported external-controller: {controller}")
    host = match.group(1) or match.group(2)
    if host in {"", "*", "0.0.0.0", "::"}:
        host = "127.0.0.1"
    elif ":" in host:
        host = f"[{host}]"
    return f"http://{host}:{match.group(3)}"


def api_request(base_url: str, secret: str, method: str, path: str, body=None):
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = {"Accept": "application/json"}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        base_url + path, data=data, headers=headers, method=method
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=2) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def yaml_value(value: str) -> str:
    value = re.split(r"\s+#", value.strip(), maxsplit=1)[0].strip().rstrip(",}")
    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1].replace("''", "'")
    if len(value) >= 2 and value[0] == value[-1] == '"':
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value[1:-1]
    return value


def provider_configs(yaml: str):
    header = re.search(r"^proxy-providers:\s*(?:#.*)?$", yaml, re.MULTILINE)
    if not header:
        return {}

    lines = yaml[header.end() :].splitlines()
    provider_indent = None
    current_name = None
    current = {}
    providers = {}
    provider_line = re.compile(r"^(\s+)([^#][^:]*?):\s*(.*)$")
    field_line = re.compile(
        r"^(\s+)(type|path|url|additional-prefix|additional-suffix):\s*(.+)$"
    )
    inline_field = re.compile(
        r"(?:^|[, {])(type|path|url|additional-prefix|additional-suffix)"
        r"\s*:\s*([^,}]+)"
    )
    for line in lines:
        if line and not line[0].isspace() and not line.startswith("#"):
            break
        match = provider_line.match(line)
        if match and (
            provider_indent is None or len(match.group(1)) == provider_indent
        ):
            if current_name is not None:
                providers[current_name] = current
            provider_indent = len(match.group(1))
            current_name = yaml_value(match.group(2))
            current = {
                key: yaml_value(value)
                for key, value in inline_field.findall(match.group(3))
            }
            continue
        match = field_line.match(line)
        if (
            current_name is not None
            and match
            and provider_indent is not None
            and len(match.group(1)) > provider_indent
        ):
            current[match.group(2)] = yaml_value(match.group(3))
    if current_name is not None:
        providers[current_name] = current
    return providers


def provider_path(config_path: Path, provider: dict) -> Path | None:
    configured_path = provider.get("path")
    if not configured_path and provider.get("type") == "http" and provider.get("url"):
        digest = hashlib.md5(
            provider["url"].encode(), usedforsecurity=False
        ).hexdigest()
        configured_path = f"proxies/{digest}"
    if not configured_path:
        return None
    path = Path(configured_path).expanduser()
    return path if path.is_absolute() else config_path.parent / path


def provider_paths(yaml: str, config_path: Path, active_providers):
    providers = provider_configs(yaml)
    return [
        path
        for name in active_providers
        if (path := provider_path(config_path, providers.get(name, {}))) is not None
    ]


def top_level_section(yaml: str, key: str) -> str:
    header = re.search(rf"(?m)^{re.escape(key)}\s*:\s*(?:#.*)?$", yaml)
    if not header:
        return ""
    end = re.search(r"(?m)^[A-Za-z0-9_-]+\s*:", yaml[header.end() :])
    return yaml[header.end() : header.end() + end.start() if end else None]


def mapping_field(mapping: str, field: str) -> str | None:
    match = re.search(
        rf"(?:^|[\n,{{-])\s*[\"']?{re.escape(field)}[\"']?\s*:\s*"
        r"""(?:("[^"\r\n]*")|'([^'\r\n]*)'|([^,\]}#\r\n]+))""",
        mapping,
        re.MULTILINE,
    )
    if not match:
        return None
    return yaml_value(next(value for value in match.groups() if value))


def proxy_records(yaml: str):
    starts = [
        (len(match.group(1)), match.start())
        for match in re.finditer(r"(?m)^([ \t]*)-[ \t]+", yaml)
    ]
    if not starts:
        return []
    indent = min(item_indent for item_indent, _ in starts)
    boundaries = [start for item_indent, start in starts if item_indent == indent]
    boundaries.append(len(yaml))

    records = []
    for index in range(len(boundaries) - 1):
        mapping = yaml[boundaries[index] : boundaries[index + 1]]
        name = mapping_field(mapping, "name")
        server = mapping_field(mapping, "server")
        if not name or not server:
            continue
        server = server.strip().strip("[]").lower().rstrip(".")
        try:
            server = str(ipaddress.ip_address(server))
        except ValueError:
            if not re.fullmatch(r"[a-z0-9._-]{1,253}", server):
                continue
        records.append((name, server))
    return records


def extract_servers(yaml: str):
    return {server for _, server in proxy_records(yaml)}


def resolved_addresses(base_url: str, secret: str, host: str):
    addresses = set()
    for query_type in ("A", "AAAA"):
        try:
            status, response = api_request(
                base_url,
                secret,
                "GET",
                "/dns/query?"
                + urllib.parse.urlencode({"name": host, "type": query_type}),
            )
            answers = json.loads(response).get("Answer", [])
        except (AttributeError, OSError, ValueError):
            continue
        if status != 200 or not isinstance(answers, list):
            continue
        for answer in answers:
            try:
                address = ipaddress.ip_address(str(answer.get("data", "")).strip())
            except (AttributeError, ValueError):
                continue
            if address.version == (4 if query_type == "A" else 6):
                addresses.add(address.compressed)
    return addresses


def direct_rule(server: str) -> str:
    try:
        address = ipaddress.ip_address(server)
    except ValueError:
        return f"DOMAIN,{server},DIRECT"
    rule_type = "IP-CIDR" if address.version == 4 else "IP-CIDR6"
    return f"{rule_type},{address}/{address.max_prefixlen},DIRECT,no-resolve"


def inject_direct_rules(yaml: str, servers) -> str:
    eol = "\r\n" if "\r\n" in yaml else "\n"
    yaml = re.sub(
        rf"^[ \t]*{re.escape(BLOCK_BEGIN)}\r?\n.*?^[ \t]*{re.escape(BLOCK_END)}\r?\n?",
        "",
        yaml,
        flags=re.MULTILINE | re.DOTALL,
    )

    header = re.search(r"^rules:\s*(?:#.*)?\r?\n", yaml, re.MULTILINE)
    indent = "  "
    if header:
        section = yaml[header.end() :]
        next_key = re.search(r"(?m)^[A-Za-z0-9_-]+\s*:", section)
        if next_key:
            section = section[: next_key.start()]
        first_rule = re.search(r"(?m)^([ \t]*)-\s+", section)
        if first_rule:
            indent = first_rule.group(1)

    rules = [f"{indent}{BLOCK_BEGIN}"]
    rules.extend(f"{indent}- {direct_rule(server)}" for server in sorted(servers))
    rules.append(f"{indent}{BLOCK_END}")
    block = eol.join(rules) + eol

    if header:
        return yaml[: header.end()] + block + yaml[header.end() :]

    yaml, count = re.subn(
        r"^rules:\s*(?:\[\s*\]|~|null)\s*(?:#.*)?$",
        lambda _: "rules:" + eol + block.rstrip("\r\n"),
        yaml,
        count=1,
        flags=re.MULTILINE | re.IGNORECASE,
    )
    if not count:
        raise ValueError("top-level multiline rules list not found")
    return yaml


def endpoint_cidrs(endpoints):
    cidrs = set()
    for endpoint in endpoints:
        try:
            address = ipaddress.ip_address(endpoint)
        except ValueError:
            continue
        cidrs.add(f"{address.compressed}/{address.max_prefixlen}")
    return cidrs


def split_flow_items(value: str):
    items = []
    start = 0
    depth = 0
    quote = None
    escaped = False
    for index, character in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif character == "\\" and quote == '"':
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in "'\"":
            quote = character
        elif character in "[{":
            depth += 1
        elif character in "]}":
            depth -= 1
        elif character == "," and depth == 0:
            items.append(value[start:index].strip())
            start = index + 1
    if quote or depth:
        raise ValueError("unterminated inline YAML collection")
    tail = value[start:].strip()
    if tail:
        items.append(tail)
    return items


def split_flow_mapping_item(item: str):
    quote = None
    escaped = False
    depth = 0
    for index, character in enumerate(item):
        if quote:
            if escaped:
                escaped = False
            elif character == "\\" and quote == '"':
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in "'\"":
            quote = character
        elif character in "[{":
            depth += 1
        elif character in "]}":
            depth -= 1
        elif character == ":" and depth == 0:
            return item[:index].strip(), item[index + 1 :].strip()
    raise ValueError("inline YAML mapping item has no key separator")


def flow_collection_end(value: str, start: int) -> int:
    pairs = {"{": "}", "[": "]"}
    stack = []
    quote = None
    escaped = False
    for index in range(start, len(value)):
        character = value[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\" and quote == '"':
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in "'\"":
            quote = character
        elif character in pairs:
            stack.append(pairs[character])
        elif character in "}]":
            if not stack or stack.pop() != character:
                raise ValueError("mismatched inline YAML collection")
            if not stack:
                return index
    raise ValueError("unterminated inline YAML collection")


YAML_METADATA_PATTERN = (
    r"(?:(?:&[A-Za-z0-9_.-]+|!![A-Za-z0-9_.-]+|![A-Za-z0-9_.-]+|!<[^>\r\n]+>)"
    r"[ \t]*)*"
)
YAML_METADATA = re.compile(YAML_METADATA_PATTERN)


def normalize_inline_sniffer(yaml: str, eol: str) -> str:
    match = re.search(
        rf"(?m)^sniffer:[ \t]*(?P<metadata>{YAML_METADATA_PATTERN})(?P<brace>\{{)",
        yaml,
    )
    if not match:
        return yaml
    start = match.start("brace")
    end = flow_collection_end(yaml, start)
    line_break = yaml.find("\n", end)
    if line_break < 0:
        replace_end = len(yaml)
        tail = yaml[end + 1 :].rstrip("\r")
        trailing_eol = ""
    else:
        replace_end = line_break + 1
        tail = yaml[end + 1 : line_break].rstrip("\r")
        trailing_eol = eol
    if not re.fullmatch(r"[ \t]*(?:#.*)?", tail):
        raise ValueError("unsupported content after inline sniffer mapping")
    metadata = match.group("metadata").strip()
    comment = tail.strip()
    header_suffix = "".join(
        part
        for part in (
            f" {metadata}" if metadata else "",
            f" {comment}" if comment else "",
        )
    )
    lines = [f"sniffer:{header_suffix}"]
    for item in split_flow_items(yaml[start + 1 : end]):
        key, value = split_flow_mapping_item(item)
        lines.append(f"  {key}: {value}")
    replacement = eol.join(lines) + trailing_eol
    return yaml[: match.start()] + replacement + yaml[replace_end:]


def parse_inline_list(value: str):
    value = value.strip()
    bracket = value.find("[")
    if bracket < 0:
        raise ValueError("skip-dst-address must be a YAML list")
    prefix = value[:bracket].strip()
    if not YAML_METADATA.fullmatch(prefix):
        raise ValueError("unsupported skip-dst-address YAML metadata")
    end = flow_collection_end(value, bracket)
    if value[end + 1 :].strip():
        raise ValueError("unsupported content after skip-dst-address list")
    return prefix, split_flow_items(value[bracket + 1 : end])


def is_yaml_metadata(value: str) -> bool:
    return bool(value and YAML_METADATA.fullmatch(value.strip()))


def generated_sniffer_block(item_indent: str, cidrs, eol: str) -> str:
    return (
        eol.join(
            [
                f"{item_indent}{SNIFFER_BLOCK_BEGIN}",
                *(f"{item_indent}- {cidr}" for cidr in sorted(cidrs)),
                f"{item_indent}{SNIFFER_BLOCK_END}",
            ]
        )
        + eol
    )


def strip_generated_sniffer_block(section: str, item_indent: str) -> str:
    pattern = re.compile(
        rf"(?m)^{re.escape(item_indent)}{re.escape(SNIFFER_BLOCK_BEGIN)}\r?\n"
        rf"(?P<body>(?:^{re.escape(item_indent)}- [^\r\n]+\r?\n)*)"
        rf"^{re.escape(item_indent)}{re.escape(SNIFFER_BLOCK_END)}\r?\n?"
    )

    def remove(match):
        values = [
            line[len(item_indent) + 2 :].strip()
            for line in match.group("body").splitlines()
        ]
        if not values or any(
            not re.fullmatch(r"(?:[^\s]+)/(?:32|128)", value) for value in values
        ):
            return match.group(0)
        return ""

    return pattern.sub(remove, section)


def inject_sniffer_skip_dst(yaml: str, endpoints) -> str:
    cidrs = endpoint_cidrs(endpoints)
    if not cidrs:
        return yaml

    eol = "\r\n" if "\r\n" in yaml else "\n"
    yaml = normalize_inline_sniffer(yaml, eol)
    header = re.search(
        r"(?m)^sniffer:[ \t]*(?P<value>[^#\r\n]*?)"
        r"(?P<comment>[ \t]+#.*)?(?P<eol>\r?\n|$)",
        yaml,
    )
    if not header:
        return yaml
    header_value = header.group("value").strip()
    if header_value.lower() in {"null", "~"}:
        return yaml
    if header_value and not is_yaml_metadata(header_value):
        raise ValueError("unsupported top-level sniffer YAML value")

    section_end = re.search(r"(?m)^[A-Za-z0-9_-]+[ \t]*:", yaml[header.end() :])
    end = header.end() + section_end.start() if section_end else len(yaml)
    section = yaml[header.end() : end]
    child_indent = "  "
    first_child = re.search(r"(?m)^([ \t]+)[^ #\r\n]", section)
    if first_child:
        child_indent = first_child.group(1)
    item_indent = child_indent + "  "

    field_pattern = re.compile(
        rf"(?m)^{re.escape(child_indent)}skip-dst-address:[ \t]*"
        r"(?P<value>[^#\r\n]*?)(?P<comment>[ \t]+#.*)?(?P<eol>\r?\n|$)"
    )
    field = field_pattern.search(section)
    if field:
        value = field.group("value").strip()
        if value and not is_yaml_metadata(value):
            metadata, user_items = parse_inline_list(value)
            metadata = f" {metadata}" if metadata else ""
            comment = field.group("comment") or ""
            replacement = (
                f"{child_indent}skip-dst-address:{metadata}{comment}{eol}"
                + "".join(f"{item_indent}- {item}{eol}" for item in user_items)
            )
            section = section[: field.start()] + replacement + section[field.end() :]
            field = field_pattern.search(section)
        section_had_final_eol = section.endswith(("\n", "\r"))
        value_start = field.end()
        value_end_match = re.search(
            rf"(?m)^(?:[ \t]{{0,{len(child_indent)}}})[^ #\r\n]", section[value_start:]
        )
        value_end = (
            value_start + value_end_match.start() if value_end_match else len(section)
        )
        prefix = section[:value_start]
        if not field.group("eol"):
            prefix += eol
        original_values = section[value_start:value_end]
        values = strip_generated_sniffer_block(original_values, item_indent)
        block = generated_sniffer_block(item_indent, cidrs, eol)
        if value_end == len(section) and not section_had_final_eol:
            block = block.rstrip("\r\n")
        section = prefix + block + values + section[value_end:]
    else:
        prefix = "" if not section or section.endswith(("\n", "\r")) else eol
        section += (
            prefix
            + f"{child_indent}skip-dst-address:{eol}"
            + generated_sniffer_block(item_indent, cidrs, eol).rstrip("\r\n")
        )
        if end < len(yaml):
            section += eol

    return yaml[: header.end()] + section + yaml[end:]


def wait_for_runtime(base_url: str, secret: str, expected_providers=frozenset()):
    last_error = "API not ready"
    deadline = time.monotonic() + 10
    while True:
        try:
            status, response = api_request(base_url, secret, "GET", "/proxies")
            if status == 200:
                proxies = json.loads(response).get("proxies")
                if isinstance(proxies, dict):
                    provider_status, provider_response = api_request(
                        base_url, secret, "GET", "/providers/proxies"
                    )
                    if provider_status == 200:
                        providers = json.loads(provider_response).get("providers")
                        if (
                            isinstance(providers, dict)
                            and expected_providers <= providers.keys()
                        ):
                            return proxies, providers
                        last_error = "proxy providers not ready"
                    else:
                        last_error = (
                            f"/providers/proxies returned HTTP {provider_status}"
                        )
                        if provider_status in {401, 403}:
                            break
                else:
                    last_error = "invalid /proxies response"
            else:
                last_error = f"/proxies returned HTTP {status}"
                if status in {401, 403}:
                    break
        except (OSError, ValueError, json.JSONDecodeError) as error:
            last_error = str(error)
        if time.monotonic() >= deadline:
            break
        time.sleep(0.25)
    raise RuntimeError(last_error)


def sync(
    config_path: Path = DEFAULT_CONFIG, base_url: str | None = None
) -> tuple[int, int]:
    yaml = config_path.read_text()
    base_url = base_url or api_base_url(yaml)
    secret = yaml_scalar(yaml, "secret")
    providers = provider_configs(yaml)
    proxies, runtime_providers = wait_for_runtime(base_url, secret, providers.keys())

    # Mihomo's API omits server addresses, but its proxy/provider inventories are
    # authoritative for names after provider filters and name overrides.
    servers = {
        server
        for name, server in proxy_records(top_level_section(yaml, "proxies"))
        if name in proxies
    }
    for provider_name, runtime_provider in runtime_providers.items():
        provider = providers.get(provider_name)
        if not provider or not isinstance(runtime_provider, dict):
            continue
        path = provider_path(config_path, provider)
        if path is None:
            continue
        runtime_names = {
            proxy.get("name")
            for proxy in runtime_provider.get("proxies", [])
            if isinstance(proxy, dict) and isinstance(proxy.get("name"), str)
        }
        prefix = provider.get("additional-prefix", "")
        suffix = provider.get("additional-suffix", "")
        try:
            provider_yaml = path.read_text()
            records = proxy_records(
                top_level_section(provider_yaml, "proxies") or provider_yaml
            )
        except (OSError, UnicodeError):
            continue
        servers.update(
            server
            for name, server in records
            if prefix + name + suffix in runtime_names
        )
    if not servers:
        raise RuntimeError("no proxy server endpoints found")
    endpoints = set(servers)
    for server in servers:
        try:
            ipaddress.ip_address(server)
        except ValueError:
            endpoints.update(resolved_addresses(base_url, secret, server))
    # Official Mihomo has no writable /rules route. PUT /configs is its supported
    # API for atomically applying a complete config with generated endpoint
    # rules and matching sniffer exclusions.
    runtime_yaml = inject_direct_rules(yaml, endpoints)
    runtime_yaml = inject_sniffer_skip_dst(runtime_yaml, endpoints)
    status, _ = api_request(
        base_url, secret, "PUT", "/configs?force=true", {"payload": runtime_yaml}
    )
    if status != 204:
        raise RuntimeError(f"/configs returned HTTP {status}")
    return len(proxies), len(endpoints)


def self_test() -> None:
    yaml = """external-controller: '0.0.0.0:9090'
secret: test
proxies:
  - name: one with spaces
    server: Node.Example.COM.
  - {name: two with spaces, server: 192.0.2.4}
  - {"name": "three with spaces", "server": "2001:db8::1"}
dns:
  nameserver:
    - https://dns.example.com/dns-query
sniffer:
  enable: true
  override-destination: true
  skip-dst-address:
    - 192.0.2.99/32
rules:
  - MATCH,PROXY
"""
    servers = extract_servers(yaml)
    assert servers == {"node.example.com", "192.0.2.4", "2001:db8::1"}
    result = inject_direct_rules(yaml, servers)
    expected = {
        "DOMAIN,node.example.com,DIRECT",
        "IP-CIDR,192.0.2.4/32,DIRECT,no-resolve",
        "IP-CIDR6,2001:db8::1/128,DIRECT,no-resolve",
    }
    assert all(
        rule in result and result.index(rule) < result.index("MATCH,PROXY")
        for rule in expected
    )
    assert result.count(BLOCK_BEGIN) == result.count(BLOCK_END) == 1
    result = inject_sniffer_skip_dst(result, servers)
    assert "    - 192.0.2.4/32" in result
    assert "    - 2001:db8::1/128" in result
    assert "    - 192.0.2.99/32" in result
    assert "node.example.com" not in top_level_section(result, "sniffer")
    assert result.count(SNIFFER_BLOCK_BEGIN) == 1
    assert inject_sniffer_skip_dst(result, servers) == result

    no_sniffer = "rules:\n  - MATCH,PROXY\n"
    assert inject_sniffer_skip_dst(no_sniffer, {"192.0.2.4"}) == no_sniffer
    empty_skip = inject_sniffer_skip_dst(
        "sniffer:\n  enable: true\n  skip-dst-address: []\nrules: []\n",
        {"192.0.2.4"},
    )
    assert empty_skip.index("  skip-dst-address:") < empty_skip.index(
        "    - 192.0.2.4/32"
    )

    eof = inject_sniffer_skip_dst("sniffer:\n  enable: true", {"192.0.2.4"})
    assert "enable: true\n  skip-dst-address:" in eof
    assert inject_sniffer_skip_dst(eof, {"192.0.2.4"}) == eof
    eof_field = inject_sniffer_skip_dst(
        "sniffer:\n  enable: true\n  skip-dst-address:", {"192.0.2.4"}
    )
    assert inject_sniffer_skip_dst(eof_field, {"192.0.2.4"}) == eof_field

    crlf = "sniffer:\r\n  enable: true\r\n  skip-dst-address:\r\n    - 203.0.113.7/32\r\nrules: []\r\n"
    crlf_result = inject_sniffer_skip_dst(crlf, {"192.0.2.4"})
    assert "\r\n" in crlf_result and "\n" not in crlf_result.replace("\r\n", "")
    assert inject_sniffer_skip_dst(crlf_result, {"192.0.2.4"}) == crlf_result

    inline_list = inject_sniffer_skip_dst(
        "sniffer:\n  enable: true\n  skip-dst-address: [203.0.113.7/32, '2001:db8::7/128']\nrules: []\n",
        {"192.0.2.4"},
    )
    assert "    - 203.0.113.7/32" in inline_list
    assert "    - '2001:db8::7/128'" in inline_list
    assert "    - 192.0.2.4/32" in inline_list

    inline_sniffer = inject_sniffer_skip_dst(
        "sniffer: {enable: true, sniff: {TLS: {ports: [443, 8443]}}, skip-domain: ['a,b']}\nrules: []\n",
        {"192.0.2.4"},
    )
    assert "  sniff: {TLS: {ports: [443, 8443]}}" in inline_sniffer
    assert "  skip-domain: ['a,b']" in inline_sniffer
    assert "    - 192.0.2.4/32" in inline_sniffer

    multiline_sniffer = inject_sniffer_skip_dst(
        'sniffer: {enable: true,\n  skip-domain: ["a,b", "x:y"],\n  skip-dst-address: [203.0.113.7/32]}\nrules: []\n',
        {"192.0.2.4"},
    )
    assert '  skip-domain: ["a,b", "x:y"]' in multiline_sniffer
    assert "    - 203.0.113.7/32" in multiline_sniffer
    assert "    - 192.0.2.4/32" in multiline_sniffer
    assert (
        inject_sniffer_skip_dst(multiline_sniffer, {"192.0.2.4"}) == multiline_sniffer
    )

    anchored = inject_sniffer_skip_dst(
        "sniffer:\n  skip-dst-address: &skip [203.0.113.7/32]\nrules: []\n",
        {"192.0.2.4"},
    )
    tagged = inject_sniffer_skip_dst(
        "sniffer:\n  skip-dst-address: !!seq [203.0.113.8/32]\nrules: []\n",
        {"192.0.2.4"},
    )
    assert "  skip-dst-address: &skip\n" in anchored
    assert "    - 203.0.113.7/32" in anchored
    assert "  skip-dst-address: !!seq\n" in tagged
    assert "    - 203.0.113.8/32" in tagged

    inline_crlf = inject_sniffer_skip_dst(
        "sniffer:\r\n  skip-dst-address: [203.0.113.7/32]\r\nrules: []\r\n",
        {"192.0.2.4"},
    )
    assert "\n" not in inline_crlf.replace("\r\n", "")
    assert inject_sniffer_skip_dst(inline_crlf, {"192.0.2.4"}) == inline_crlf

    metadata_sniffer = inject_sniffer_skip_dst(
        "sniffer: &sniff {enable: true, skip-domain: [example.com]} # retained\nrules: []\n",
        {"192.0.2.4"},
    )
    assert "sniffer: &sniff # retained\n" in metadata_sniffer
    assert "    - 192.0.2.4/32" in metadata_sniffer
    assert inject_sniffer_skip_dst(metadata_sniffer, {"192.0.2.4"}) == metadata_sniffer
    null_sniffer = "sniffer: null\nrules: []\n"
    assert inject_sniffer_skip_dst(null_sniffer, {"192.0.2.4"}) == null_sniffer
    try:
        inject_sniffer_skip_dst("sniffer: *shared\nrules: []\n", {"192.0.2.4"})
    except ValueError as error:
        assert "unsupported top-level sniffer" in str(error)
    else:
        raise AssertionError("unsupported sniffer alias was silently accepted")

    collision = f"notes:\n  {SNIFFER_BLOCK_BEGIN}\n  keep me\n  {SNIFFER_BLOCK_END}\nsniffer:\n  enable: true\n"
    collision_result = inject_sniffer_skip_dst(collision, {"192.0.2.4"})
    assert (
        f"  {SNIFFER_BLOCK_BEGIN}\n  keep me\n  {SNIFFER_BLOCK_END}" in collision_result
    )
    assert collision_result.count(SNIFFER_BLOCK_BEGIN) == 2

    try:
        import yaml as yaml_parser
    except ImportError:
        yaml_parser = None
    if yaml_parser:
        for document in (
            eof,
            eof_field,
            crlf_result,
            inline_list,
            inline_sniffer,
            multiline_sniffer,
            anchored,
            tagged,
            inline_crlf,
            metadata_sniffer,
            null_sniffer,
            collision_result,
        ):
            yaml_parser.safe_load(document)

    null_rules = inject_direct_rules("rules: ~\n", {"192.0.2.4"})
    assert "IP-CIDR,192.0.2.4/32,DIRECT,no-resolve" in null_rules
    indentless = inject_direct_rules("rules:\n- MATCH,PROXY\n", {"proxy.example"})
    assert "\n- DOMAIN,proxy.example,DIRECT\n" in indentless

    requests = []
    runtime_providers = {}
    original_api_request = globals()["api_request"]

    def fake_api_request(base_url, secret, method, path, body=None):
        requests.append((secret, method, path, body))
        if path == "/proxies":
            return 200, b'{"proxies":{"one with spaces":{"type":"Vless"}}}'
        if path == "/providers/proxies":
            providers = {
                "active": {"proxies": []},
                "remote": {"proxies": []},
                "inactive": {"proxies": []},
            }
            providers.update(runtime_providers)
            return 200, json.dumps({"providers": providers}).encode()
        if path == "/dns/query?name=node.example.com&type=A":
            return 200, b'{"Answer":[{"data":"198.51.100.7"}]}'
        if path == "/dns/query?name=node.example.com&type=AAAA":
            return 200, b'{"Answer":[{"data":"2001:db8::7"}]}'
        if path.endswith("type=A"):
            return 503, b'{"message":"DNS unavailable"}'
        if path.endswith("type=AAAA"):
            return 200, b'{"Answer":[{"data":"not-an-address"}]}'
        return 204, b""

    try:
        globals()["api_request"] = fake_api_request
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.yaml"
            config.write_text(yaml)
            assert sync(config, "http://127.0.0.1:9090") == (1, 3)

            provider = Path(directory) / "custom-provider.data"
            provider.write_text(
                """proxies:
  - {name: kept with spaces, server: kept.example.com}
  - {name: filtered with spaces, server: filtered.example.com}
proxy-groups:
  - name: group
    proxies: [kept with spaces, filtered with spaces]
"""
            )
            provider_config = Path(directory) / "provider-config.yaml"
            provider_config.write_text(
                """external-controller: 127.0.0.1:9090
secret: test
proxy-providers:
  active:
    type: file
    path: custom-provider.data
  remote:
    type: http
    url: https://example.com/subscription
  inactive:
    type: file
    path: ignored.yaml
rules: null
"""
            )
            remote = (
                Path(directory)
                / "proxies"
                / hashlib.md5(
                    b"https://example.com/subscription", usedforsecurity=False
                ).hexdigest()
            )
            assert set(
                provider_paths(
                    provider_config.read_text(), provider_config, {"active", "remote"}
                )
            ) == {provider, remote}
            runtime_providers["active"] = {"proxies": [{"name": "kept with spaces"}]}
            request_count = len(requests)
            assert sync(provider_config, "http://127.0.0.1:9090") == (1, 1)
            provider_payload = next(
                body["payload"]
                for _, method, path, body in requests[request_count:]
                if method == "PUT" and path == "/configs?force=true"
            )
            assert "DOMAIN,kept.example.com,DIRECT" in provider_payload
            assert "filtered.example.com" not in provider_payload
    finally:
        globals()["api_request"] = original_api_request

    original_monotonic = time.monotonic
    original_sleep = time.sleep
    original_api_request = globals()["api_request"]
    clock = iter((0.0, 10.0))
    try:
        time.monotonic = lambda: next(clock)
        time.sleep = lambda _: None
        globals()["api_request"] = lambda *args, **kwargs: (_ for _ in ()).throw(
            OSError("offline")
        )
        try:
            wait_for_runtime("http://127.0.0.1:9090", "")
        except RuntimeError as error:
            assert str(error) == "offline"
        else:
            raise AssertionError("zero-wait API failure should raise RuntimeError")
    finally:
        time.monotonic = original_monotonic
        time.sleep = original_sleep
        globals()["api_request"] = original_api_request

    assert requests[0][1:3] == ("GET", "/proxies")
    assert requests[1][1:3] == ("GET", "/providers/proxies")
    assert requests[2][1:3] == (
        "GET",
        "/dns/query?name=node.example.com&type=A",
    )
    assert requests[3][1:3] == (
        "GET",
        "/dns/query?name=node.example.com&type=AAAA",
    )
    payload = next(
        body["payload"]
        for _, method, path, body in requests
        if method == "PUT" and path == "/configs?force=true"
    )
    assert payload.index("DOMAIN,node.example.com,DIRECT") < payload.index(
        "MATCH,PROXY"
    )
    assert "IP-CIDR,198.51.100.7/32,DIRECT,no-resolve" in payload
    assert "IP-CIDR6,2001:db8::7/128,DIRECT,no-resolve" in payload
    assert "    - 198.51.100.7/32" in payload
    assert "    - 2001:db8::7/128" in payload
    assert payload.count(SNIFFER_BLOCK_BEGIN) == 1
    print("self-test: ok")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Add DIRECT rules for active Mihomo proxy endpoints"
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--api-url", help="override external-controller URL")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    proxy_count, endpoint_count = sync(args.config, args.api_url)
    print(
        f"clash proxy bypass: loaded {proxy_count} API entries; "
        f"applied {endpoint_count} DIRECT endpoint rules"
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"clash proxy bypass: {error}", file=sys.stderr)
        raise SystemExit(1)
