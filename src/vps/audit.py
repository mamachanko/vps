import ipaddress
import json
import platform
import re
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum


class Status(StrEnum):
    ACTION = "action"
    REVIEW = "review"
    UNKNOWN = "unknown"
    PASS = "pass"


class Verdict(StrEnum):
    ACTION_NEEDED = "action_needed"
    REVIEW_NEEDED = "review_needed"
    INCOMPLETE = "incomplete"
    BASELINE_PASSED = "baseline_passed"


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    status: Status
    evidence: str
    hint: str | None = None


@dataclass(frozen=True)
class AuditReport:
    host: str
    system: str
    findings: tuple[Finding, ...]

    @property
    def verdict(self) -> Verdict:
        statuses = {finding.status for finding in self.findings}
        for status, verdict in (
            (Status.ACTION, Verdict.ACTION_NEEDED),
            (Status.REVIEW, Verdict.REVIEW_NEEDED),
            (Status.UNKNOWN, Verdict.INCOMPLETE),
        ):
            if status in statuses:
                return verdict
        return Verdict.BASELINE_PASSED


@dataclass(frozen=True)
class _ProbeFailure:
    evidence: str


_TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_SSH_SCOPE = "Global on-disk settings."
_SSH_SAFETY = (
    "Before changing SSH, test key login and sudo in a second session, keep the "
    "existing session open, and run sudo sshd -t before reloading."
)
_SSH_INSPECT = (
    "Run sudo sshd -T to inspect global settings and review Match rules for your login."
)
_FIREWALL_INSPECT = (
    "Inspect sudo nft list ruleset or the active firewall manager. Review explicit "
    "allow rules and the provider firewall."
)
_FIREWALL_HINT = (
    _FIREWALL_INSPECT + " Before changing input policies, preserve SSH access "
    "and arrange recovery access."
)
_UPDATE_HINT = (
    "Review unattended-upgrades settings in /etc/apt/apt.conf.d and recent runs. "
    "On another distribution, check its update manager."
)


def _run_tool(name: str, *arguments: str) -> str | _ProbeFailure:
    executable = shutil.which(name, path=_TRUSTED_PATH)
    if executable is None:
        return _ProbeFailure(f"{name} is not available in standard system directories.")
    try:
        result = subprocess.run(
            [executable, *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3,
            check=False,
            env={"PATH": _TRUSTED_PATH, "LC_ALL": "C", "LANG": "C"},
        )
    except FileNotFoundError:
        return _ProbeFailure(f"{name} is no longer available.")
    except PermissionError:
        return _ProbeFailure(f"Permission denied while executing {name}.")
    except subprocess.TimeoutExpired:
        return _ProbeFailure(f"{name} timed out after 3 seconds.")
    except OSError:
        return _ProbeFailure(f"{name} could not be executed.")
    if result.returncode != 0:
        permission_errors = (
            "permission denied",
            "operation not permitted",
            "must be root",
            "requires root",
            "are you root",
        )
        if any(message in result.stderr.lower() for message in permission_errors):
            return _ProbeFailure(f"Permission denied while reading {name} evidence.")
        return _ProbeFailure(f"{name} failed with exit status {result.returncode}.")
    if len(result.stdout) > 1024 * 1024:
        return _ProbeFailure(
            f"{name} returned more evidence than this probe can inspect."
        )
    return result.stdout


def _ssh_findings(output: str | _ProbeFailure) -> tuple[Finding, Finding]:
    root_title = "SSH root login"
    password_title = "SSH password authentication"
    if isinstance(output, _ProbeFailure):
        return (
            Finding(
                "ssh_root_login",
                root_title,
                Status.UNKNOWN,
                output.evidence,
                _SSH_INSPECT,
            ),
            Finding(
                "ssh_password_auth",
                password_title,
                Status.UNKNOWN,
                output.evidence,
                _SSH_INSPECT,
            ),
        )
    settings: dict[str, str | None] = {}
    for line in output.splitlines():
        parts = line.split(maxsplit=1)
        if parts and parts[0] in {
            "permitrootlogin",
            "passwordauthentication",
            "kbdinteractiveauthentication",
            "authenticationmethods",
        }:
            key = parts[0]
            value = parts[1] if len(parts) == 2 else ""
            settings[key] = value if key not in settings and len(value) <= 256 else None

    root = settings.get("permitrootlogin")
    if root == "no":
        root_status = Status.PASS
    elif root == "yes":
        root_status = Status.ACTION
    elif root in {"prohibit-password", "without-password", "forced-commands-only"}:
        root_status = Status.REVIEW
    else:
        root_status = Status.UNKNOWN
    root_evidence = (
        f"PermitRootLogin {root}. "
        if root_status != Status.UNKNOWN
        else "PermitRootLogin is absent or unrecognized. "
    ) + _SSH_SCOPE
    root_finding = Finding(
        "ssh_root_login",
        root_title,
        root_status,
        root_evidence,
        None
        if root_status == Status.PASS
        else _SSH_INSPECT
        if root_status == Status.UNKNOWN
        else "Prefer a sudo user and PermitRootLogin no. " + _SSH_SAFETY,
    )

    password = settings.get("passwordauthentication")
    interactive = settings.get("kbdinteractiveauthentication")
    methods = settings.get("authenticationmethods")
    if password not in {"yes", "no"} or interactive not in {"yes", "no"}:
        password_status = Status.UNKNOWN
        password_evidence = (
            "Password or keyboard-interactive setting is absent or unrecognized. "
        )
    elif password == interactive == "no":
        password_status = Status.PASS
        password_evidence = (
            "PasswordAuthentication no. KbdInteractiveAuthentication no. "
        )
    elif not _valid_authentication_methods(methods):
        password_status = Status.UNKNOWN
        password_evidence = "AuthenticationMethods is absent or unrecognized. "
    else:
        unchained_password = methods == "any" or "password" in methods.split()
        password_status = (
            Status.ACTION if password == "yes" and unchained_password else Status.REVIEW
        )
        password_evidence = (
            f"PasswordAuthentication {password}. KbdInteractiveAuthentication "
            f"{interactive}. AuthenticationMethods {methods}. "
        )
    password_finding = Finding(
        "ssh_password_auth",
        password_title,
        password_status,
        password_evidence + _SSH_SCOPE,
        None
        if password_status == Status.PASS
        else _SSH_INSPECT + " Keyboard-interactive may be required for MFA."
        if password_status == Status.UNKNOWN
        else "Prefer keys and disable password authentication where it is not required. "
        "Keyboard-interactive may be required for MFA. " + _SSH_SAFETY,
    )
    return root_finding, password_finding


def _valid_authentication_methods(value: str | None) -> bool:
    if value == "any":
        return True
    if not value:
        return False
    methods = {
        "publickey",
        "password",
        "keyboard-interactive",
        "keyboard-interactive:pam",
        "keyboard-interactive:bsdauth",
        "hostbased",
        "gssapi-with-mic",
    }
    return all(
        method in methods
        for alternative in value.split()
        for method in alternative.split(",")
    )


def _socket_address(value: str) -> tuple[str, bool] | None:
    if len(value) > 128 or ":" not in value:
        return None
    host, port = value.rsplit(":", 1)
    if port != "*" and (
        not port.isascii() or not port.isdecimal() or int(port) > 65535
    ):
        return None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host == "*":
        return f"*:{port}", False
    host, separator, scope = host.partition("%")
    if separator and (not scope or "%" in scope):
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    loopback = address.is_loopback
    display_host = f"{address}%{scope}" if separator else str(address)
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            loopback = address.ipv4_mapped.is_loopback
        return f"[{display_host}]:{port}", loopback
    return f"{display_host}:{port}", loopback


def _listener_finding(output: str | _ProbeFailure) -> Finding:
    title = "Network listeners"
    hint = "Use ss -lntup to identify services. Confirm intended listeners and provider firewall rules."
    if isinstance(output, _ProbeFailure):
        return Finding(
            "network_listeners", title, Status.UNKNOWN, output.evidence, hint
        )
    exposed = []
    total = 0
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        if (
            len(parts) != 6
            or parts[0] not in {"tcp", "udp"}
            or parts[1] != {"tcp": "LISTEN", "udp": "UNCONN"}.get(parts[0])
            or not all(part.isascii() and part.isdecimal() for part in parts[2:4])
        ):
            return Finding(
                "network_listeners",
                title,
                Status.UNKNOWN,
                "ss returned an unrecognized TCP/UDP listener record.",
                hint,
            )
        local = _socket_address(parts[4])
        peer = _socket_address(parts[5])
        if local is None or peer is None:
            return Finding(
                "network_listeners",
                title,
                Status.UNKNOWN,
                "ss returned an unrecognized socket address.",
                hint,
            )
        total += 1
        endpoint, loopback = local
        if not loopback:
            exposed.append(f"{parts[0]} {endpoint}")
    if not exposed:
        return Finding(
            "network_listeners",
            title,
            Status.PASS,
            f"No non-loopback TCP/UDP listeners found ({total} bindings inspected).",
        )
    examples = ", ".join(sorted(exposed)[:5])
    return Finding(
        "network_listeners",
        title,
        Status.REVIEW,
        f"{len(exposed)} non-loopback TCP/UDP bindings: {examples}. "
        f"{total} bindings inspected. External reachability not checked.",
        hint,
    )


def _firewall_finding(output: str | _ProbeFailure) -> Finding:
    title = "Firewall input default policy"
    unknown = "nft returned an unrecognized ruleset. Input default policies could not be verified."
    if isinstance(output, _ProbeFailure):
        return Finding(
            "firewall_input_policy",
            title,
            Status.UNKNOWN,
            output.evidence,
            _FIREWALL_INSPECT,
        )
    try:
        data = json.loads(output)
        policies, covered, dormant = _input_policies(data)
    except (ValueError, TypeError, KeyError):
        return Finding(
            "firewall_input_policy", title, Status.UNKNOWN, unknown, _FIREWALL_INSPECT
        )
    counts = Counter(policies)
    details = (
        ", ".join(f"{policy} ({count})" for policy, count in sorted(counts.items()))
        or "no filter base input hooks"
    )
    coverage = "/".join(sorted(covered)) or "none"
    status = (
        Status.PASS if covered == {"IPv4", "IPv6"} and not dormant else Status.REVIEW
    )
    evidence = (
        f"Live nftables input default policies: {details}. "
        f"Default-drop coverage: {coverage}. {len(policies)} input policies inspected."
    )
    if dormant:
        evidence += " Dormant IP tables are present and do not count toward coverage."
    return Finding("firewall_input_policy", title, status, evidence, _FIREWALL_HINT)


def _input_policies(data: object) -> tuple[list[str], set[str], bool]:
    if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
        raise ValueError
    tables: dict[tuple[str, str], bool] = {}
    chains = []
    for item in data["nftables"]:
        if not isinstance(item, dict) or len(item) != 1:
            raise ValueError
        if "table" in item:
            table = item["table"]
            if not isinstance(table, dict):
                raise ValueError
            family, name = table.get("family"), table.get("name")
            flags = table.get("flags", [])
            if (
                not isinstance(family, str)
                or not isinstance(name, str)
                or not isinstance(flags, list)
                or not all(isinstance(flag, str) for flag in flags)
                or (family, name) in tables
            ):
                raise ValueError
            tables[(family, name)] = "dormant" in flags
        elif "chain" in item:
            chains.append(item["chain"])
    policies = []
    covered: set[str] = set()
    for chain in chains:
        if not isinstance(chain, dict):
            raise ValueError
        family, table, name = chain.get("family"), chain.get("table"), chain.get("name")
        if not all(isinstance(value, str) for value in (family, table, name)):
            raise ValueError
        if (family, table) not in tables:
            raise ValueError
        if family not in {"ip", "ip6", "inet"} or chain.get("hook") != "input":
            continue
        policy = chain.get("policy")
        if chain.get("type") != "filter" or policy not in {"accept", "drop"}:
            raise ValueError
        inactive = tables[(family, table)]
        policies.append(f"{family} {policy}" + (" dormant" if inactive else ""))
        if policy == "drop" and not inactive:
            if family in {"ip", "inet"}:
                covered.add("IPv4")
            if family in {"ip6", "inet"}:
                covered.add("IPv6")
    dormant = any(
        inactive
        for (family, _), inactive in tables.items()
        if family in {"ip", "ip6", "inet"}
    )
    return policies, covered, dormant


def _update_finding(output: str | _ProbeFailure) -> Finding:
    title = "Automatic update schedule"
    if isinstance(output, _ProbeFailure):
        return Finding(
            "automatic_updates", title, Status.UNKNOWN, output.evidence, _UPDATE_HINT
        )
    values: dict[str, str] = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"(PERIODIC|UPDATE|UNATTENDED)='([^']{0,32})';?", line)
        if match is None or match[1] in values:
            return Finding(
                "automatic_updates",
                title,
                Status.UNKNOWN,
                "apt-config returned unrecognized periodic settings.",
                _UPDATE_HINT,
            )
        values[match[1]] = match[2]
    periodic = values.get("PERIODIC", "1")
    update = values.get("UPDATE", "0")
    unattended = values.get("UNATTENDED", "0")
    if re.fullmatch(r"[0-9]+", periodic) is None or any(
        re.fullmatch(r"(?:[0-9]+[smhd]?|always)", value) is None
        for value in (update, unattended)
    ):
        return Finding(
            "automatic_updates",
            title,
            Status.UNKNOWN,
            "APT periodic enable or interval values are unrecognized.",
            _UPDATE_HINT,
        )
    scheduled = int(periodic) > 0 and all(
        value == "always" or int(value.rstrip("smhd")) > 0
        for value in (update, unattended)
    )
    installed = shutil.which("unattended-upgrade", path=_TRUSTED_PATH) is not None
    evidence = (
        f"APT periodic enable={periodic}"
        + (" (default)" if "PERIODIC" not in values else "")
        + f". Package-list interval={update}. Unattended-upgrade interval={unattended}. "
        + f"Unattended-upgrade executable {'found' if installed else 'not found'}. "
        "Review recent runs and installed patches separately."
    )
    return Finding(
        "automatic_updates",
        title,
        Status.PASS if scheduled and installed else Status.REVIEW,
        evidence,
        _UPDATE_HINT,
    )


def collect_audit() -> AuditReport:
    """Inspect five Linux hardening baselines without elevation or changes."""
    ssh = _ssh_findings(_run_tool("sshd", "-T"))
    findings = (
        *ssh,
        _listener_finding(_run_tool("ss", "-H", "-lntu")),
        _firewall_finding(_run_tool("nft", "--json", "--terse", "list", "ruleset")),
        _update_finding(
            _run_tool(
                "apt-config",
                "shell",
                "PERIODIC",
                "APT::Periodic::Enable",
                "UPDATE",
                "APT::Periodic::Update-Package-Lists",
                "UNATTENDED",
                "APT::Periodic::Unattended-Upgrade",
            )
        ),
    )
    try:
        system = (
            platform.freedesktop_os_release().get("PRETTY_NAME") or platform.system()
        )
    except OSError:
        system = platform.system()
    order = {status: index for index, status in enumerate(Status)}
    return AuditReport(
        platform.node()[:255] or "unknown",
        system[:255],
        tuple(sorted(findings, key=lambda finding: order[finding.status])),
    )
