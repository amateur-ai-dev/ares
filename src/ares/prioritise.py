"""JSON-only substitute for Hayabusa's relevance ordering.

Hayabusa cannot consume the OTRF APT29 JSON corpus (it ships JSON, PCAP, and
Zeek artifacts rather than EVTX).  These transparent, deliberately cheap
heuristics only order already-verified edges for model context; they never
create, verify, suppress, or badge an edge.
"""

from dataclasses import dataclass
from ipaddress import IPv4Address, ip_address, ip_network
import ntpath

from .predicates import PROCESS_OPENED_CONNECTION, SPAWNED


LOLBINS = frozenset({
    "rundll32", "regsvr32", "mshta", "wscript", "cscript", "certutil",
    "bitsadmin", "powershell", "cmd", "schtasks", "at", "wmic", "msbuild",
    "installutil", "sc", "net", "whoami", "systeminfo",
})
SHELL_OR_SCRIPT_HOSTS = frozenset({"cmd", "powershell", "wscript", "cscript", "mshta", "rundll32", "regsvr32"})
OFFICE_OR_BROWSER = frozenset({"winword", "excel", "powerpnt", "outlook", "onenote", "chrome", "msedge", "firefox", "iexplore"})
OBFUSCATION_MARKERS = (
    "-enc", "-encodedcommand", "frombase64string", "iex", "invoke-expression",
    "downloadstring", "-w hidden", "-nop", "bypass",
)
COMMON_PORTS = frozenset({
    20, 21, 22, 23, 25, 53, 67, 68, 80, 88, 110, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 464, 465, 587, 636, 993, 995, 1433, 1521,
    3306, 3389, 5432, 5985, 5986, 8080, 8443,
})


@dataclass(frozen=True)
class PrioritisedEdge:
    edge: object
    score: int
    reasons: tuple[str, ...]


def _event(value):
    return getattr(value, "event", value)


def _basename(value):
    return ntpath.splitext(ntpath.basename(str(value or "")))[0].lower()


def _process_events(edge):
    return [
        ("source", _event(edge.source)),
        ("target", _event(edge.target)),
    ]


def _is_outside_system_directories(image):
    value = str(image or "").strip().lower().replace("/", "\\")
    return bool(value) and not (
        value.startswith("c:\\windows\\")
        or value.startswith("c:\\program files\\")
        or value.startswith("c:\\program files (x86)\\")
    )


def _is_rfc1918(destination):
    try:
        value = ip_address(str(destination))
    except ValueError:
        return False
    return isinstance(value, IPv4Address) and (
        value in ip_network("10.0.0.0/8")
        or value in ip_network("172.16.0.0/12")
        or value in ip_network("192.168.0.0/16")
    )


def _user_writable_path(path):
    value = str(path or "").lower().replace("/", "\\")
    return "\\appdata\\local\\temp\\" in value or "\\appdata\\roaming\\" in value


def _referenced_user_writable_write(edge, events):
    references = []
    for _, event in _process_events(edge):
        references.extend((str(event.get("Image", "")), str(event.get("CommandLine", ""))))
    references = "\n".join(references).lower().replace("/", "\\")
    edge_time = max(str(_event(edge.source).get("EventTime", "")), str(_event(edge.target).get("EventTime", "")))
    for item in events:
        event = _event(item)
        if event.get("EventID") != 11 or event.get("Channel") != "Microsoft-Windows-Sysmon/Operational":
            continue
        path = event.get("TargetFilename")
        if not _user_writable_path(path):
            continue
        normalised = str(path).lower().replace("/", "\\")
        if normalised in references and str(event.get("EventTime", "")) <= edge_time:
            return normalised
    return None


def score_edge_relevance(edge, events):
    """Return a small explainable relevance score and its contributing reasons."""
    reasons = []
    endpoints = _process_events(edge)
    for label, event in endpoints:
        if event.get("EventID") == 1 and _is_outside_system_directories(event.get("Image")):
            reasons.append(f"{label}_image_outside_system_directories")
    if any(_basename(event.get("Image")) in LOLBINS for _, event in endpoints):
        reasons.append("living_off_the_land_binary")
    command_lines = "\n".join(str(event.get("CommandLine", "")) for _, event in endpoints).lower()
    if any(marker.lower() in command_lines for marker in OBFUSCATION_MARKERS):
        reasons.append("encoded_or_obfuscated_command")
    if edge.relation_type == SPAWNED:
        source_name = _basename(_event(edge.source).get("Image"))
        target_name = _basename(_event(edge.target).get("Image"))
        if source_name in OFFICE_OR_BROWSER and target_name in SHELL_OR_SCRIPT_HOSTS:
            reasons.append("office_or_browser_started_shell_or_script_host")
    if edge.relation_type == PROCESS_OPENED_CONNECTION:
        connection = _event(edge.target)
        destination = connection.get("DestinationIp")
        if destination and not _is_rfc1918(destination):
            reasons.append("non_rfc1918_destination")
        try:
            port = int(connection.get("DestinationPort"))
        except (TypeError, ValueError):
            port = None
        if port is not None and port not in COMMON_PORTS:
            reasons.append("uncommon_destination_port")
    written_path = _referenced_user_writable_write(edge, events)
    if written_path:
        reasons.append(f"user_writable_write_referenced:{written_path}")
    return len(reasons), tuple(reasons)


def prioritise_edges(edges, events):
    """Return all input edges in descending relevance order without filtering them."""
    ranked = [
        PrioritisedEdge(edge, *score_edge_relevance(edge, events))
        for edge in edges
    ]
    return sorted(ranked, key=lambda item: -item.score)
