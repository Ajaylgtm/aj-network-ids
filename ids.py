"""A small, dependency-free IPv4 PCAP intrusion detection tool."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import subprocess
import struct
import sys
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterator


class PcapFormatError(ValueError):
    """Raised when a PCAP file is invalid or truncated."""


@dataclass(frozen=True)
class Packet:
    timestamp: float
    src: str
    dst: str
    protocol: str
    src_port: int | None
    dst_port: int | None
    tcp_flags: int
    length: int


@dataclass(frozen=True)
class Alert:
    timestamp: str
    severity: str
    rule: str
    source: str
    description: str
    evidence: dict[str, int]


def _read_exact(stream: BinaryIO, length: int, context: str) -> bytes:
    data = stream.read(length)
    if len(data) != length:
        raise PcapFormatError(f"Truncated {context}")
    return data


def iter_pcap(stream: BinaryIO) -> Iterator[Packet]:
    """Yield supported IPv4 packets from a classic PCAP stream."""
    header = _read_exact(stream, 24, "PCAP global header")
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if header[:4] not in formats:
        raise PcapFormatError("Unsupported PCAP magic; expected classic PCAP")
    endian, time_units = formats[header[:4]]
    major, _minor, _zone, _sigfigs, snaplen, link_type = struct.unpack(
        endian + "HHiIII", header[4:]
    )
    if major != 2:
        raise PcapFormatError(f"Unsupported PCAP version {major}")
    if snaplen == 0:
        raise PcapFormatError("Invalid PCAP snap length")
    if link_type != 1:
        raise PcapFormatError(
            f"Unsupported link type {link_type}; Ethernet (1) is required"
        )

    while True:
        record_header = stream.read(16)
        if not record_header:
            return
        if len(record_header) != 16:
            raise PcapFormatError("Truncated PCAP packet header")
        seconds, fraction, captured_len, _original_len = struct.unpack(
            endian + "IIII", record_header
        )
        if captured_len > snaplen or captured_len > 16 * 1024 * 1024:
            raise PcapFormatError(f"Invalid captured packet length {captured_len}")
        frame = _read_exact(stream, captured_len, "PCAP packet data")
        packet = _parse_ethernet(frame, seconds + fraction / time_units)
        if packet is not None:
            yield packet


def _parse_ethernet(frame: bytes, timestamp: float) -> Packet | None:
    if len(frame) < 14:
        return None
    ether_type = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    while ether_type in (0x8100, 0x88A8, 0x9100):
        if len(frame) < offset + 4:
            return None
        ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    if ether_type != 0x0800 or len(frame) < offset + 20:
        return None

    ip_header = frame[offset:]
    version_ihl = ip_header[0]
    ihl = (version_ihl & 0x0F) * 4
    if version_ihl >> 4 != 4 or ihl < 20 or len(ip_header) < ihl:
        return None
    total_len = struct.unpack_from("!H", ip_header, 2)[0]
    if total_len < ihl or len(ip_header) < total_len:
        return None

    fragment = struct.unpack_from("!H", ip_header, 6)[0]
    if fragment & 0x1FFF:
        return None
    protocol_number = ip_header[9]
    src = str(ipaddress.IPv4Address(ip_header[12:16]))
    dst = str(ipaddress.IPv4Address(ip_header[16:20]))
    transport = ip_header[ihl:total_len]
    src_port = dst_port = None
    tcp_flags = 0

    if protocol_number == 6:
        if len(transport) < 20:
            return None
        src_port, dst_port = struct.unpack_from("!HH", transport)
        tcp_header_len = (transport[12] >> 4) * 4
        if tcp_header_len < 20 or len(transport) < tcp_header_len:
            return None
        tcp_flags = transport[13]
        protocol = "TCP"
    elif protocol_number == 17:
        if len(transport) < 8:
            return None
        src_port, dst_port = struct.unpack_from("!HH", transport)
        protocol = "UDP"
    elif protocol_number == 1:
        protocol = "ICMP"
    else:
        protocol = f"IP-{protocol_number}"

    return Packet(
        timestamp, src, dst, protocol, src_port, dst_port, tcp_flags, total_len
    )


class IntrusionDetector:
    """Detect common scan and burst patterns in a stream of decoded packets."""

    def __init__(
        self,
        *,
        window_seconds: int = 60,
        port_scan_threshold: int = 10,
        host_scan_threshold: int = 10,
        syn_burst_threshold: int = 100,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if min(port_scan_threshold, host_scan_threshold, syn_burst_threshold) <= 0:
            raise ValueError("detection thresholds must be positive")
        self.window_seconds = window_seconds
        self.port_scan_threshold = port_scan_threshold
        self.host_scan_threshold = host_scan_threshold
        self.syn_burst_threshold = syn_burst_threshold
        self._syn_windows: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)
        self._reported: set[tuple[str, str]] = set()
        self.alerts: list[Alert] = []
        self.packet_count = 0

    def process(self, packet: Packet) -> None:
        self.packet_count += 1
        if packet.protocol != "TCP" or packet.tcp_flags & 0x12 != 0x02:
            return
        if packet.dst_port is None:
            return

        window = self._syn_windows[packet.src]
        window.append((packet.timestamp, packet.dst, packet.dst_port))
        cutoff = packet.timestamp - self.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()

        ports = {entry[2] for entry in window}
        hosts = {entry[1] for entry in window}
        self._report_once(
            packet,
            "TCP_SYN_PORT_SCAN",
            "medium",
            len(ports) >= self.port_scan_threshold,
            f"Source sent SYN packets to {len(ports)} distinct destination ports "
            f"within {self.window_seconds}s",
            {"distinct_destination_ports": len(ports)},
        )
        self._report_once(
            packet,
            "TCP_SYN_HOST_SCAN",
            "medium",
            len(hosts) >= self.host_scan_threshold,
            f"Source sent SYN packets to {len(hosts)} distinct destination hosts "
            f"within {self.window_seconds}s",
            {"distinct_destination_hosts": len(hosts)},
        )
        self._report_once(
            packet,
            "TCP_SYN_BURST",
            "high",
            len(window) >= self.syn_burst_threshold,
            f"Source sent {len(window)} TCP SYN packets within {self.window_seconds}s",
            {"syn_packets": len(window)},
        )

    def _report_once(
        self,
        packet: Packet,
        rule: str,
        severity: str,
        matched: bool,
        description: str,
        evidence: dict[str, int],
    ) -> None:
        key = (packet.src, rule)
        if not matched or key in self._reported:
            return
        self._reported.add(key)
        timestamp = datetime.fromtimestamp(packet.timestamp, timezone.utc).isoformat()
        self.alerts.append(
            Alert(timestamp, severity, rule, packet.src, description, evidence)
        )


def analyze(stream: BinaryIO, detector: IntrusionDetector | None = None) -> IntrusionDetector:
    result = detector or IntrusionDetector()
    for packet in iter_pcap(stream):
        result.process(packet)
    return result


DEFAULT_WATCH_DIR = Path.home() / "NetworkIDS" / "captures"
STARTUP_ENTRY_NAME = "NetworkIDS.vbs"


class CaptureWatcher:
    """Wait for finished PCAP files and analyze each file once per version."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self._observed: dict[Path, tuple[tuple[int, int], int]] = {}
        self._processed: dict[Path, tuple[int, int]] = {}

    def poll_once(self) -> None:
        current_paths = {
            path.resolve()
            for path in self.directory.iterdir()
            if path.is_file() and path.suffix.lower() in {".pcap", ".cap"}
        }
        for path in set(self._observed) | set(self._processed):
            if path not in current_paths:
                self._observed.pop(path, None)
                self._processed.pop(path, None)

        for path in sorted(current_paths):
            stat = path.stat()
            signature = (stat.st_size, stat.st_mtime_ns)
            if self._processed.get(path) == signature:
                continue

            previous = self._observed.get(path)
            stable_polls = previous[1] + 1 if previous and previous[0] == signature else 1
            self._observed[path] = (signature, stable_polls)
            if stable_polls < 2:
                continue

            try:
                with path.open("rb") as capture:
                    detector = analyze(capture)
            except (OSError, PcapFormatError, ValueError) as error:
                print(f"ids: could not analyze {path}: {error}", file=sys.stderr)
            else:
                print(f"Analyzed {detector.packet_count} IPv4 packets from {path}")
                for alert in detector.alerts:
                    print(
                        f"[{alert.severity.upper()}] {alert.rule} from {alert.source} "
                        f"at {alert.timestamp}: {alert.description}"
                    )
            self._processed[path] = signature


def watch_captures(directory: Path, poll_interval: float) -> None:
    if poll_interval <= 0:
        raise ValueError("poll_interval must be positive")
    directory.mkdir(parents=True, exist_ok=True)
    watcher = CaptureWatcher(directory.resolve())
    print(f"Watching {watcher.directory} for .pcap and .cap files (Ctrl+C to stop)")
    while True:
        watcher.poll_once()
        time.sleep(poll_interval)


def _startup_script_path() -> Path:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise OSError("APPDATA is not set; Windows Startup folder is unavailable")
    return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / STARTUP_ENTRY_NAME


def install_startup(watch_directory: Path, poll_interval: float) -> Path:
    if sys.platform != "win32":
        raise OSError("automatic login startup is supported only on Windows")
    startup_script = _startup_script_path()
    startup_script.parent.mkdir(parents=True, exist_ok=True)
    watch_directory.mkdir(parents=True, exist_ok=True)
    command = subprocess.list2cmdline([
        sys.executable,
        str(Path(__file__).resolve()),
        "--watch-dir",
        str(watch_directory.resolve()),
        "--poll-interval",
        str(poll_interval),
    ])
    vb_command = command.replace('"', '""')
    startup_script.write_text(
        'Option Explicit\n'
        'Dim shell, command\n'
        'Set shell = CreateObject("WScript.Shell")\n'
        f'command = "{vb_command}"\n'
        'shell.Run command, 1, False\n',
        encoding="utf-8",
    )
    return startup_script


def remove_startup() -> Path:
    if sys.platform != "win32":
        raise OSError("automatic login startup is supported only on Windows")
    startup_script = _startup_script_path()
    startup_script.unlink(missing_ok=True)
    return startup_script


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze a PCAP capture or continuously watch a folder for captures."
    )
    parser.add_argument(
        "pcap", type=Path, nargs="?",
        help="path to a classic Ethernet PCAP file (omit to watch a folder)",
    )
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument("--window", type=int, default=60, help="detection window in seconds")
    parser.add_argument(
        "--port-threshold", type=int, default=10,
        help="distinct destination ports required for a scan alert",
    )
    parser.add_argument(
        "--host-threshold", type=int, default=10,
        help="distinct destination hosts required for a scan alert",
    )
    parser.add_argument(
        "--syn-threshold", type=int, default=100,
        help="SYN packets required for a burst alert",
    )
    parser.add_argument(
        "--watch-dir", type=Path, default=DEFAULT_WATCH_DIR,
        help=f"folder to watch (default: {DEFAULT_WATCH_DIR})",
    )
    parser.add_argument(
        "--poll-interval", type=float, default=2,
        help="seconds between folder checks in watch mode",
    )
    startup = parser.add_mutually_exclusive_group()
    startup.add_argument(
        "--install-startup", action="store_true",
        help="start the folder watcher automatically when you sign in to Windows",
    )
    startup.add_argument(
        "--remove-startup", action="store_true",
        help="remove the automatic Windows login startup entry",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.json and (args.pcap is None or args.install_startup or args.remove_startup):
        parser.error("--json can only be used when analyzing a PCAP file")
    if args.pcap is not None and (args.install_startup or args.remove_startup):
        parser.error("startup options cannot be combined with a PCAP file")
    try:
        if args.install_startup:
            path = install_startup(args.watch_dir, args.poll_interval)
            print(f"Installed Windows login startup entry: {path}")
            print(f"Watching for captures in: {args.watch_dir.resolve()}")
            return 0
        if args.remove_startup:
            path = remove_startup()
            print(f"Removed Windows login startup entry: {path}")
            return 0
        if args.pcap is None:
            watch_captures(args.watch_dir, args.poll_interval)
            return 0

        detector = IntrusionDetector(
            window_seconds=args.window,
            port_scan_threshold=args.port_threshold,
            host_scan_threshold=args.host_threshold,
            syn_burst_threshold=args.syn_threshold,
        )
        with args.pcap.open("rb") as capture:
            analyze(capture, detector)
    except (OSError, PcapFormatError, ValueError) as error:
        print(f"ids: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({
            "capture": str(args.pcap),
            "packets_analyzed": detector.packet_count,
            "alerts": [asdict(alert) for alert in detector.alerts],
        }, indent=2))
    else:
        print(f"Analyzed {detector.packet_count} IPv4 packets")
        if not detector.alerts:
            print("No configured detection rules were triggered.")
        for alert in detector.alerts:
            print(
                f"[{alert.severity.upper()}] {alert.rule} from {alert.source} "
                f"at {alert.timestamp}: {alert.description}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())