import io
import json
import struct
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import ids


def ethernet_tcp(src, dst, src_port, dst_port, flags=0x02):
    tcp = struct.pack("!HHIIHHHH", src_port, dst_port, 0, 0, 5 << 12 | flags, 4096, 0, 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
        bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))),
    )
    return b"\x00" * 12 + struct.pack("!H", 0x0800) + ip + tcp


def make_pcap(packets, *, endian="<", magic=b"\xd4\xc3\xb2\xa1"):
    global_header = magic + struct.pack(endian + "HHiIII", 2, 4, 0, 0, 65535, 1)
    records = bytearray()
    for timestamp, frame in packets:
        records.extend(struct.pack(endian + "IIII", timestamp, 0, len(frame), len(frame)))
        records.extend(frame)
    return io.BytesIO(global_header + records)


class PcapParserTests(unittest.TestCase):
    def test_reads_little_and_big_endian_pcap(self):
        frame = ethernet_tcp("10.0.0.1", "10.0.0.2", 50000, 443)
        cases = (
            ("<", b"\xd4\xc3\xb2\xa1"),
            (">", b"\xa1\xb2\xc3\xd4"),
        )
        for endian, magic in cases:
            with self.subTest(endian=endian):
                packet = next(ids.iter_pcap(make_pcap([(12, frame)], endian=endian, magic=magic)))
                self.assertEqual((packet.src, packet.dst, packet.dst_port), ("10.0.0.1", "10.0.0.2", 443))
                self.assertEqual(packet.tcp_flags, 0x02)

    def test_detects_port_scan_and_ignores_syn_ack(self):
        frames = [
            ethernet_tcp("192.0.2.1", "198.51.100.1", 40000, port)
            for port in range(20, 25)
        ]
        frames.append(ethernet_tcp("192.0.2.1", "198.51.100.1", 40000, 25, 0x12))
        detector = ids.IntrusionDetector(port_scan_threshold=5)
        for packet in ids.iter_pcap(make_pcap([(100 + i, frame) for i, frame in enumerate(frames)])):
            detector.process(packet)
        self.assertEqual([alert.rule for alert in detector.alerts], ["TCP_SYN_PORT_SCAN"])

    def test_detects_host_scan_and_syn_burst(self):
        frames = [
            ethernet_tcp("192.0.2.2", f"198.51.100.{i}", 40000, 443)
            for i in range(1, 4)
        ]
        detector = ids.IntrusionDetector(
            host_scan_threshold=3, port_scan_threshold=50, syn_burst_threshold=3
        )
        for packet in ids.iter_pcap(make_pcap([(200, frame) for frame in frames])):
            detector.process(packet)
        self.assertEqual(
            {alert.rule for alert in detector.alerts},
            {"TCP_SYN_HOST_SCAN", "TCP_SYN_BURST"},
        )

    def test_rejects_truncated_capture(self):
        with self.assertRaisesRegex(ids.PcapFormatError, "Truncated PCAP global header"):
            list(ids.iter_pcap(io.BytesIO(b"short")))

    def test_cli_prints_json(self):
        frame = ethernet_tcp("192.0.2.1", "198.51.100.1", 40000, 443)
        with tempfile.TemporaryDirectory() as directory:
            capture_path = Path(directory) / "sample.pcap"
            capture_path.write_bytes(make_pcap([(1, frame)]).getvalue())
            output = io.StringIO()
            with redirect_stdout(output):
                result = ids.main([str(capture_path), "--json"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["packets_analyzed"], 1)

    def test_watcher_processes_only_stable_files_once(self):
        frame = ethernet_tcp("192.0.2.1", "198.51.100.1", 40000, 443)
        with tempfile.TemporaryDirectory() as directory:
            capture_path = Path(directory) / "sample.pcap"
            capture_path.write_bytes(make_pcap([(1, frame)]).getvalue())
            watcher = ids.CaptureWatcher(Path(directory))
            output = io.StringIO()
            with redirect_stdout(output):
                watcher.poll_once()
                self.assertEqual(output.getvalue(), "")
                watcher.poll_once()
                watcher.poll_once()
            self.assertEqual(output.getvalue().count("Analyzed 1 IPv4 packets"), 1)

    def test_watcher_reprocesses_file_after_it_changes(self):
        frame = ethernet_tcp("192.0.2.1", "198.51.100.1", 40000, 443)
        with tempfile.TemporaryDirectory() as directory:
            capture_path = Path(directory) / "sample.pcap"
            capture_path.write_bytes(make_pcap([(1, frame)]).getvalue())
            watcher = ids.CaptureWatcher(Path(directory))
            output = io.StringIO()
            with redirect_stdout(output):
                watcher.poll_once()
                watcher.poll_once()
                capture_path.write_bytes(make_pcap([(1, frame), (2, frame)]).getvalue())
                with patch("ids.time.sleep", return_value=None):
                    watcher.poll_once()
                    watcher.poll_once()
            self.assertEqual(output.getvalue().count("Analyzed"), 2)

    def test_cli_runs_watcher_when_capture_path_is_omitted(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("ids.watch_captures") as watch:
                self.assertEqual(ids.main(["--watch-dir", directory]), 0)
            watch.assert_called_once_with(Path(directory), 2)


if __name__ == "__main__":
    unittest.main()