import unittest

import app


class EveAlertTests(unittest.TestCase):
    def test_parses_alert_and_maps_suricata_severity(self):
        event = (
            '{"event_type":"alert","timestamp":"2026-10-28T10:00:00Z",'
            '"src_ip":"192.0.2.1","src_port":1234,"dest_ip":"198.51.100.2",'
            '"dest_port":443,"alert":{"severity":1,"signature":"Example rule"}}\n'
        )
        entries, pending = app.parse_eve_alerts(event)
        self.assertEqual(pending, "")
        self.assertEqual(entries, [(
            "2026-10-28T10:00:00Z",
            "HIGH",
            "Example rule",
            "192.0.2.1:1234",
            "198.51.100.2:443",
        )])

    def test_keeps_partial_event_until_next_read(self):
        partial = '{"event_type":"alert","alert":{"signature":"Example'
        entries, pending = app.parse_eve_alerts(partial)
        self.assertEqual(entries, [])
        self.assertEqual(pending, partial)
        completed, remainder = app.parse_eve_alerts(
            pending + ' rule","severity":2}}\n'
        )
        self.assertEqual(remainder, "")
        self.assertEqual(completed[0][1:3], ("MEDIUM", "Example rule"))

    def test_ignores_non_alert_eve_events(self):
        event = '{"event_type":"flow","src_ip":"192.0.2.1"}\n'
        self.assertEqual(app.parse_eve_alerts(event), ([], ""))

    def test_parses_flow_endpoints_protocol_packets_and_bytes(self):
        event = (
            '{"event_type":"flow","timestamp":"2026-10-28T10:00:00Z",'
            '"src_ip":"192.0.2.1","src_port":1234,"dest_ip":"198.51.100.2",'
            '"dest_port":443,"proto":"TCP","app_proto":"tls",'
            '"flow":{"pkts_toserver":4,"pkts_toclient":6,'
            '"bytes_toserver":400,"bytes_toclient":900,"state":"established"}}\n'
        )
        alerts, flows, pending = app.parse_eve_events(event)
        self.assertEqual(alerts, [])
        self.assertEqual(pending, "")
        self.assertEqual(flows[0]["source"], "192.0.2.1:1234")
        self.assertEqual(flows[0]["destination"], "198.51.100.2:443")
        self.assertEqual(flows[0]["protocol"], "tls")
        self.assertEqual(flows[0]["packets"], 10)
        self.assertEqual(flows[0]["bytes"], 1300)
        self.assertEqual(flows[0]["state"], "established")

    def test_retains_partial_flow_event(self):
        partial = '{"event_type":"flow","flow":{"bytes_toserver":10'
        alerts, flows, pending = app.parse_eve_events(partial)
        self.assertEqual((alerts, flows, pending), ([], [], partial))
        _, completed, remainder = app.parse_eve_events(
            pending + ',"pkts_toserver":1}}\n'
        )
        self.assertEqual(remainder, "")
        self.assertEqual(completed[0]["bytes"], 10)
        self.assertEqual(completed[0]["packets"], 1)

    def test_traffic_stats_aggregate_flow_bytes_and_endpoints(self):
        stats = app.TrafficStats()
        stats.record({
            "timestamp": "now",
            "epoch": 100.0,
            "source": "192.0.2.1:1234",
            "destination": "198.51.100.2:443",
            "protocol": "tls",
            "packets": 10,
            "bytes": 1300,
        })
        stats.record({
            "timestamp": "now",
            "epoch": 101.0,
            "source": "192.0.2.1:1234",
            "destination": "198.51.100.3:53",
            "protocol": "dns",
            "packets": 2,
            "bytes": 120,
        })
        self.assertEqual(stats.flow_count, 2)
        self.assertEqual(stats.packet_count, 12)
        self.assertEqual(stats.byte_count, 1420)
        self.assertEqual(len(stats.endpoints), 3)
        self.assertEqual(stats.endpoint_bytes["192.0.2.1:1234"], 1420)
        self.assertEqual(stats.protocol_flows.most_common(), [("tls", 1), ("dns", 1)])


if __name__ == "__main__":
    unittest.main()
