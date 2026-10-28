"""Windows desktop controller for the Suricata network IDS."""

from __future__ import annotations

import argparse
import base64
import ctypes
import json
import os
import shutil
import subprocess
import sys
import threading
import webbrowser
from collections import Counter, deque
from datetime import datetime
from pathlib import Path
from time import time
from tkinter import (
    BOTH,
    END,
    LEFT,
    RIGHT,
    X,
    Button,
    Canvas,
    Entry,
    Frame,
    Label,
    StringVar,
    Tk,
    filedialog,
    messagebox,
    ttk,
)

APP_NAME = "Network IDS"
DATA_DIR = Path(os.environ.get("APPDATA", Path.home())) / "NetworkIDS"
SETTINGS_PATH = DATA_DIR / "settings.json"


def find_suricata() -> Path | None:
    candidates = [
        shutil.which("suricata"),
        r"C:\Program Files\Suricata\suricata.exe",
        r"C:\Program Files (x86)\Suricata\suricata.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return None


def find_config(executable: Path | None) -> Path | None:
    candidates = []
    if executable:
        candidates.extend([
            executable.parent / "suricata.yaml",
            executable.parent / "etc" / "suricata" / "suricata.yaml",
            executable.parent.parent / "etc" / "suricata" / "suricata.yaml",
        ])
    candidates.extend([
        Path(r"C:\Program Files\Suricata\suricata.yaml"),
        Path(r"C:\Program Files\Suricata\etc\suricata\suricata.yaml"),
        Path(r"C:\Program Files (x86)\Suricata\suricata.yaml"),
    ])
    return next((path for path in candidates if path.is_file()), None)


def find_rules_updater(executable: Path | None) -> Path | None:
    candidates = [shutil.which("suricata-update")]
    if executable:
        candidates.extend([
            executable.parent / "suricata-update.exe",
            executable.parent / "suricata-update",
            executable.parent / "suricata-update.bat",
        ])
    return next(
        (Path(candidate) for candidate in candidates if candidate and Path(candidate).is_file()),
        None,
    )


def _gui_executable() -> Path:
    windowless = Path(sys.executable).with_name("pythonw.exe")
    return windowless if windowless.is_file() else Path(sys.executable)


def _application_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable]
    script = Path(__file__).resolve()
    packaged = script.parent / "dist" / "NetworkIDS.exe"
    if packaged.is_file():
        return [str(packaged)]
    return [str(_gui_executable()), str(script)]


def find_npcap_library() -> Path | None:
    windows = Path(os.environ.get("WINDIR", r"C:\Windows"))
    candidates = [
        windows / "System32" / "Npcap" / "wpcap.dll",
        windows / "System32" / "wpcap.dll",
        windows / "SysWOW64" / "Npcap" / "wpcap.dll",
        windows / "SysWOW64" / "wpcap.dll",
    ]
    return next((path for path in candidates if path.is_file()), None)


class _PcapAddress(ctypes.Structure):
    pass


class _PcapInterface(ctypes.Structure):
    pass


_PcapAddress._fields_ = [
    ("next", ctypes.POINTER(_PcapAddress)),
    ("addr", ctypes.c_void_p),
    ("netmask", ctypes.c_void_p),
    ("broadaddr", ctypes.c_void_p),
    ("dstaddr", ctypes.c_void_p),
]
_PcapInterface._fields_ = [
    ("next", ctypes.POINTER(_PcapInterface)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.POINTER(_PcapAddress)),
    ("flags", ctypes.c_uint),
]


def list_capture_interfaces() -> list[tuple[str, str]]:
    """Return Npcap device IDs and descriptions using its public libpcap API."""
    library = find_npcap_library()
    if library is None:
        raise OSError("Npcap is not installed. Install it to enable live capture.")
    try:
        pcap = ctypes.WinDLL(str(library))
    except OSError as error:
        raise OSError(f"Could not load Npcap library {library}: {error}") from error

    pcap.pcap_findalldevs.argtypes = [
        ctypes.POINTER(ctypes.POINTER(_PcapInterface)),
        ctypes.c_char_p,
    ]
    pcap.pcap_findalldevs.restype = ctypes.c_int
    pcap.pcap_freealldevs.argtypes = [ctypes.POINTER(_PcapInterface)]
    devices = ctypes.POINTER(_PcapInterface)()
    error_buffer = ctypes.create_string_buffer(256)
    result = pcap.pcap_findalldevs(ctypes.byref(devices), error_buffer)
    if result != 0:
        message = error_buffer.value.decode("utf-8", errors="replace")
        raise OSError(f"Npcap could not enumerate interfaces: {message}")

    found = []
    try:
        current = devices
        while current:
            device = current.contents
            name = device.name.decode("utf-8", errors="replace") if device.name else ""
            description = (
                device.description.decode("utf-8", errors="replace")
                if device.description
                else name
            )
            if name:
                found.append((name, description))
            current = device.next
    finally:
        pcap.pcap_freealldevs(devices)
    return found


def _windows_startup_path() -> Path:
    if sys.platform != "win32":
        raise OSError("Windows startup integration is only available on Windows")
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise OSError("APPDATA is not set; Windows Startup folder is unavailable")
    return (
        Path(appdata)
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
        / "NetworkIDS.vbs"
    )


def install_startup_entry() -> Path:
    command = subprocess.list2cmdline(_application_command())
    startup_path = _windows_startup_path()
    startup_path.parent.mkdir(parents=True, exist_ok=True)
    startup_path.write_text(
        'Option Explicit\n'
        'Dim shell, command\n'
        'Set shell = CreateObject("WScript.Shell")\n'
        f'command = "{command.replace(chr(34), chr(34) * 2)}"\n'
        'shell.Run command, 1, False\n',
        encoding="utf-8",
    )
    return startup_path


def remove_startup_entry() -> Path:
    startup_path = _windows_startup_path()
    startup_path.unlink(missing_ok=True)
    return startup_path


def create_desktop_shortcut() -> Path:
    if sys.platform != "win32":
        raise OSError("Desktop shortcuts are only supported on Windows")
    desktop = Path.home() / "Desktop"
    desktop.mkdir(parents=True, exist_ok=True)
    shortcut = desktop / f"{APP_NAME}.lnk"
    app_command = _application_command()

    def ps_quote(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    powershell = (
        "$shell = New-Object -ComObject WScript.Shell; "
        f"$link = $shell.CreateShortcut({ps_quote(str(shortcut))}); "
        f"$link.TargetPath = {ps_quote(app_command[0])}; "
        f"$link.Arguments = {ps_quote(subprocess.list2cmdline(app_command[1:]))}; "
        f"$link.WorkingDirectory = {ps_quote(str(Path(app_command[0]).parent))}; "
        f"$link.IconLocation = {ps_quote(app_command[0])}; "
        "$link.Save()"
    )
    encoded = base64.b64encode(powershell.encode("utf-16le")).decode("ascii")
    subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return shortcut


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def parse_eve_alerts(data: str) -> tuple[list[tuple[str, str, str, str, str]], str]:
    """Parse EVE alert rows while retaining an unfinished trailing event."""
    alerts, _flows, pending = parse_eve_events(data)
    return alerts, pending


def _event_epoch(value: str) -> float:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (ValueError, OverflowError):
        return time()


def parse_eve_events(
    data: str,
) -> tuple[
    list[tuple[str, str, str, str, str]],
    list[dict[str, object]],
    str,
]:
    """Parse complete Suricata alert/flow events and retain an unfinished line."""
    lines = data.splitlines(keepends=True)
    pending = ""
    if lines and not lines[-1].endswith(("\n", "\r")):
        pending = lines.pop()
    alerts = []
    flows = []
    severity_names = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        event_type = event.get("event_type")
        if event_type == "alert":
            alert = event.get("alert") or {}
            if not isinstance(alert, dict):
                continue
            severity = alert.get("severity", "")
            severity = severity_names.get(severity, str(severity))
            source = f"{event.get('src_ip', '')}:{event.get('src_port', '')}".rstrip(":")
            destination = (
                f"{event.get('dest_ip', '')}:{event.get('dest_port', '')}".rstrip(":")
            )
            alerts.append((
                str(event.get("timestamp", "")),
                severity,
                str(alert.get("signature", "Suricata alert")),
                source,
                destination,
            ))
        elif event_type == "flow":
            flow_details = event.get("flow") or {}
            if not isinstance(flow_details, dict):
                flow_details = {}
            try:
                packet_count = max(
                    0,
                    int(flow_details.get("pkts_toserver", 0) or 0)
                    + int(flow_details.get("pkts_toclient", 0) or 0),
                )
                byte_count = max(
                    0,
                    int(flow_details.get("bytes_toserver", 0) or 0)
                    + int(flow_details.get("bytes_toclient", 0) or 0),
                )
            except (TypeError, ValueError, OverflowError):
                packet_count = byte_count = 0
            source = f"{event.get('src_ip', '')}:{event.get('src_port', '')}".rstrip(":")
            destination = (
                f"{event.get('dest_ip', '')}:{event.get('dest_port', '')}".rstrip(":")
            )
            timestamp = str(event.get("timestamp", ""))
            flows.append({
                "timestamp": timestamp,
                "epoch": _event_epoch(timestamp),
                "source": source,
                "destination": destination,
                "protocol": str(event.get("app_proto") or event.get("proto") or "unknown"),
                "packets": packet_count,
                "bytes": byte_count,
                "state": str(flow_details.get("state", "")),
            })
    return alerts, flows, pending


class TrafficStats:
    """Aggregate observed Suricata flow records for the live dashboard."""

    def __init__(self) -> None:
        self.flow_count = 0
        self.packet_count = 0
        self.byte_count = 0
        self.endpoint_bytes: Counter[str] = Counter()
        self.endpoints: set[str] = set()
        self.protocol_flows: Counter[str] = Counter()
        self.recent_flows: deque[dict[str, object]] = deque(maxlen=200)
        self.recent_bytes: deque[tuple[float, int]] = deque()

    def record(self, flow: dict[str, object]) -> None:
        source = str(flow["source"])
        destination = str(flow["destination"])
        byte_count = max(0, int(flow["bytes"]))
        packet_count = max(0, int(flow["packets"]))
        protocol = str(flow["protocol"])
        epoch = float(flow["epoch"])
        self.flow_count += 1
        self.packet_count += packet_count
        self.byte_count += byte_count
        self.endpoints.update((source, destination))
        self.endpoint_bytes[source] += byte_count
        self.endpoint_bytes[destination] += byte_count
        self.protocol_flows[protocol] += 1
        self.recent_flows.append(flow)
        self.recent_bytes.append((epoch, byte_count))
        self.prune(epoch)

    def prune(self, now: float) -> None:
        cutoff = now - 60
        while self.recent_bytes and self.recent_bytes[0][0] < cutoff:
            self.recent_bytes.popleft()


def _format_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1024 or unit == "TB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TB"


class NetworkIDSApp:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1200x850")
        self.root.minsize(900, 650)
        self.process: subprocess.Popen | None = None
        self.process_log = None
        self.eve_position = 0
        self.eve_pending = ""
        self.traffic_stats = TrafficStats()
        self.alert_count = 0
        self._settings = self._load_settings()
        self.suricata_var = StringVar(value=self._settings.get(
            "suricata", str(find_suricata() or "")
        ))
        self.config_var = StringVar(value=self._settings.get(
            "config", str(find_config(find_suricata()) or "")
        ))
        self.log_dir_var = StringVar(value=self._settings.get(
            "log_dir", str(DATA_DIR / "logs")
        ))
        self.interface_var = StringVar(value=self._settings.get("interface", ""))
        self.status_var = StringVar(value="Stopped")
        self._build_ui()
        self.refresh_interfaces(quiet=True)
        self.root.after(500, self._poll_engine)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    @staticmethod
    def _load_settings() -> dict[str, str]:
        try:
            value = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as error:
            messagebox.showwarning(APP_NAME, f"Could not load saved settings: {error}")
            return {}
        return value if isinstance(value, dict) else {}

    def _save_settings(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        settings = {
            "suricata": self.suricata_var.get().strip(),
            "config": self.config_var.get().strip(),
            "log_dir": self.log_dir_var.get().strip(),
            "interface": self.interface_var.get().strip(),
        }
        SETTINGS_PATH.write_text(json.dumps(settings, indent=2), encoding="utf-8")

    def _build_ui(self) -> None:
        heading = Frame(self.root, padx=14, pady=10)
        heading.pack(fill=X)
        Label(heading, text="Network IDS", font=("Segoe UI", 18, "bold")).pack(side=LEFT)
        Label(heading, textvariable=self.status_var, font=("Segoe UI", 10)).pack(side=RIGHT)

        setup = ttk.LabelFrame(self.root, text="Suricata configuration", padding=10)
        setup.pack(fill=X, padx=14, pady=(0, 10))
        self._path_row(setup, 0, "Suricata executable", self.suricata_var, self._browse_executable)
        self._path_row(setup, 1, "Suricata config", self.config_var, self._browse_config)
        self._path_row(setup, 2, "Log directory", self.log_dir_var, self._browse_log_dir)

        controls = Frame(self.root, padx=14)
        controls.pack(fill=X)
        Label(controls, text="Live capture interface").pack(side=LEFT)
        self.interface_combo = ttk.Combobox(
            controls, textvariable=self.interface_var, width=58
        )
        self.interface_combo.pack(side=LEFT, padx=(8, 6), fill=X, expand=True)
        Button(controls, text="Refresh", command=self.refresh_interfaces).pack(side=LEFT)
        self.start_button = Button(controls, text="Start IDS", command=self.start_monitoring)
        self.start_button.pack(side=LEFT, padx=(8, 0))
        self.stop_button = Button(
            controls, text="Stop IDS", command=self.stop_monitoring, state="disabled"
        )
        self.stop_button.pack(side=LEFT, padx=(6, 0))
        Button(controls, text="Update Rules", command=self.update_rules).pack(
            side=LEFT, padx=(6, 0)
        )

        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill=BOTH, expand=True, padx=14, pady=10)
        self._build_dashboard()

        alert_tab = Frame(self.tabs, padx=8, pady=8)
        columns = ("timestamp", "severity", "signature", "source", "destination")
        self.alerts = ttk.Treeview(alert_tab, columns=columns, show="headings", height=12)
        for column, title, width in (
            ("timestamp", "Time (UTC)", 180),
            ("severity", "Severity", 80),
            ("signature", "Rule / signature", 370),
            ("source", "Source", 135),
            ("destination", "Destination", 135),
        ):
            self.alerts.heading(column, text=title)
            self.alerts.column(column, width=width, minwidth=70, stretch=column == "signature")
        scrollbar = ttk.Scrollbar(alert_tab, orient="vertical", command=self.alerts.yview)
        self.alerts.configure(yscrollcommand=scrollbar.set)
        self.alerts.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill="y")
        self.tabs.add(alert_tab, text="Security alerts")

        footer = Frame(self.root, padx=14, pady=10)
        footer.pack(fill=X)
        Button(footer, text="Create Desktop Shortcut", command=self._make_shortcut).pack(side=LEFT)
        Button(footer, text="Start at Sign-in", command=self._enable_startup).pack(
            side=LEFT, padx=6
        )
        Button(footer, text="Remove Sign-in Start", command=self._disable_startup).pack(side=LEFT)
        Button(footer, text="Setup links", command=self._open_setup_links).pack(
            side=LEFT, padx=6
        )
        self.message_var = StringVar(
            value="Select a capture interface. Live capture requires Suricata, Npcap, and elevated permission."
        )
        Label(footer, textvariable=self.message_var, anchor="w", wraplength=670).pack(
            side=LEFT, padx=(12, 0), fill=X, expand=True
        )

    def _build_dashboard(self) -> None:
        dashboard = Frame(self.tabs, padx=10, pady=8)
        self.tabs.add(dashboard, text="Traffic dashboard")
        summary = Frame(dashboard)
        summary.pack(fill=X, pady=(0, 8))
        self.metric_vars = {
            "flows": StringVar(value="0"),
            "packets": StringVar(value="0"),
            "bytes": StringVar(value="0 B"),
            "endpoints": StringVar(value="0"),
        }
        for column, (key, title) in enumerate((
            ("flows", "Observed flows"),
            ("packets", "Packets in flows"),
            ("bytes", "Bytes in flows"),
            ("endpoints", "Device endpoints"),
        )):
            card = ttk.LabelFrame(summary, text=title, padding=(12, 6))
            card.grid(row=0, column=column, sticky="ew", padx=(0, 8))
            Label(card, textvariable=self.metric_vars[key], font=("Segoe UI", 18, "bold")).pack()
            summary.columnconfigure(column, weight=1)

        chart_frame = ttk.LabelFrame(
            dashboard,
            text="Flow volume · bytes reported per 5-second bucket · last 60 seconds",
            padding=6,
        )
        chart_frame.pack(fill=X, pady=(0, 8))
        self.traffic_chart = Canvas(
            chart_frame, height=150, background="white", highlightthickness=0
        )
        self.traffic_chart.pack(fill=X, expand=True)
        self.traffic_chart.bind("<Configure>", lambda _event: self._draw_traffic_chart())

        self.protocol_var = StringVar(value="Protocols: waiting for Suricata flow events")
        Label(dashboard, textvariable=self.protocol_var, anchor="w").pack(
            fill=X, pady=(0, 6)
        )
        tables = ttk.Panedwindow(dashboard, orient="horizontal")
        tables.pack(fill=BOTH, expand=True)

        recent_frame = ttk.LabelFrame(tables, text="Recent observed flows", padding=6)
        flow_columns = ("timestamp", "source", "destination", "protocol", "packets", "bytes")
        self.flows_table = ttk.Treeview(
            recent_frame, columns=flow_columns, show="headings", height=10
        )
        flow_headers = (
            ("timestamp", "Time (UTC)", 155),
            ("source", "Source device", 155),
            ("destination", "Destination device", 155),
            ("protocol", "Protocol", 85),
            ("packets", "Packets", 70),
            ("bytes", "Bytes", 80),
        )
        for column, title, width in flow_headers:
            self.flows_table.heading(column, text=title)
            self.flows_table.column(column, width=width, minwidth=60, stretch=True)
        flow_scroll = ttk.Scrollbar(
            recent_frame, orient="vertical", command=self.flows_table.yview
        )
        self.flows_table.configure(yscrollcommand=flow_scroll.set)
        self.flows_table.pack(side=LEFT, fill=BOTH, expand=True)
        flow_scroll.pack(side=RIGHT, fill="y")
        tables.add(recent_frame, weight=4)

        devices_frame = ttk.LabelFrame(tables, text="Endpoints by observed bytes", padding=6)
        self.devices_table = ttk.Treeview(
            devices_frame, columns=("endpoint", "bytes"), show="headings", height=10
        )
        self.devices_table.heading("endpoint", text="Device / IP endpoint")
        self.devices_table.heading("bytes", text="Flow bytes")
        self.devices_table.column("endpoint", width=170, minwidth=100, stretch=True)
        self.devices_table.column("bytes", width=100, minwidth=75, stretch=False)
        device_scroll = ttk.Scrollbar(
            devices_frame, orient="vertical", command=self.devices_table.yview
        )
        self.devices_table.configure(yscrollcommand=device_scroll.set)
        self.devices_table.pack(side=LEFT, fill=BOTH, expand=True)
        device_scroll.pack(side=RIGHT, fill="y")
        tables.add(devices_frame, weight=2)

    @staticmethod
    def _path_row(parent, row, label, variable, browse_command) -> None:
        Label(parent, text=label, anchor="w", width=22).grid(
            row=row, column=0, sticky="w", pady=3
        )
        Entry(parent, textvariable=variable).grid(
            row=row, column=1, sticky="ew", padx=6, pady=3
        )
        Button(parent, text="Browse", command=browse_command).grid(
            row=row, column=2, pady=3
        )
        parent.columnconfigure(1, weight=1)

    def _browse_executable(self) -> None:
        path = filedialog.askopenfilename(
            title="Select suricata.exe",
            filetypes=[("Suricata executable", "suricata.exe"), ("Executables", "*.exe")],
        )
        if path:
            self.suricata_var.set(path)
            config = find_config(Path(path))
            if config:
                self.config_var.set(str(config))

    def _browse_config(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Suricata configuration",
            filetypes=[("YAML configuration", "*.yaml *.yml"), ("All files", "*.*")],
        )
        if path:
            self.config_var.set(path)

    def _browse_log_dir(self) -> None:
        path = filedialog.askdirectory(title="Select Suricata log directory")
        if path:
            self.log_dir_var.set(path)

    def refresh_interfaces(self, quiet: bool = False) -> None:
        try:
            devices = list_capture_interfaces()
        except OSError as error:
            self.interface_combo["values"] = ()
            self.message_var.set(str(error))
            if not quiet:
                messagebox.showerror(APP_NAME, str(error))
            return
        self.interface_combo["values"] = [name for name, _description in devices]
        descriptions = {name: description for name, description in devices}
        if not self.interface_var.get() and devices:
            self.interface_var.set(devices[0][0])
        selected = self.interface_var.get()
        self.message_var.set(
            f"Selected: {descriptions.get(selected, selected)}. "
            "Capture is local to this computer; it does not monitor all internet traffic."
        )

    def start_monitoring(self) -> None:
        if self.process and self.process.poll() is None:
            return
        if not _is_admin():
            answer = messagebox.askyesno(
                APP_NAME,
                "Live packet capture usually needs Administrator permission. "
                "Restart the application with an elevation prompt?",
            )
            if answer:
                self._restart_as_admin()
            return

        executable = Path(self.suricata_var.get().strip())
        config = Path(self.config_var.get().strip())
        interface = self.interface_var.get().strip()
        log_dir = Path(self.log_dir_var.get().strip())
        if not executable.is_file():
            messagebox.showerror(APP_NAME, "Select a valid suricata.exe.")
            return
        if not config.is_file():
            messagebox.showerror(APP_NAME, "Select a valid suricata.yaml configuration.")
            return
        if not interface:
            messagebox.showerror(APP_NAME, "Select a live capture interface.")
            return

        self._save_settings()
        self.start_button.configure(state="disabled")
        self.status_var.set("Checking configuration…")
        threading.Thread(
            target=self._start_worker,
            args=(executable, config, interface, log_dir),
            daemon=True,
        ).start()

    def _start_worker(
        self, executable: Path, config: Path, interface: str, log_dir: Path
    ) -> None:
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            options = [
                str(executable), "-T", "-c", str(config),
                "--set", f"default-log-dir={log_dir}",
            ]
            check = subprocess.run(
                options, cwd=str(config.parent), capture_output=True,
                text=True, timeout=60, check=False,
            )
            if check.returncode:
                detail = (check.stderr or check.stdout).strip()
                raise RuntimeError(f"Suricata configuration test failed:\n{detail}")

            log_stream = (log_dir / "suricata-console.log").open("a", encoding="utf-8")
            command = [
                str(executable), "-c", str(config), "-i", interface,
                "--set", f"default-log-dir={log_dir}",
            ]
            process = subprocess.Popen(
                command,
                cwd=str(config.parent),
                stdout=log_stream,
                stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            self.root.after(
                0, lambda: self._engine_started(process, log_stream, log_dir)
            )
        except (OSError, subprocess.SubprocessError, RuntimeError) as error:
            self.root.after(0, lambda message=str(error): self._start_failed(message))

    def _engine_started(self, process, log_stream, log_dir: Path) -> None:
        self.process = process
        self.process_log = log_stream
        self.eve_path = log_dir / "eve.json"
        try:
            self.eve_position = self.eve_path.stat().st_size
        except OSError:
            self.eve_position = 0
        self.eve_pending = ""
        self.traffic_stats = TrafficStats()
        self.alert_count = 0
        for table in (self.alerts, self.flows_table, self.devices_table):
            for item in table.get_children():
                table.delete(item)
        self._refresh_dashboard()
        if process.poll() is not None:
            self._engine_stopped()
            self.message_var.set(
                f"Suricata exited ({process.returncode}). See {log_dir / 'suricata-console.log'}"
            )
            return
        self.status_var.set("Running")
        self.message_var.set(
            f"Suricata is running. Traffic dashboard and alerts are reading {self.eve_path}"
        )
        self.stop_button.configure(state="normal")

    def _start_failed(self, message: str) -> None:
        self.start_button.configure(state="normal")
        self.status_var.set("Stopped")
        self.message_var.set(message)
        messagebox.showerror(APP_NAME, message)

    def _poll_engine(self) -> None:
        if self.process:
            if self.process.poll() is not None:
                code = self.process.returncode
                self._engine_stopped()
                self.status_var.set(f"Stopped (exit code {code})")
            else:
                self._read_alerts()
        self.root.after(500, self._poll_engine)

    def _read_alerts(self) -> None:
        path = getattr(self, "eve_path", None)
        if path is None or not path.is_file():
            return
        try:
            size = path.stat().st_size
            if size < self.eve_position:
                self.eve_position = 0
                self.eve_pending = ""
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                stream.seek(self.eve_position)
                data = self.eve_pending + stream.read()
                self.eve_position = stream.tell()
        except OSError as error:
            self.message_var.set(f"Could not read alert log: {error}")
            return

        alerts, flows, self.eve_pending = parse_eve_events(data)
        for entry in alerts:
            self.alerts.insert(
                "",
                0,
                values=entry,
            )
            self.alert_count += 1
            children = self.alerts.get_children()
            for old_item in children[500:]:
                self.alerts.delete(old_item)
        if flows:
            for flow in flows:
                self.traffic_stats.record(flow)
            self._refresh_dashboard()

    def _refresh_dashboard(self) -> None:
        stats = self.traffic_stats
        self.metric_vars["flows"].set(f"{stats.flow_count:,}")
        self.metric_vars["packets"].set(f"{stats.packet_count:,}")
        self.metric_vars["bytes"].set(_format_bytes(stats.byte_count))
        self.metric_vars["endpoints"].set(f"{len(stats.endpoints):,}")

        for item in self.flows_table.get_children():
            self.flows_table.delete(item)
        if stats.recent_flows:
            for flow in stats.recent_flows:
                self.flows_table.insert(
                    "",
                    0,
                    values=(
                        flow["timestamp"],
                        flow["source"],
                        flow["destination"],
                        flow["protocol"],
                        f"{flow['packets']:,}",
                        _format_bytes(int(flow["bytes"])),
                    ),
                )
        else:
            self.flows_table.insert(
                "", END, values=("Waiting for EVE flow events", "", "", "", "", "")
            )

        for item in self.devices_table.get_children():
            self.devices_table.delete(item)
        if stats.endpoint_bytes:
            for endpoint, byte_count in stats.endpoint_bytes.most_common(15):
                self.devices_table.insert(
                    "", END, values=(endpoint, _format_bytes(byte_count))
                )
        else:
            self.devices_table.insert(
                "", END, values=("Waiting for EVE flow events", "")
            )

        if stats.protocol_flows:
            protocols = "  |  ".join(
                f"{protocol}: {count:,}"
                for protocol, count in stats.protocol_flows.most_common(8)
            )
            self.protocol_var.set(f"Flows by protocol: {protocols}")
        else:
            self.protocol_var.set(
                "Flows by protocol: waiting for EVE flow events "
                "(ensure flow logging is enabled in Suricata's EVE configuration)"
            )
        self._draw_traffic_chart()

    def _draw_traffic_chart(self) -> None:
        if not hasattr(self, "traffic_chart"):
            return
        canvas = self.traffic_chart
        canvas.delete("all")
        width = max(canvas.winfo_width(), 320)
        height = max(canvas.winfo_height(), 100)
        left, right, top, bottom = 52, width - 12, 12, height - 23
        chart_width = max(right - left, 1)
        chart_height = max(bottom - top, 1)
        now = time()
        self.traffic_stats.prune(now)
        bucket_bytes = [0] * 12
        for epoch, byte_count in self.traffic_stats.recent_bytes:
            age = now - epoch
            if 0 <= age < 60:
                index = 11 - min(11, int(age / 5))
                bucket_bytes[index] += byte_count
        maximum = max(bucket_bytes, default=0)

        canvas.create_text(
            4, top, text=_format_bytes(maximum), anchor="nw", fill="#566273"
        )
        canvas.create_line(left, top, left, bottom, fill="#aeb8c2")
        canvas.create_line(left, bottom, right, bottom, fill="#aeb8c2")
        gap = 4
        bar_width = max((chart_width - gap * 11) / 12, 1)
        for index, value in enumerate(bucket_bytes):
            x1 = left + index * (bar_width + gap)
            bar_height = chart_height * value / maximum if maximum else 0
            if bar_height:
                canvas.create_rectangle(
                    x1,
                    bottom - bar_height,
                    x1 + bar_width,
                    bottom,
                    fill="#2276c9",
                    outline="",
                )
        canvas.create_text(left, height - 4, text="60s ago", anchor="sw", fill="#566273")
        canvas.create_text(right, height - 4, text="now", anchor="se", fill="#566273")
        if maximum == 0:
            canvas.create_text(
                (left + right) / 2,
                (top + bottom) / 2,
                text="No flow bytes reported in the last 60 seconds",
                fill="#566273",
            )

    def update_rules(self) -> None:
        executable = Path(self.suricata_var.get().strip())
        updater = find_rules_updater(executable)
        if updater is None:
            messagebox.showerror(
                APP_NAME,
                "suricata-update was not found. Install the updater or configure it "
                "with your Suricata installation before updating rules.",
            )
            return
        self.message_var.set("Updating Suricata rules from configured rule sources…")
        threading.Thread(
            target=self._update_rules_worker, args=(updater,), daemon=True
        ).start()

    def _update_rules_worker(self, updater: Path) -> None:
        try:
            result = subprocess.run(
                [str(updater)], capture_output=True, text=True,
                timeout=600, check=False,
            )
            if result.returncode:
                details = (result.stderr or result.stdout).strip()
                raise RuntimeError(details or f"updater exited with code {result.returncode}")
            output = (result.stdout or "Rules updated successfully.").strip()
            self.root.after(0, lambda: self._rules_updated(output))
        except (OSError, subprocess.SubprocessError, RuntimeError) as error:
            self.root.after(0, lambda message=str(error): self._rules_update_failed(message))

    def _rules_updated(self, output: str) -> None:
        self.message_var.set(
            "Rules updated. Stop and restart live monitoring to load the new rules."
            if self.process and self.process.poll() is None
            else "Rules updated successfully."
        )
        messagebox.showinfo(APP_NAME, output[-3000:])

    def _rules_update_failed(self, message: str) -> None:
        self.message_var.set(f"Rule update failed: {message}")
        messagebox.showerror(APP_NAME, f"Could not update Suricata rules:\n{message}")

    def stop_monitoring(self) -> None:
        process = self.process
        if not process or process.poll() is not None:
            self._engine_stopped()
            return
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        self._engine_stopped()
        self.status_var.set("Stopped")
        self.message_var.set("Suricata monitoring stopped.")

    def _engine_stopped(self) -> None:
        self.process = None
        if self.process_log:
            self.process_log.close()
            self.process_log = None
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")

    def _restart_as_admin(self) -> None:
        command = _application_command()
        executable = command[0]
        arguments = subprocess.list2cmdline(command[1:])
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable, arguments, str(Path(executable).parent), 1
        )
        if result <= 32:
            messagebox.showerror(APP_NAME, "Windows could not start the elevated application.")
        else:
            self.root.destroy()

    def _make_shortcut(self) -> None:
        try:
            shortcut = create_desktop_shortcut()
        except (OSError, subprocess.SubprocessError) as error:
            messagebox.showerror(APP_NAME, f"Could not create Desktop shortcut: {error}")
        else:
            messagebox.showinfo(APP_NAME, f"Desktop shortcut created:\n{shortcut}")

    def _enable_startup(self) -> None:
        try:
            path = install_startup_entry()
        except OSError as error:
            messagebox.showerror(APP_NAME, str(error))
        else:
            messagebox.showinfo(APP_NAME, f"Network IDS will open at sign-in:\n{path}")

    def _disable_startup(self) -> None:
        try:
            path = remove_startup_entry()
        except OSError as error:
            messagebox.showerror(APP_NAME, str(error))
        else:
            messagebox.showinfo(APP_NAME, f"Removed startup entry:\n{path}")

    @staticmethod
    def _open_setup_links() -> None:
        webbrowser.open("https://suricata.io/download/")
        webbrowser.open("https://npcap.com/")

    def close(self) -> None:
        if self.process and self.process.poll() is None:
            if not messagebox.askyesno(APP_NAME, "Stop Suricata and exit?"):
                return
            self.stop_monitoring()
        self.root.destroy()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Suricata Windows desktop controller")
    parser.add_argument("--make-shortcut", action="store_true")
    parser.add_argument("--install-startup", action="store_true")
    parser.add_argument("--remove-startup", action="store_true")
    parser.add_argument("--check", action="store_true", help="print detected IDS components")
    args = parser.parse_args(argv)
    if sum((args.make_shortcut, args.install_startup, args.remove_startup, args.check)) > 1:
        parser.error("choose only one setup or check option")

    try:
        if args.make_shortcut:
            print(create_desktop_shortcut())
            return 0
        if args.install_startup:
            print(install_startup_entry())
            return 0
        if args.remove_startup:
            print(remove_startup_entry())
            return 0
        if args.check:
            print(f"Suricata: {find_suricata() or 'not installed'}")
            print(f"Npcap: {find_npcap_library() or 'not installed'}")
            print(f"Capture interfaces: {len(list_capture_interfaces()) if find_npcap_library() else 0}")
            return 0
    except (OSError, subprocess.SubprocessError) as error:
        print(f"{APP_NAME}: {error}", file=sys.stderr)
        return 2

    root = Tk()
    NetworkIDSApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
