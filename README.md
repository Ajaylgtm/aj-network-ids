# Network IDS for Windows

The desktop application in `app.py` provides a Windows interface for running
the Suricata intrusion detection engine against a live network interface. It
shows Suricata alerts from EVE JSON and includes controls for selecting the
engine, configuration, interface, and log folder. Suricata supplies the
protocol analysis and rule-based detection; the application is a local
controller, not a replacement detection engine.

## Requirements

Windows, Python 3.10 or later with Tkinter, Suricata, and Npcap. Live capture
normally requires Administrator permission. The app asks before relaunching
elevated. Only monitor systems and traffic you are authorized to inspect.

## Build the Windows application

On Windows with Python installed, run `build_windows.bat`. It installs the
PyInstaller build tool, runs the test suite, and creates:

```text
dist\NetworkIDS.exe
```

The executable bundles the Python desktop UI, but **does not bundle Suricata or
Npcap**. Install those separately using their official installers; live traffic
capture needs Npcap and normally administrator permission. The app's Desktop
shortcut and sign-in startup actions use the packaged executable when it is
present.

The repository also includes a GitHub Actions workflow that tests the project,
builds the Windows executable, and publishes it as a downloadable workflow
artifact on each push or pull request. Open the successful workflow run on
GitHub and download the `NetworkIDS-Windows` artifact.

## Start the application

```powershell
python app.py
```

After building, double-click `dist\NetworkIDS.exe` to use the packaged app.

In the app, select `suricata.exe`, its `suricata.yaml`, a capture interface,
and a log folder, then click **Start IDS**. The app first tests the Suricata
configuration and then starts live capture. The **Traffic dashboard** shows
the flow records Suricata reports: source/destination endpoints, protocol,
packet and byte totals, recent flows, and flow volume over time. **Security
alerts** shows rule matches. Suricata rules and alert behavior are controlled
by the selected configuration and its installed ruleset.
Click **Update Rules** to run the installed `suricata-update` tool; updated
rules are loaded the next time Suricata is started.

Dashboard traffic is based on Suricata EVE `flow` events. Enable EVE JSON flow
logging in the selected Suricata configuration for the dashboard to populate.
Suricata may emit flow records when flows close, so these are observed flow
totals and not guaranteed packet-by-packet or instantaneous bandwidth
measurements. The dashboard can only report traffic visible on the selected
capture interface; a typical computer cannot see unrelated traffic between
other devices without network-level capture such as a configured mirror port.

```powershell
python app.py --make-shortcut
```

The app also has a **Create Desktop Shortcut** button. To launch the app
automatically at Windows sign-in, click **Start at Sign-in** (or run
`python app.py --install-startup`). This starts the application UI; click
**Start IDS** to begin live monitoring. Remove automatic startup from the app
or run `python app.py --remove-startup`.

```powershell
python app.py --check
```

`--check` reports whether Suricata and Npcap are found. Suricata can be
installed using the official Windows installer at
[suricata.io/download](https://suricata.io/download/) or, where available:

```powershell
winget install --id OISF.Suricata --exact
```

Npcap is a separate driver required for Windows live capture. Install it from
[npcap.com](https://npcap.com/), then restart the app. Follow the installer
prompts and license terms. A live interface is not necessarily the same as
seeing all traffic on the network: a normal PC typically sees traffic sent to
or from itself.

## PCAP analysis utility

```powershell
python ids.py .\capture.pcap
python ids.py .\capture.pcap --json
```

`ids.py` remains a small offline PCAP analyzer and folder watcher. It is
independent of Suricata and is not the live IDS engine.

## Test

```powershell
python -m unittest discover -s tests -v
python -m py_compile app.py ids.py
```