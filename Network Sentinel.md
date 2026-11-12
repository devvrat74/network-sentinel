# Network Sentinel

A beginner-friendly, consent-based Python cybersecurity utility for:
- TCP port reachability checks on explicitly authorized systems.
- Detecting repeated failed-login events in a local authentication log.
- Recording scan and analysis activity to a timestamped log.

## Requirements
- Python 3.9+
- `colorama`

## Setup
```bash
python -m venv .venv
# Windows:
.venv\\Scripts\\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
```

## Run
```bash
python network_sentinel.py
```

## Safe testing
Use `127.0.0.1` (localhost) or a lab machine you own. Try ports such as `22,80,443`.
The scanner uses normal TCP connection attempts; it is not a stealth scanner.
The demo `auth_events.log` is created automatically if missing. You may add records
using this format: `YYYY-MM-DD HH:MM:SS,username,source_ip,FAILED|SUCCESS`.

## Files
- `network_sentinel.py` - application source.
- `auth_events.log` - sample authentication events.
- `sentinel_activity.log` - generated activity log.
- `requirements.txt` - external dependency.

## Limitations
A closed TCP port and a filtered port may look identical from a client-side
connection test. This is a learning project, not a replacement for an enterprise
vulnerability scanner, SIEM, endpoint protection, or professional penetration test.
