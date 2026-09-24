# Network Log Analyzer — Prototype

A Flask + SQLite + Pandas + scikit-learn prototype for a network log
anomaly-detection / threat-classification / incident-response workflow.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python model/train_model.py     # trains the Isolation Forest on data/sample_logs.csv
python app.py
```

Then open http://localhost:5000

Demo logins (optional — you can also skip login from the login page):
- `admin` / `admin123`
- `analyst` / `analyst123`

## Demo flow

1. **Upload Logs** — upload `data/sample_logs.csv` (or your own CSV with the
   required columns, or a `.log`/`.txt` file in the format:
   `2026-07-11 10:32:00 TCP 192.168.1.5:51515 -> 8.8.8.8:53 bytes=450 packets=5 event=DNS Query severity=Low`)
2. **Log Viewer** — see parsed logs, filter by IP/protocol/severity/status.
3. Click **Run Detection** — runs the Isolation Forest model, tags each log
   Normal/Suspicious, then applies rule-based threat classification to the
   suspicious ones.
4. **Detection Results** — table of predictions with anomaly/risk scores.
5. Click into any row → **Incident Details** — full incident context plus
   suggested response actions.
6. **Dashboard** — summary cards + charts (timeline, attack types, protocol
   mix, severity, top attacking IPs).
7. **Reports** — export all logs or suspicious-only logs as CSV.

## Notes on scope

This is a semester-project prototype, not a production security tool:
- Anomaly detection uses Isolation Forest on 6 basic numeric features —
  good enough to demonstrate the workflow, not tuned for real traffic.
- Threat classification is rule-based (port scan / DDoS / brute force /
  malware C2 / data exfiltration / unknown), not a trained classifier.
- Login is a simple hardcoded two-user demo, not production auth.
- Reports are CSV only (add `reportlab`/`weasyprint` later for PDF).

## Project structure

```
network-log-analyzer/
├── app.py                  # Flask routes
├── config.py               # paths, demo users, constants
├── requirements.txt
├── model/
│   ├── anomaly_model.pkl   # trained Isolation Forest (generated)
│   └── train_model.py      # standalone training script
├── data/
│   └── sample_logs.csv     # sample dataset for training + demo upload
├── instance/                # SQLite DB + uploaded files (created at runtime)
├── templates/               # Jinja2 + Bootstrap pages
├── static/                  # CSS + Chart.js
└── utils/
    ├── parser.py            # CSV / freeform log parsing & normalization
    ├── detector.py           # feature engineering + Isolation Forest
    ├── classifier.py         # rule-based threat classification
    ├── response_engine.py    # threat type -> recommended actions
    └── db.py                 # SQLite access layer
```
