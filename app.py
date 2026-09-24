from scipy.stats import _sensitivity_analysis
import os
import io
import csv
import uuid
from utils.agents.orchestrator import security_orchestrator
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, jsonify
)
from werkzeug.utils import secure_filename

from config import Config
from utils import db
from utils.parser import parse_csv, parse_freeform, LogParseError
from utils.detector import preprocess, predict_anomalies, score_to_status, compute_risk_score, load_model
from utils.classifier import classify_threat, build_batch_aggregates, generate_description
from utils.response_engine import get_response_actions

app = Flask(__name__)
app.config.from_object(Config)

os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
db.init_db()

# Ensure a model exists on startup so /detect always has something to load.
try:
    load_model()
except Exception:
    pass


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in Config.ALLOWED_EXTENSIONS


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------- routes ---

@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = Config.DEMO_USERS.get(username)
        if user and user["password"] == password:
            session["username"] = username
            session["role"] = user["role"]
            flash(f"Welcome, {username}!", "success")
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    stats = db.get_stats()
    return render_template("dashboard.html", stats=stats)


@app.route("/upload", methods=["GET", "POST"])
def upload_logs():
    if request.method == "POST":
        if "logfile" not in request.files:
            flash("No file part in the request.", "danger")
            return redirect(request.url)

        file = request.files["logfile"]
        if file.filename == "":
            flash("No file selected.", "danger")
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash("Unsupported file type. Please upload .csv, .log, or .txt.", "danger")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        extension = filename.rsplit(".", 1)[1].lower()
        saved_path = os.path.join(Config.UPLOAD_FOLDER, f"{uuid.uuid4().hex}_{filename}")
        file.save(saved_path)
        filesize = os.path.getsize(saved_path)

        try:
            if extension == "csv":
                df = parse_csv(saved_path)
            else:
                with open(saved_path, "r", errors="ignore") as f:
                    df = parse_freeform(f.read())
        except LogParseError as e:
            flash(f"Failed to parse file: {e}", "danger")
            return redirect(request.url)
        except Exception as e:
            flash(f"Unexpected error while parsing: {e}", "danger")
            return redirect(request.url)

        batch_id = uuid.uuid4().hex[:12]
        # Add placeholder analysis columns (filled in by /detect)
        for col in ["status", "anomaly_score", "threat_type", "risk_score", "description"]:
            df[col] = None
        df["batch_id"] = batch_id

        db.insert_logs(df, batch_id)
        db.record_upload(
            batch_id=batch_id,
            filename=filename,
            filesize=filesize,
            upload_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            rows_parsed=len(df),
        )

        flash(f"Uploaded '{filename}' — {len(df)} log rows parsed successfully.", "success")
        return redirect(url_for("view_logs", batch_id=batch_id))

    return render_template("upload.html")


@app.route("/logs")
def view_logs():
    filters = {
        "source_ip": request.args.get("source_ip", "").strip(),
        "protocol": request.args.get("protocol", "").strip(),
        "severity": request.args.get("severity", "").strip(),
        "status": request.args.get("status", "").strip(),
        "threat_type": request.args.get("threat_type", "").strip(),
    }
    logs = db.fetch_logs(filters=filters, limit=1000)
    return render_template("logs.html", logs=logs, filters=filters)


@app.route("/detect")
def detect_anomalies():
    batch_id = request.args.get("batch_id")

    rows = db.fetch_unanalyzed_logs(batch_id=batch_id)
    if not rows:
        flash("No new logs to analyze. Upload a file first.", "info")
        return redirect(url_for("view_logs"))

    import pandas as pd
    df = pd.DataFrame([dict(r) for r in rows])
    df, features = preprocess(df)

    preds, scores = predict_anomalies(features)
    df["_pred"] = preds
    df["_score"] = scores

    port_scan_counts, ddos_counts, bruteforce_counts = build_batch_aggregates(df)
    analyzed = 0
    suspicious = 0
    update_results = []

    for _, row in df.iterrows():

        row_dict = row.to_dict()

        analysis = security_orchestrator.analyze_log(
            row=row_dict,
            anomaly_prediction=row["_pred"],
            anomaly_score=row["_score"],
            port_scan_counts=port_scan_counts,
            ddos_counts=ddos_counts,
            bruteforce_counts=bruteforce_counts,
        )

        status = analysis["status"]

        threat_type = (
            analysis["threat_type"]
            if status == "Suspicious"
            else None
        )

        risk_score = int(30 + (abs(float(analysis["anomaly_score"])) * 500)) if status == "Suspicious" else 0
        risk_score = min(100, risk_score)

        description = (
            analysis["explanation"]
            if status == "Suspicious"
            else None
        )

        if status == "Suspicious":
            suspicious += 1

        update_results.append(
            (
                status,
                float(analysis["anomaly_score"]),
                threat_type,
                risk_score,
                description,
                int(row["id"]),
            )
        )

        analyzed += 1

    # Update all logs in one database transaction
    db.update_log_analysis_batch(update_results)
    # Update all logs in one database transaction
    db.update_log_analysis_batch(update_results)
    flash(f"Analyzed {analyzed} logs — {suspicious} flagged as suspicious.", "success")
    return redirect(url_for("detection_results"))


@app.route("/results")
def detection_results():
    conn = db.get_connection()
    rows = conn.execute(
        "SELECT id, source_ip, protocol, status, anomaly_score, risk_score, threat_type "
        "FROM logs WHERE status IS NOT NULL ORDER BY id DESC LIMIT 500"
    ).fetchall()
    conn.close()
    return render_template("results.html", rows=rows)


@app.route("/incident/<int:log_id>")
def incident_details(log_id):
    log = db.fetch_log_by_id(log_id)
    if log is None:
        flash("Incident not found.", "danger")
        return redirect(url_for("view_logs"))
    actions = get_response_actions(log["threat_type"]) if log["threat_type"] else get_response_actions("Unknown Attack")
    return render_template("incident.html", log=log, actions=actions)


@app.route("/reports")
def reports():
    stats = db.get_stats()
    return render_template("reports.html", stats=stats)


@app.route("/export/csv")
def export_csv():
    scope = request.args.get("scope", "all")  # all | suspicious
    conn = db.get_connection()
    if scope == "suspicious":
        rows = conn.execute("SELECT * FROM logs WHERE status='Suspicious' ORDER BY id").fetchall()
    else:
        rows = conn.execute("SELECT * FROM logs ORDER BY id").fetchall()
    conn.close()

    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        for r in rows:
            writer.writerow(dict(r))
    else:
        output.write("No data available\n")

    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    filename = f"incident_report_{scope}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name=filename)


# ------------------------------------------------------------- API endpoints ---

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "network-log-analyzer"
    }), 200


@app.route("/analyze", methods=["POST"])
def analyze_log_api():
    if not request.is_json:
        return jsonify({
            "error": "Invalid Content-Type. Expected application/json"
        }), 400

    data = request.get_json(silent=True)
    if data is None or not isinstance(data, dict):
        return jsonify({
            "error": "Invalid or missing JSON payload"
        }), 400

    required_fields = ["source_ip", "destination_ip"]
    missing = [f for f in required_fields if f not in data or data[f] is None or str(data[f]).strip() == ""]
    if missing:
        return jsonify({
            "error": f"Missing required fields: {', '.join(missing)}"
        }), 400

    try:
        analysis = security_orchestrator.analyze_log(row=data)
        response_payload = {
            "anomaly_prediction": analysis["anomaly_prediction"],
            "anomaly_score": analysis["anomaly_score"],
            "threat_type": analysis["threat_type"],
            "severity": analysis["severity"],
            "confidence": analysis["confidence"],
            "recommended_action": analysis["recommended_action"],
            "explanation": analysis["explanation"]
        }
        return jsonify(response_payload), 200
    except Exception as e:
        return jsonify({
            "error": f"Failed to analyze network log: {str(e)}"
        }), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
