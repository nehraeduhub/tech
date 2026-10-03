#!/usr/bin/env python3
"""Tech Guardians VAPT Portal.

A fully portable, database-free web portal. Launch it, open the browser, confirm
authorisation, enter a target, and it runs non-intrusive assessment checks and
produces a branded PDF report.

Design goals:
  * Portable  - pure Python, no DB, state kept in memory + files on disk.
  * Safe      - requires explicit authorisation before any scan runs.
  * Offline   - works from a USB stick; external scanners used only if present.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for, jsonify,
    send_file, abort,
)

from scanner.engine import run_scan, normalize_target
from scanner.checks.external_tools import available_tools
from report.pdf_generator import build_report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)

app = Flask(__name__)

# In-memory job registry (no database -- fully portable).
# job_id -> {status, target, result, pdf, error, client, assessor, ref}
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()


def _run_job(job_id: str) -> None:
    job = JOBS[job_id]
    try:
        job["status"] = "running"
        result = run_scan(
            job["target"],
            use_external_tools=job.get("use_external", True),
        )
        rd = result.to_dict()
        job["result"] = rd

        # Persist JSON + PDF alongside each other in /reports.
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe = "".join(c if c.isalnum() else "_"
                       for c in result.normalized_url)[:40]
        base = f"TechGuardians_VAPT_{safe}_{stamp}"
        json_path = os.path.join(REPORT_DIR, base + ".json")
        pdf_path = os.path.join(REPORT_DIR, base + ".pdf")
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(rd, fh, indent=2)
        build_report(
            rd, pdf_path,
            client_name=job.get("client", ""),
            assessor=job.get("assessor", ""),
            engagement_ref=job.get("ref", ""),
        )
        job["pdf"] = os.path.basename(pdf_path)
        job["json"] = os.path.basename(json_path)
        job["status"] = "done"
    except Exception as exc:  # noqa: BLE001
        job["status"] = "error"
        job["error"] = str(exc)


@app.route("/")
def index():
    return render_template("index.html", tools=available_tools())


@app.route("/scan", methods=["POST"])
def scan():
    target = (request.form.get("target") or "").strip()
    authorised = request.form.get("authorised") == "on"
    if not authorised:
        return render_template("index.html", tools=available_tools(),
                               error="You must confirm written authorisation "
                                     "before scanning."), 400
    try:
        normalize_target(target)  # validate early
    except ValueError as exc:
        return render_template("index.html", tools=available_tools(),
                               error=f"Invalid target: {exc}"), 400

    job_id = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[job_id] = {
            "status": "queued",
            "target": target,
            "client": (request.form.get("client") or "").strip(),
            "assessor": (request.form.get("assessor") or "").strip(),
            "ref": (request.form.get("ref") or "").strip(),
            "use_external": request.form.get("use_external") == "on",
            "created": datetime.now().isoformat(),
        }
    threading.Thread(target=_run_job, args=(job_id,), daemon=True).start()
    return redirect(url_for("scanning", job_id=job_id))


@app.route("/scanning/<job_id>")
def scanning(job_id: str):
    if job_id not in JOBS:
        abort(404)
    return render_template("scanning.html", job_id=job_id,
                           target=JOBS[job_id]["target"])


@app.route("/status/<job_id>")
def status(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"status": "unknown"}), 404
    payload = {"status": job["status"]}
    if job["status"] == "done":
        payload["result"] = {
            "risk_rating": job["result"]["risk_rating"],
            "risk_score": job["result"]["risk_score"],
            "severity_counts": job["result"]["severity_counts"],
            "count": len(job["result"]["findings"]),
        }
        payload["log"] = job["result"]["tool_log"]
    elif job["status"] == "error":
        payload["error"] = job.get("error", "unknown error")
    elif job.get("result"):
        payload["log"] = job["result"].get("tool_log", [])
    return jsonify(payload)


@app.route("/report/<job_id>")
def report(job_id: str):
    job = JOBS.get(job_id)
    if not job or job.get("status") != "done":
        abort(404)
    return render_template("report.html", job_id=job_id, job=job,
                           result=job["result"])


@app.route("/download/<job_id>")
def download(job_id: str):
    job = JOBS.get(job_id)
    if not job or not job.get("pdf"):
        abort(404)
    return send_file(os.path.join(REPORT_DIR, job["pdf"]), as_attachment=True)


@app.route("/download-json/<job_id>")
def download_json(job_id: str):
    job = JOBS.get(job_id)
    if not job or not job.get("json"):
        abort(404)
    return send_file(os.path.join(REPORT_DIR, job["json"]), as_attachment=True)


if __name__ == "__main__":
    import webbrowser

    host = os.environ.get("TG_HOST", "127.0.0.1")
    port = int(os.environ.get("TG_PORT", "5000"))
    url = f"http://{host}:{port}/"
    print("=" * 56)
    print("  Tech Guardians VAPT Portal")
    print("  Vulnerability Assessment & Penetration Testing")
    print("=" * 56)
    print(f"  Portal:  {url}")
    print("  Reports saved to: ./reports/")
    print("  Press Ctrl+C to stop.")
    print("=" * 56)
    try:
        if os.environ.get("TG_NO_BROWSER") != "1":
            threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    except Exception:  # noqa: BLE001
        pass
    app.run(host=host, port=port, debug=False)
