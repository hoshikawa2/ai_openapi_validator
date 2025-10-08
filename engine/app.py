import sys
import subprocess
import json
from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename
import os
from typing import Optional

UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "outputs"
ALLOWED_EXTENSIONS = {"json", "yaml", "yml"}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["OUTPUT_FOLDER"] = OUTPUT_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Nome de arquivo vazio"}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        rules_file = "rules.json"
        report_file = os.path.join(app.config["OUTPUT_FOLDER"], "report.json")
        spec_out = os.path.join(app.config["OUTPUT_FOLDER"], "spec_fixed.json")

        cmd = [
            sys.executable, "rules_dispatcher.py",
            filepath, rules_file,
            "--min-severity", "info"
        ]

        try:
            result = subprocess.run(cmd, check=True, text=True, capture_output=True)

            if os.path.exists("report.json"):
                os.replace("report.json", report_file)
            if os.path.exists("spec_fixed.json"):
                os.replace("spec_fixed.json", spec_out)

            # Carregar o relatório para exibir
            report_summary = []
            if os.path.exists(report_file):
                with open(report_file, "r", encoding="utf-8") as f:
                    report_data = json.load(f)
                    # Resumir (máx. 10 linhas para UI)
                    for item in report_data[:10]:
                        report_summary.append(f"[{item['severity'].upper()}] {item['message']} @ {item['path']}")
                    if len(report_data) > 10:
                        report_summary.append(f"... {len(report_data)-10} mais itens")

            log_msgs = [
                f"📂 Arquivo {filename} recebido",
                "🤖 Aplicando regras do rules.json...",
                f"✅ Relatório salvo em {report_file}",
                f"✅ Especificação corrigida em {spec_out}"
            ]

            return jsonify({
                "log": log_msgs,
                "report_summary": report_summary,
                "download_report": "/download/report",
                "download_spec": "/download/spec"
            })
        except subprocess.CalledProcessError as e:
            return jsonify({"error": f"Erro no processamento: {e.stderr}"}), 500
    return jsonify({"error": "Extensão inválida"}), 400

@app.route("/download/report")
def download_report():
    path = os.path.join(app.config["OUTPUT_FOLDER"], "report.json")
    return send_file(path, as_attachment=True)

@app.route("/download/spec")
def download_spec():
    path = os.path.join(app.config["OUTPUT_FOLDER"], "spec_fixed.json")
    return send_file(path, as_attachment=True)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=9010)
