const uploadForm = document.getElementById("upload-form");
const logBox = document.getElementById("log-box");
const reportBox = document.getElementById("report-box");
const downloads = document.getElementById("downloads");
const dlReport = document.getElementById("download-report");
const dlSpec = document.getElementById("download-spec");

function addLog(msg) {
    const div = document.createElement("div");
    div.classList.add("log");
    div.textContent = msg;
    logBox.appendChild(div);
    logBox.scrollTop = logBox.scrollHeight;
}

function addReport(msg) {
    const div = document.createElement("div");
    div.classList.add("report");
    div.textContent = msg;
    reportBox.appendChild(div);
    reportBox.scrollTop = reportBox.scrollHeight;
}

uploadForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const formData = new FormData(uploadForm);
    logBox.innerHTML = "";
    reportBox.innerHTML = "";
    downloads.style.display = "none";

    addLog("⏳ Enviando arquivo...");
    const res = await fetch("/upload", { method: "POST", body: formData });
    const data = await res.json();
    if (data.error) {
        addLog("❌ Erro: " + data.error);
    } else {
        data.log.forEach(msg => addLog(msg));
        data.report_summary.forEach(msg => addReport(msg));
        downloads.style.display = "block";
        dlReport.href = data.download_report;
        dlSpec.href = data.download_spec;
    }
});
