
const fileInput = document.getElementById("fileInput");
const uploadArea = document.getElementById("uploadArea");
const selectedFile = document.getElementById("selectedFile");
const fileName = document.getElementById("fileName");
const fileSize = document.getElementById("fileSize");
const removeFile = document.getElementById("removeFile");
const fileScanButton = document.getElementById("fileScanButton");
const fileScanForm = document.getElementById("fileScanForm");

let currentFile = null;

const allowedExtensions = ["pdf", "docx", "zip", "exe", "apk"];

function displayFile(file) {
    const extension = file.name.split(".").pop().toLowerCase();

    if (!allowedExtensions.includes(extension)) {
        alert("Unsupported file format. Please select PDF, DOCX, ZIP, EXE or APK.");
        return;
    }

    currentFile = file;

    fileName.textContent = file.name;
    fileSize.textContent = (file.size / (1024 * 1024)).toFixed(2) + " MB";

    uploadArea.style.display = "none";
    selectedFile.style.display = "flex";
    fileScanButton.disabled = false;
}

fileInput.addEventListener("change", function () {
    if (fileInput.files.length > 0) {
        displayFile(fileInput.files[0]);
    }
});

removeFile.addEventListener("click", function () {
    currentFile = null;
    fileInput.value = "";

    selectedFile.style.display = "none";
    uploadArea.style.display = "block";
    fileScanButton.disabled = true;
});

// Drag and Drop
uploadArea.addEventListener("dragover", function (event) {
    event.preventDefault();
    uploadArea.classList.add("drag-active");
});

uploadArea.addEventListener("dragleave", function () {
    uploadArea.classList.remove("drag-active");
});

uploadArea.addEventListener("drop", function (event) {
    event.preventDefault();
    uploadArea.classList.remove("drag-active");

    const file = event.dataTransfer.files[0];

    if (file) {
        displayFile(file);
    }
});

// Real Backend File Scanning
fileScanForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    if (!currentFile) return;

    fileScanButton.disabled = true;
    fileScanButton.textContent = "Scanning...";

    const resultContainer = document.getElementById("fileScanResult");

    resultContainer.innerHTML = `
        <div class="result-empty">
            <div class="loading-spinner"></div>
            <h4>Analyzing File</h4>
            <p>LinkShield is inspecting your file. Please wait...</p>
        </div>
    `;

    try {
        const formData = new FormData();
        formData.append("file", currentFile);

        const response = await fetch("/api/scan/file", {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "File scanning failed.");
        }

        resultContainer.innerHTML = `
            <div class="result-empty">
                <div class="result-empty-icon">✓</div>
                <h4>File Analysis Completed</h4>
                <p><strong>File:</strong> ${escapeHTML(data.file_name)}</p>
                <p><strong>File Type:</strong> ${escapeHTML(data.file_type)}</p>
                <p><strong>Status:</strong> ${escapeHTML(data.status)}</p>
                <p><strong>Findings:</strong> ${data.findings.length}</p>
                <p>${escapeHTML(data.message)}</p>
                <a href="/results/${encodeURIComponent(data.scan_id)}" class="btn btn-primary">
                    View Detailed Results
                </a>
            </div>
        `;

    } catch (error) {
        resultContainer.innerHTML = `
            <div class="result-empty">
                <h4>Scan Failed</h4>
                <p>${escapeHTML(error.message)}</p>
            </div>
        `;
    } finally {
        fileScanButton.disabled = false;
        fileScanButton.textContent = "Scan File";
    }
});

function escapeHTML(value) {
    const element = document.createElement("span");
    element.textContent = String(value);
    return element.innerHTML;
}
