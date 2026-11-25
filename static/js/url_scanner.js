
const urlScanForm = document.getElementById("urlScanForm");
const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");
const scanResult = document.getElementById("scanResult");

if (urlScanForm) {
    urlScanForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        const url = urlInput.value.trim();

        if (!url) {
            return;
        }

        try {
            const parsedUrl = new URL(url);

            if (!["http:", "https:"].includes(parsedUrl.protocol)) {
                throw new Error("Invalid protocol");
            }
        } catch {
            alert("Please enter a valid HTTP or HTTPS URL.");
            return;
        }

        scanButton.disabled = true;
        scanButton.textContent = "Scanning...";

        scanResult.innerHTML = `
            <div class="result-empty">
                <div class="loading-spinner"></div>
                <h4>Analyzing URL</h4>
                <p>Please wait while LinkShield analyzes the URL.</p>
            </div>
        `;

        try {
            const response = await fetch("/api/scan/url", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ url: url })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || "URL scanning failed.");
            }

            scanResult.innerHTML = `
                <div class="result-empty">
                    <div class="result-empty-icon">✓</div>
                    <h4>URL Analysis Completed</h4>
                    <p><strong>Risk Level:</strong> ${data.risk_level.replaceAll("_", " ").toUpperCase()}</p>
                    <p><strong>Status:</strong> ${data.status}</p>
                    <p><strong>Scan ID:</strong> ${data.scan_id}</p>
                    <p>${data.message}</p>
                    <a href="/results/${encodeURIComponent(data.scan_id)}" class="btn btn-primary">
                        View Detailed Results
                    </a>
                </div>
            `;

        } catch (error) {
            scanResult.innerHTML = `
                <div class="result-empty">
                    <h4>Scan Failed</h4>
                    <p>${error.message}</p>
                </div>
            `;
        } finally {
            scanButton.disabled = false;
            scanButton.textContent = "Scan URL";
        }
    });
}
