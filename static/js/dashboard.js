
const quickScanForm = document.getElementById("quickScanForm");
const quickUrl = document.getElementById("quickUrl");

if (quickScanForm) {
    quickScanForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        const url = quickUrl.value.trim();
        const scanButton = quickScanForm.querySelector("button");

        if (!url) return;

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

            window.location.href =
                `/results/${encodeURIComponent(data.scan_id)}`;

        } catch (error) {
            alert(error.message);
        } finally {
            scanButton.disabled = false;
            scanButton.textContent = "Scan URL";
        }
    });
}
