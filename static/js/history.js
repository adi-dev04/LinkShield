
const historySearch = document.getElementById("historySearch");
const typeFilter = document.getElementById("typeFilter");
const riskFilter = document.getElementById("riskFilter");

function filterHistory() {
    const searchValue = historySearch.value.toLowerCase().trim();
    const selectedType = typeFilter.value;
    const selectedRisk = riskFilter.value;

    const rows = document.querySelectorAll(".history-row");

    rows.forEach(row => {
        const target = row.dataset.target;
        const type = row.dataset.type;
        const risk = row.dataset.risk;

        const matchesSearch = target.includes(searchValue);
        const matchesType = selectedType === "all" || type === selectedType;
        const matchesRisk = selectedRisk === "all" || risk === selectedRisk;

        row.style.display =
            matchesSearch && matchesType && matchesRisk ? "" : "none";
    });
}

if (historySearch && typeFilter && riskFilter) {
    historySearch.addEventListener("input", filterHistory);
    typeFilter.addEventListener("change", filterHistory);
    riskFilter.addEventListener("change", filterHistory);
}
