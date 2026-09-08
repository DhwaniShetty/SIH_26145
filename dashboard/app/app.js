let chartInstance = null;
let pollInterval = null;

const API_BASE = "http://localhost:8000/api";

document.addEventListener("DOMContentLoaded", () => {
    initChart();
    fetchData();

    document.getElementById("btn-replay").addEventListener("click", triggerReplay);
    document.getElementById("filter-severity").addEventListener("change", fetchData);
    document.querySelector(".close-btn").addEventListener("click", closeModal);
    
    // Automatically poll every 2 seconds to catch the backend auto-replay
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(fetchData, 2000);
});

async function fetchData() {
    try {
        await Promise.all([
            fetchAlerts(),
            fetchSummary()
        ]);
    } catch (e) {
        console.error("Error fetching data:", e);
    }
}

async function fetchAlerts() {
    const sev = document.getElementById("filter-severity").value;
    let url = `${API_BASE}/alerts?limit=50`;
    if (sev) url += `&severity=${sev}`;

    const res = await fetch(url);
    const data = await res.json();

    const tbody = document.getElementById("alerts-tbody");
    tbody.innerHTML = "";

    data.alerts.forEach(alert => {
        const tr = document.createElement("tr");
        const dt = new Date(alert.timestamp * 1000).toLocaleTimeString();

        tr.innerHTML = `
            <td>${dt}</td>
            <td><strong>${alert.threat_class}</strong></td>
            <td><span class="badge ${alert.severity.toLowerCase()}">${alert.severity}</span></td>
            <td>${(alert.confidence_score * 100).toFixed(1)}%</td>
            <td>${alert.flow_id.src_ip}</td>
            <td>${alert.flow_id.dst_ip}</td>
        `;

        tr.addEventListener("click", () => openModal(alert));
        tbody.appendChild(tr);
    });
}

async function fetchSummary() {
    const res = await fetch(`${API_BASE}/stats/summary`);
    const data = await res.json();

    // Update Chart
    const labels = Object.keys(data.rate_by_class);
    const values = Object.values(data.rate_by_class);

    chartInstance.data.labels = labels;
    chartInstance.data.datasets[0].data = values;
    chartInstance.update();

    // Update Top Talkers
    const ul = document.getElementById("top-talkers-list");
    ul.innerHTML = "";
    data.top_talkers.forEach(t => {
        ul.innerHTML += `<li><span>${t.ip}</span> <strong>${t.count} alerts</strong></li>`;
    });
}

async function triggerReplay() {
    const btn = document.getElementById("btn-replay");
    const ind = document.getElementById("status-indicator");
    const scenarioSelect = document.getElementById("select-scenario");
    const selectedScenario = scenarioSelect ? scenarioSelect.value : "random";

    btn.disabled = true;
    btn.textContent = "Replay Running...";
    ind.className = "status active";
    ind.textContent = "Launching...";

    try {
        const res = await fetch(`${API_BASE}/replay?scenario=${encodeURIComponent(selectedScenario)}`, { method: "POST" });
        const data = await res.json();
        if (data.scenario) {
            ind.textContent = `Live: ${data.scenario}`;
        } else {
            ind.textContent = "Live Updates";
        }

        // Immediately fetch data and start polling
        fetchData();
        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(fetchData, 2000);

        // Reset after 30 seconds
        setTimeout(() => {
            clearInterval(pollInterval);
            btn.disabled = false;
            btn.textContent = "Start Live Demo Replay";
            ind.className = "status idle";
            ind.textContent = "Idle";
        }, 30000);

    } catch (e) {
        console.error(e);
        btn.disabled = false;
        btn.textContent = "Start Live Demo Replay";
        ind.className = "status idle";
        ind.textContent = "Idle";
    }
}

function initChart() {
    const ctx = document.getElementById('classChart').getContext('2d');
    chartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#a855f7', '#14b8a6'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { color: '#94a3b8' } }
            }
        }
    });
}


function openModal(alert) {
    document.getElementById("modal-title").textContent = `Alert: ${alert.alert_id}`;
    document.getElementById("modal-explanation").textContent = alert.evidence.explanation;
    document.getElementById("modal-features").textContent = JSON.stringify(alert.evidence.features, null, 2);

    const relUl = document.getElementById("modal-related");
    relUl.innerHTML = "";
    if (alert.related_alert_ids && alert.related_alert_ids.length > 0) {
        alert.related_alert_ids.forEach(id => {
            relUl.innerHTML += `<li>${id}</li>`;
        });
    } else {
        relUl.innerHTML = "<li>None</li>";
    }

    document.getElementById("drilldown-modal").classList.add("visible");
}

function closeModal() {
    document.getElementById("drilldown-modal").classList.remove("visible");
}
