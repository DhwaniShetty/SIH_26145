let chartInstance = null;
let pollInterval = null;
let sseSource = null;
let replayCountdownTimer = null;
let replaySecondsRemaining = 0;
const seenAlertIds = new Set();
const classCounts = {};
const talkerCounts = {};

const API_BASE = "http://localhost:8000/api";

document.addEventListener("DOMContentLoaded", () => {
    initChart();
    fetchData();
    initSSE();

    document.getElementById("btn-replay").addEventListener("click", triggerReplay);
    
    const btnStop = document.getElementById("btn-stop-replay");
    if (btnStop) {
        btnStop.addEventListener("click", stopReplay);
    }

    const selectDuration = document.getElementById("select-duration");
    if (selectDuration) {
        selectDuration.addEventListener("change", (e) => {
            const customInput = document.getElementById("input-custom-duration");
            if (customInput) {
                if (e.target.value === "custom") {
                    customInput.classList.remove("hidden");
                    customInput.focus();
                } else {
                    customInput.classList.add("hidden");
                }
            }
        });
    }

    document.getElementById("filter-severity").addEventListener("change", () => {
        fetchAlerts();
    });
    document.querySelector(".close-btn").addEventListener("click", closeModal);
    
    // Heartbeat fallback poll every 5 seconds in case SSE drops
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(fetchSummary, 5000);
});

function initSSE() {
    if (!window.EventSource) return;

    if (sseSource) {
        sseSource.close();
    }

    sseSource = new EventSource(`${API_BASE}/stream`);

    // 1. Live Telemetry stream (Constraint D)
    sseSource.addEventListener("telemetry", (event) => {
        try {
            const data = JSON.parse(event.data);
            updateTelemetryUI(data);
        } catch (e) {
            console.error("Telemetry parse error:", e);
        }
    });

    // 2. Real-Time Alert push stream (Constraint C)
    sseSource.addEventListener("alert", (event) => {
        try {
            const alert = JSON.parse(event.data);
            handleIncomingLiveAlert(alert);
        } catch (e) {
            console.error("Alert push parse error:", e);
        }
    });

    sseSource.onerror = () => {
        // EventSource will automatically retry connecting in background
    };
}

function updateTelemetryUI(data) {
    const ppsEl = document.getElementById("telem-pps");
    const mbpsEl = document.getElementById("telem-mbps");
    const flowsEl = document.getElementById("telem-flows");
    const latEl = document.getElementById("telem-latency");
    const diodeEl = document.getElementById("telem-diode");

    if (ppsEl && data.pkts_per_sec !== undefined) {
        ppsEl.textContent = `${Number(data.pkts_per_sec).toLocaleString()} pkts/s`;
    }
    if (mbpsEl && data.mbps !== undefined) {
        mbpsEl.textContent = `${Number(data.mbps).toFixed(1)} Mbps`;
    }
    if (flowsEl && data.active_flows !== undefined) {
        flowsEl.textContent = `${Number(data.active_flows).toLocaleString()} flows`;
    }
    if (latEl && data.latency_ms !== undefined) {
        latEl.textContent = `${Number(data.latency_ms).toFixed(2)} ms`;
    }
    if (diodeEl && data.diode_mode) {
        diodeEl.textContent = data.diode_mode;
    }
}

function handleIncomingLiveAlert(alert) {
    if (seenAlertIds.has(alert.alert_id)) return;
    seenAlertIds.add(alert.alert_id);

    // Check filter
    const sevFilter = document.getElementById("filter-severity").value;
    if (sevFilter && alert.severity.toUpperCase() !== sevFilter.toUpperCase()) {
        return;
    }

    const tbody = document.getElementById("alerts-tbody");
    if (!tbody) return;

    const tr = document.createElement("tr");
    tr.className = "row-new-alert";
    tr.dataset.alertId = alert.alert_id;
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

    // Prepend to show newest at top
    if (tbody.firstChild) {
        tbody.insertBefore(tr, tbody.firstChild);
    } else {
        tbody.appendChild(tr);
    }

    // Cap rows to 100 to prevent DOM memory bloating
    while (tbody.children.length > 100) {
        tbody.removeChild(tbody.lastChild);
    }

    // Real-time incremental Chart update
    const tc = alert.threat_class;
    classCounts[tc] = (classCounts[tc] || 0) + 1;
    updateChartIncrementally();

    // Real-time incremental Top Talker update
    const src = alert.flow_id.src_ip;
    if (src) {
        talkerCounts[src] = (talkerCounts[src] || 0) + 1;
        updateTopTalkersUI();
    }
}

function updateChartIncrementally() {
    if (!chartInstance) return;
    chartInstance.data.labels = Object.keys(classCounts);
    chartInstance.data.datasets[0].data = Object.values(classCounts);
    chartInstance.update();
}

function updateTopTalkersUI() {
    const ul = document.getElementById("top-talkers-list");
    if (!ul) return;
    ul.innerHTML = "";
    const sorted = Object.entries(talkerCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
    sorted.forEach(([ip, count]) => {
        ul.innerHTML += `<li><span>${ip}</span> <strong>${count} alerts</strong></li>`;
    });
}

async function fetchData() {
    try {
        await Promise.all([
            fetchAlerts(),
            fetchSummary(),
            fetchTelemetry()
        ]);
    } catch (e) {
        console.error("Error fetching data:", e);
    }
}

async function fetchTelemetry() {
    try {
        const res = await fetch(`${API_BASE}/stats/telemetry`);
        const data = await res.json();
        updateTelemetryUI(data);
    } catch (e) {
        // silent fail
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
        seenAlertIds.add(alert.alert_id);
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

    // Sync class counts
    Object.assign(classCounts, data.rate_by_class);
    updateChartIncrementally();

    // Sync top talkers
    const ul = document.getElementById("top-talkers-list");
    ul.innerHTML = "";
    data.top_talkers.forEach(t => {
        talkerCounts[t.ip] = t.count;
        ul.innerHTML += `<li><span>${t.ip}</span> <strong>${t.count} alerts</strong></li>`;
    });
}

function getSelectedDuration() {
    const select = document.getElementById("select-duration");
    if (!select) return 20;
    if (select.value === "custom") {
        const input = document.getElementById("input-custom-duration");
        const val = parseInt(input ? input.value : "20", 10);
        return (val && val > 0) ? Math.min(val, 7200) : 20;
    }
    return parseInt(select.value, 10) || 20;
}

function formatCountdownTime(totalSeconds) {
    const mins = Math.floor(totalSeconds / 60);
    const secs = totalSeconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

function resetReplayUI(statusNote = null) {
    if (replayCountdownTimer) {
        clearInterval(replayCountdownTimer);
        replayCountdownTimer = null;
    }
    replaySecondsRemaining = 0;

    const btnReplay = document.getElementById("btn-replay");
    const btnStop = document.getElementById("btn-stop-replay");
    const countdownEl = document.getElementById("countdown-timer");
    const ind = document.getElementById("status-indicator");

    if (btnReplay) {
        btnReplay.disabled = false;
        btnReplay.innerHTML = "▶ Start Live Demo Replay";
    }
    if (btnStop) {
        btnStop.disabled = true;
    }
    if (countdownEl) {
        countdownEl.classList.add("hidden");
    }
    if (ind) {
        ind.className = "status idle";
        ind.textContent = statusNote ? `Idle (${statusNote})` : "Idle (Air-Gapped)";
    }
}

async function triggerReplay() {
    const btnReplay = document.getElementById("btn-replay");
    const btnStop = document.getElementById("btn-stop-replay");
    const ind = document.getElementById("status-indicator");
    const scenarioSelect = document.getElementById("select-scenario");
    const countdownEl = document.getElementById("countdown-timer");
    const timerDisplay = document.getElementById("timer-display");

    const selectedScenario = scenarioSelect ? scenarioSelect.value : "random";
    const duration = getSelectedDuration();

    // Update UI controls to active replay state
    btnReplay.disabled = true;
    btnReplay.innerHTML = "⏳ Replay Running...";
    if (btnStop) btnStop.disabled = false;
    ind.className = "status active";
    ind.textContent = "Launching...";

    // Initialize countdown timer display
    replaySecondsRemaining = duration;
    if (timerDisplay) timerDisplay.textContent = formatCountdownTime(replaySecondsRemaining);
    if (countdownEl) countdownEl.classList.remove("hidden");

    if (replayCountdownTimer) {
        clearInterval(replayCountdownTimer);
    }
    replayCountdownTimer = setInterval(() => {
        replaySecondsRemaining -= 1;
        if (replaySecondsRemaining <= 0) {
            resetReplayUI("Completed");
            fetchAlerts();
            fetchSummary();
        } else {
            if (timerDisplay) {
                timerDisplay.textContent = formatCountdownTime(replaySecondsRemaining);
            }
        }
    }, 1000);

    try {
        const url = `${API_BASE}/replay?scenario=${encodeURIComponent(selectedScenario)}&duration=${encodeURIComponent(duration)}`;
        const res = await fetch(url, { method: "POST" });
        const data = await res.json();
        if (data.scenario) {
            ind.textContent = `Streaming: ${data.scenario}`;
        } else {
            ind.textContent = "Streaming Ingress";
        }

        // Reconnect SSE to ensure stream is actively receiving live events
        initSSE();

    } catch (e) {
        console.error("Failed to start replay:", e);
        resetReplayUI("Error");
    }
}

async function stopReplay() {
    const btnStop = document.getElementById("btn-stop-replay");
    const ind = document.getElementById("status-indicator");

    if (btnStop) btnStop.disabled = true;
    if (ind) ind.textContent = "Halting Replay...";

    try {
        await fetch(`${API_BASE}/replay/stop`, { method: "POST" });
    } catch (e) {
        console.error("Failed to halt replay on backend:", e);
    } finally {
        resetReplayUI("Stopped");
        // Immediately fetch refreshed stats and alerts
        fetchAlerts();
        fetchSummary();
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
