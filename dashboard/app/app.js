let classChartInstance = null;
let trafficChartInstance = null;
let pollInterval = null;
let sseSource = null;
let replayCountdownTimer = null;
let replaySecondsRemaining = 0;

let seenAlertIds = new Set();
let classCounts = {};
let talkerCounts = {};

// Traffic chart data
const MAX_TRAFFIC_POINTS = 60; // 60 seconds rolling buffer
let trafficTimeLabels = [];
let trafficPpsData = [];
let trafficMbpsData = [];

// Notification Manager State
let notificationThreshold = 1000;
let inAppNotifEnabled = true;
let osNotifEnabled = false;
let notifiedThresholds = {}; // { "DDoS": 1000, "C2 Beaconing": 0, ... }

const API_BASE = "http://localhost:8000/api";

document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    initConfigModal();
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
        applySeverityFilter();
    });
    document.getElementById("close-drilldown").addEventListener("click", closeModal);
    
    // Heartbeat fallback poll every 5 seconds in case SSE drops
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(fetchSummary, 5000);
});

/* --- CONFIG & NOTIFICATIONS --- */

function initConfigModal() {
    const btnConfig = document.getElementById("btn-config");
    const modal = document.getElementById("config-modal");
    const closeBtn = document.getElementById("close-config");
    const saveBtn = document.getElementById("btn-save-config");
    
    const inputThresh = document.getElementById("input-threshold");
    const checkInApp = document.getElementById("check-inapp");
    const checkOS = document.getElementById("check-os");

    btnConfig.addEventListener("click", () => {
        inputThresh.value = notificationThreshold;
        checkInApp.checked = inAppNotifEnabled;
        checkOS.checked = osNotifEnabled;
        modal.classList.remove("hidden");
    });

    closeBtn.addEventListener("click", () => modal.classList.add("hidden"));

    saveBtn.addEventListener("click", () => {
        notificationThreshold = parseInt(inputThresh.value, 10) || 1000;
        inAppNotifEnabled = checkInApp.checked;
        
        if (checkOS.checked && !osNotifEnabled) {
            // Request OS permission if enabling
            if ("Notification" in window) {
                Notification.requestPermission().then(perm => {
                    osNotifEnabled = (perm === "granted");
                    if (!osNotifEnabled) {
                        alert("OS Notifications permission denied.");
                        checkOS.checked = false;
                    }
                });
            } else {
                alert("OS Notifications not supported in this browser.");
                checkOS.checked = false;
                osNotifEnabled = false;
            }
        } else {
            osNotifEnabled = checkOS.checked;
        }

        modal.classList.add("hidden");
    });
}

function checkAndTriggerNotification(threatClass, currentCount) {
    if (!notificationThreshold || notificationThreshold <= 0) return;

    const lastNotified = notifiedThresholds[threatClass] || 0;
    
    // Trigger only if we crossed a new threshold boundary
    if (currentCount - lastNotified >= notificationThreshold) {
        // Find the highest threshold crossed
        const crossedThreshold = Math.floor(currentCount / notificationThreshold) * notificationThreshold;
        
        if (crossedThreshold > lastNotified) {
            notifiedThresholds[threatClass] = crossedThreshold;
            fireNotification(threatClass, crossedThreshold);
        }
    }
}

function fireNotification(threatClass, count) {
    const title = `⚠ Threat Alert: ${threatClass}`;
    const body = `Detection count reached ${count.toLocaleString()}. Network traffic requires attention.`;
    
    let severity = "critical";
    if (threatClass.toLowerCase().includes("recon")) severity = "warning";
    
    // In-App Toast
    if (inAppNotifEnabled) {
        const container = document.getElementById("toast-container");
        const toast = document.createElement("div");
        toast.className = `toast toast-${severity}`;
        toast.innerHTML = `
            <div class="toast-header">
                <span>${title}</span>
                <span style="font-size: 10px; opacity: 0.7;">${new Date().toLocaleTimeString()}</span>
            </div>
            <div class="toast-body">${body}</div>
        `;
        container.appendChild(toast);
        
        // Remove toast after 5s
        setTimeout(() => {
            if (container.contains(toast)) {
                container.removeChild(toast);
            }
        }, 5000);
    }
    
    // OS Notification
    if (osNotifEnabled && "Notification" in window && Notification.permission === "granted") {
        try {
            new Notification(title, { body: body, icon: "/favicon.ico" });
        } catch (e) {
            console.error("OS Notification failed", e);
        }
    }
}

/* --- STATE RESET --- */
function resetSessionState() {
    seenAlertIds.clear();
    classCounts = {};
    talkerCounts = {};
    notifiedThresholds = {}; // Reset thresholds on new replay
    
    trafficTimeLabels = [];
    trafficPpsData = [];
    trafficMbpsData = [];
    
    document.getElementById("alerts-tbody").innerHTML = "";
    document.getElementById("top-talkers-list").innerHTML = "";
    
    updateClassChart();
    updateTrafficChart();
}

/* --- SSE STREAMING --- */

function initSSE() {
    if (!window.EventSource) return;

    if (sseSource) {
        sseSource.close();
    }

    sseSource = new EventSource(`${API_BASE}/stream`);

    // 1. Live Telemetry stream
    sseSource.addEventListener("telemetry", (event) => {
        try {
            const data = JSON.parse(event.data);
            updateTelemetryUI(data);
            appendTrafficChartData(data);
        } catch (e) {
            console.error("Telemetry parse error:", e);
        }
    });

    // 2. Real-Time Alert stream
    sseSource.addEventListener("alert", (event) => {
        try {
            const alert = JSON.parse(event.data);
            handleIncomingLiveAlert(alert);
        } catch (e) {
            console.error("Alert push parse error:", e);
        }
    });

    sseSource.onerror = () => {
        // Background reconnect
    };
}

/* --- TELEMETRY & CHARTS --- */

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
        flowsEl.textContent = `${Number(data.active_flows).toLocaleString()}`;
    }
    if (latEl && data.latency_ms !== undefined) {
        latEl.textContent = `${Number(data.latency_ms).toFixed(2)} ms`;
    }
    if (diodeEl && data.diode_mode) {
        diodeEl.textContent = data.diode_mode;
    }
}

function initCharts() {
    // Class Chart (Doughnut)
    const ctxClass = document.getElementById('classChart').getContext('2d');
    classChartInstance = new Chart(ctxClass, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: ['#ef4444', '#f97316', '#eab308', '#0088ff', '#a855f7', '#14b8a6'],
                borderWidth: 1,
                borderColor: '#111'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { color: '#888', font: { family: 'Consolas' } } }
            },
            cutout: '70%'
        }
    });

    // Traffic Time-Series Chart (Line)
    const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
    trafficChartInstance = new Chart(ctxTraffic, {
        type: 'line',
        data: {
            labels: trafficTimeLabels,
            datasets: [
                {
                    label: 'Packets/s',
                    data: trafficPpsData,
                    borderColor: '#00ff00',
                    backgroundColor: 'rgba(0, 255, 0, 0.1)',
                    borderWidth: 1.5,
                    fill: true,
                    tension: 0.1,
                    yAxisID: 'y'
                },
                {
                    label: 'Mbps',
                    data: trafficMbpsData,
                    borderColor: '#0088ff',
                    backgroundColor: 'rgba(0, 136, 255, 0.1)',
                    borderWidth: 1.5,
                    fill: true,
                    tension: 0.1,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false, // For performance during high frequency updates
            interaction: {
                mode: 'index',
                intersect: false,
            },
            plugins: {
                legend: { position: 'top', labels: { color: '#888', font: { family: 'Consolas' } } }
            },
            scales: {
                x: {
                    ticks: { color: '#888', font: { family: 'Consolas', size: 10 }, maxTicksLimit: 10 },
                    grid: { color: '#333' }
                },
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    ticks: { color: '#00ff00', font: { family: 'Consolas', size: 10 } },
                    grid: { color: '#333' },
                    title: { display: true, text: 'Pkts/s', color: '#888', font: { size: 10 } }
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    grid: { drawOnChartArea: false },
                    ticks: { color: '#0088ff', font: { family: 'Consolas', size: 10 } },
                    title: { display: true, text: 'Mbps', color: '#888', font: { size: 10 } }
                }
            }
        }
    });
}

function appendTrafficChartData(data) {
    if (!trafficChartInstance) return;
    
    const now = new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    
    trafficTimeLabels.push(now);
    trafficPpsData.push(data.pkts_per_sec || 0);
    trafficMbpsData.push(data.mbps || 0);
    
    if (trafficTimeLabels.length > MAX_TRAFFIC_POINTS) {
        trafficTimeLabels.shift();
        trafficPpsData.shift();
        trafficMbpsData.shift();
    }
    
    trafficChartInstance.update();
}

/* --- EVENT STREAM & ALERTS --- */

function handleIncomingLiveAlert(alert) {
    if (seenAlertIds.has(alert.alert_id)) return;
    seenAlertIds.add(alert.alert_id);

    // Filter check
    const sevFilter = document.getElementById("filter-severity").value;
    if (sevFilter && alert.severity.toUpperCase() !== sevFilter.toUpperCase()) {
        // We still increment counts even if filtered from view, but don't add to table
    } else {
        appendAlertToTable(alert);
    }

    // Incremental Data Updates
    const tc = alert.threat_class;
    classCounts[tc] = (classCounts[tc] || 0) + 1;
    updateClassChart();
    
    checkAndTriggerNotification(tc, classCounts[tc]);

    const src = alert.flow_id.src_ip;
    if (src) {
        talkerCounts[src] = (talkerCounts[src] || 0) + 1;
        updateTopTalkersUI();
    }
}

function appendAlertToTable(alert) {
    const tbody = document.getElementById("alerts-tbody");
    if (!tbody) return;

    const tr = document.createElement("tr");
    const sev = alert.severity.toLowerCase();
    tr.className = `row-${sev}`;
    
    const dt = new Date(alert.timestamp * 1000).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 });

    tr.innerHTML = `
        <td>${dt}</td>
        <td>${alert.flow_id.src_ip}</td>
        <td>${alert.flow_id.dst_ip}</td>
        <td>${alert.flow_id.protocol}</td>
        <td>${alert.threat_class}</td>
        <td><span class="sev-${sev}">${alert.severity}</span></td>
        <td>DETECTED</td>
    `;

    tr.addEventListener("click", () => openModal(alert));

    // Prepend to top
    if (tbody.firstChild) {
        tbody.insertBefore(tr, tbody.firstChild);
    } else {
        tbody.appendChild(tr);
    }

    // Cap rows to 150 (Rolling bounded buffer)
    while (tbody.children.length > 150) {
        tbody.removeChild(tbody.lastChild);
    }
}

function applySeverityFilter() {
    // A proper real-time filter just fetches recent history from backend or applies going forward
    fetchAlerts(); 
}

function updateClassChart() {
    if (!classChartInstance) return;
    classChartInstance.data.labels = Object.keys(classCounts);
    classChartInstance.data.datasets[0].data = Object.values(classCounts);
    classChartInstance.update();
}

function updateTrafficChart() {
    if (!trafficChartInstance) return;
    trafficChartInstance.update();
}

function updateTopTalkersUI() {
    const ul = document.getElementById("top-talkers-list");
    if (!ul) return;
    
    // Convert to array, sort, take top 10
    const sorted = Object.entries(talkerCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
        
    ul.innerHTML = sorted.map(([ip, count]) => {
        return `<li><span>${ip}</span> <strong>${count.toLocaleString()}</strong></li>`;
    }).join("");
}

/* --- BACKEND FETCHES --- */

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

    try {
        const res = await fetch(url);
        const data = await res.json();

        const tbody = document.getElementById("alerts-tbody");
        tbody.innerHTML = "";

        data.alerts.forEach(alert => {
            appendAlertToTable(alert);
            seenAlertIds.add(alert.alert_id);
        });
    } catch (e) {
        console.error("Fetch alerts failed", e);
    }
}

async function fetchSummary() {
    try {
        const res = await fetch(`${API_BASE}/stats/summary`);
        const data = await res.json();

        // Sync class counts
        Object.assign(classCounts, data.rate_by_class);
        updateClassChart();

        // Sync top talkers
        const ul = document.getElementById("top-talkers-list");
        ul.innerHTML = "";
        data.top_talkers.forEach(t => {
            talkerCounts[t.ip] = t.count;
            ul.innerHTML += `<li><span>${t.ip}</span> <strong>${t.count.toLocaleString()}</strong></li>`;
        });
    } catch (e) {
        console.error("Fetch summary failed", e);
    }
}

/* --- REPLAY CONTROLS --- */

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
        btnReplay.innerHTML = "▶ START";
    }
    if (btnStop) {
        btnStop.disabled = true;
    }
    if (countdownEl) {
        countdownEl.classList.add("hidden");
    }
    if (ind) {
        ind.className = "status-indicator idle";
        ind.textContent = statusNote ? `IDLE (${statusNote.toUpperCase()})` : "IDLE (AIR-GAPPED)";
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
    
    resetSessionState(); // Clear UI state on new run

    btnReplay.disabled = true;
    btnReplay.innerHTML = "⏳ RUNNING...";
    if (btnStop) btnStop.disabled = false;
    ind.className = "status-indicator active";
    ind.textContent = "LAUNCHING...";

    replaySecondsRemaining = duration;
    if (timerDisplay) timerDisplay.textContent = formatCountdownTime(replaySecondsRemaining);
    if (countdownEl) countdownEl.classList.remove("hidden");

    if (replayCountdownTimer) clearInterval(replayCountdownTimer);
    
    replayCountdownTimer = setInterval(() => {
        replaySecondsRemaining -= 1;
        if (replaySecondsRemaining <= 0) {
            resetReplayUI("COMPLETED");
            fetchData();
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
            ind.textContent = `STREAMING: ${data.scenario.toUpperCase()}`;
        } else {
            ind.textContent = "STREAMING INGRESS";
        }

        initSSE(); // Reconnect SSE

    } catch (e) {
        console.error("Failed to start replay:", e);
        resetReplayUI("ERROR");
    }
}

async function stopReplay() {
    const btnStop = document.getElementById("btn-stop-replay");
    const ind = document.getElementById("status-indicator");

    if (btnStop) btnStop.disabled = true;
    if (ind) ind.textContent = "HALTING REPLAY...";

    try {
        await fetch(`${API_BASE}/replay/stop`, { method: "POST" });
    } catch (e) {
        console.error("Failed to halt replay on backend:", e);
    } finally {
        resetReplayUI("STOPPED");
        fetchData();
    }
}

/* --- MODALS --- */

function openModal(alert) {
    document.getElementById("modal-title").textContent = `ALERT: ${alert.alert_id}`;
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

    document.getElementById("drilldown-modal").classList.remove("hidden");
}

function closeModal() {
    document.getElementById("drilldown-modal").classList.add("hidden");
}
