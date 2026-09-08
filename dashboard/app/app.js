let chartInstance = null;
let networkInstance = null;
let pollInterval = null;

const API_BASE = "http://localhost:8000/api";

document.addEventListener("DOMContentLoaded", () => {
    initChart();
    initNetwork();
    fetchData();
    
    document.getElementById("btn-replay").addEventListener("click", triggerReplay);
    document.getElementById("filter-severity").addEventListener("change", fetchData);
    document.querySelector(".close-btn").addEventListener("click", closeModal);
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
    
    // Graph dataset
    let nodes = new vis.DataSet();
    let edges = new vis.DataSet();
    
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
        
        // Add to graph
        let color = "#3b82f6";
        if (alert.severity === "CRITICAL") color = "#ef4444";
        if (alert.severity === "HIGH") color = "#f97316";
        if (alert.severity === "MEDIUM") color = "#eab308";
        
        nodes.add({
            id: alert.alert_id,
            label: alert.threat_class,
            color: color,
            title: alert.evidence.explanation
        });
        
        if (alert.related_alert_ids) {
            alert.related_alert_ids.forEach(rel_id => {
                // Avoid missing node errors by just pushing the edge; 
                // vis handles it gracefully if configured or we can ensure node exists
                edges.add({
                    from: rel_id,
                    to: alert.alert_id,
                    arrows: "to",
                    color: { color: 'rgba(255,255,255,0.2)' }
                });
            });
        }
    });
    
    if (networkInstance) {
        networkInstance.setData({nodes: nodes, edges: edges});
    }
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
    
    btn.disabled = true;
    btn.textContent = "Replay Running...";
    ind.className = "status active";
    ind.textContent = "Live Updates";
    
    try {
        await fetch(`${API_BASE}/replay`, {method: "POST"});
        
        // Start polling
        if(pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(fetchData, 2000);
        
        // Stop polling after some time to simulate demo end
        setTimeout(() => {
            clearInterval(pollInterval);
            btn.disabled = false;
            btn.textContent = "Start Live Demo Replay";
            ind.className = "status idle";
            ind.textContent = "Idle";
        }, 30000); // 30 second demo
        
    } catch(e) {
        console.error(e);
        btn.disabled = false;
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

function initNetwork() {
    const container = document.getElementById('temporal-graph');
    const options = {
        nodes: {
            shape: 'dot',
            size: 16,
            font: { color: '#f8fafc' }
        },
        physics: {
            forceAtlas2Based: { gravitationalConstant: -26, centralGravity: 0.005, springLength: 230, springConstant: 0.18 },
            maxVelocity: 146,
            solver: 'forceAtlas2Based',
            timestep: 0.35,
            stabilization: { iterations: 150 }
        }
    };
    networkInstance = new vis.Network(container, {}, options);
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
