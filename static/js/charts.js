const CHART_COLORS = ["#3b82f6", "#ef4444", "#f59e0b", "#22c55e", "#8b5cf6", "#ec4899", "#06b6d4"];

function initTimelineChart(canvasId, data) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  new Chart(ctx, {
    type: "line",
    data: {
      labels: data.map(d => d.t),
      datasets: [{
        label: "Logs",
        data: data.map(d => d.c),
        borderColor: "#3b82f6",
        backgroundColor: "rgba(59,130,246,0.15)",
        fill: true,
        tension: 0.3,
      }]
    },
    options: { responsive: true, plugins: { legend: { display: false } } }
  });
}

function initAttackTypesChart(canvasId, data) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  new Chart(ctx, {
    type: "bar",
    data: {
      labels: data.map(d => d.threat_type),
      datasets: [{
        label: "Incidents",
        data: data.map(d => d.c),
        backgroundColor: CHART_COLORS,
      }]
    },
    options: { responsive: true, plugins: { legend: { display: false } } }
  });
}

function initProtocolChart(canvasId, data) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  new Chart(ctx, {
    type: "pie",
    data: {
      labels: data.map(d => d.protocol),
      datasets: [{
        data: data.map(d => d.c),
        backgroundColor: CHART_COLORS,
      }]
    },
    options: { responsive: true }
  });
}

function initSeverityChart(canvasId, data) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  new Chart(ctx, {
    type: "bar",
    data: {
      labels: data.map(d => d.severity),
      datasets: [{
        label: "Count",
        data: data.map(d => d.c),
        backgroundColor: CHART_COLORS,
      }]
    },
    options: { responsive: true, plugins: { legend: { display: false } } }
  });
}
