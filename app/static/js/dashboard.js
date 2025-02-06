function updateDashboard() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            document.getElementById('packetCount').textContent = data.total_packets;
            document.getElementById('duration').textContent = 
                Math.round(data.duration) + 's';

            updateProtocolChart(data.protocols);

            // update connections list
            const connectionsDiv = document.getElementById('connectionsList');
            connectionsDiv.innerHTML = Object.entries(data.top_connections)
                .map(([conn, count]) => `<div>${conn}: ${count}</div>`)
                .join('');

            const alertsDiv = document.getElementById('alertsList');
            alertsDiv.innerHTML = data.suspicious_activity
                .map(alert => `
                    <div class="alert">
                        ${alert.type}: ${alert.source} → ${alert.destination}
                        (${new Date(alert.timestamp).toLocaleTimeString()})
                    </div>
                `)
                .join('');
        });
}

let protocolChart;
function initProtocolChart() {
    const ctx = document.getElementById('protocolChart').getContext('2d');
    protocolChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#FF6384',
                    '#36A2EB',
                    '#FFCE56',
                    '#4BC0C0',
                    '#9966FF'
                ]
            }]
        }
    });
}

function updateProtocolChart(protocols) {
    protocolChart.data.labels = Object.keys(protocols);
    protocolChart.data.datasets[0].data = Object.values(protocols);
    protocolChart.update();
}

initProtocolChart();
setInterval(updateDashboard, 1000);