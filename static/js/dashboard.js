// Dashboard Chart Contexts
const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
const ctxGauge = document.getElementById('gaugeChart').getContext('2d');

// Traffic Line Chart
const trafficChart = new Chart(ctxTraffic, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Packets Per Second (PPS)',
            data: [],
            borderColor: 'rgba(75, 192, 192, 1)',
            tension: 0.1,
            fill: true
        }, {
            label: 'Bytes Per Second (BPS)',
            data: [],
            borderColor: 'rgba(54, 162, 235, 1)',
            tension: 0.1,
            hidden: true // Hide by default to avoid scale issues
        }]
    },
    options: {
        responsive: true,
        scales: {
            x: { display: false } // Hide timestamps for cleaner look
        }
    }
});

// Threat Gauge (Simulated using Doughnut)
const gaugeChart = new Chart(ctxGauge, {
    type: 'doughnut',
    data: {
        labels: ['Safe', 'Threat'],
        datasets: [{
            data: [100, 0],
            backgroundColor: ['#2ecc71', '#e74c3c']
        }]
    },
    options: {
        circumference: 180,
        rotation: 270,
        cutout: '70%',
        responsive: true
    }
});

// Polling for Data
function fetchData() {
    fetch('/api/traffic')
        .then(response => response.json())
        .then(data => {
            if (data.error) return;

            // Update Traffic Chart
            const timeLabel = new Date().toLocaleTimeString();
            if (trafficChart.data.labels.length > 20) {
                trafficChart.data.labels.shift();
                trafficChart.data.datasets[0].data.shift();
                trafficChart.data.datasets[1].data.shift();
            }
            trafficChart.data.labels.push(timeLabel);
            trafficChart.data.datasets[0].data.push(data.pps);
            trafficChart.data.datasets[1].data.push(data.bps);
            trafficChart.update();

            // Update Gauge/Threat Level
            const score = data.anomaly_score * 100; // 0-100
            gaugeChart.data.datasets[0].data = [100 - score, score];
            gaugeChart.update();

            // Alert Logic
            const alertBox = document.getElementById('ddos-alert');
            if (data.threat_level === 'DDoS Detected') {
                alertBox.classList.remove('d-none');
                alertBox.innerHTML = `<strong>WARNING:</strong> DDoS Detected! Anomaly Score: ${data.anomaly_score.toFixed(2)}`;
            } else {
                alertBox.classList.add('d-none');
            }

        })
        .catch(error => console.error('Error fetching traffic:', error));
}

// Start polling every 2 seconds (faster than 5s for demo feel)
setInterval(fetchData, 2000);

// Buttons
document.getElementById('simulate-btn')?.addEventListener('click', function () {
    // Determine state (simple toggle logic for demo)
    const btn = this;
    const isSimulating = btn.innerText.includes('Stop');

    fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active: !isSimulating })
    })
        .then(res => res.json())
        .then(data => {
            if (data.status.includes('Started')) {
                btn.innerText = 'Stop Simulation';
                btn.classList.remove('btn-warning');
                btn.classList.add('btn-secondary');
            } else {
                btn.innerText = 'Simulate Attack';
                btn.classList.add('btn-warning');
                btn.classList.remove('btn-secondary');
            }
        });
});

document.getElementById('mitigate-btn')?.addEventListener('click', function () {
    fetch('/api/mitigate', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            const statusDiv = document.getElementById('action-status');
            statusDiv.innerText = `Mitigation Applied: ${data.action}. Blocked ${data.blocked} IPs.`;
            setTimeout(() => { statusDiv.innerText = ''; }, 5000);
        });
});
