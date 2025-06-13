// Chart configurations
const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
        y: {
            beginAtZero: true,
            grid: {
                color: 'rgba(0,0,0,0.1)'
            }
        },
        x: {
            grid: {
                color: 'rgba(0,0,0,0.1)'
            }
        }
    },
    plugins: {
        legend: {
            display: true,
            position: 'top'
        }
    },
    animation: {
        duration: 300
    }
};

// Initialize charts
const requestCtx = document.getElementById('requestChart').getContext('2d');
const requestChart = new Chart(requestCtx, {
    type: 'line',
    data: {
        labels: Array.from({ length: 60 }, (_, i) => i - 59),
        datasets: [{
            label: 'Requests/Second',
            data: Array(60).fill(0),
            borderColor: '#3498db',
            backgroundColor: 'rgba(52, 152, 219, 0.1)',
            fill: true,
            tension: 0.4
        }]
    },
    options: chartOptions
});

const errorCtx = document.getElementById('errorChart').getContext('2d');
const errorChart = new Chart(errorCtx, {
    type: 'line',
    data: {
        labels: Array.from({ length: 60 }, (_, i) => i - 59),
        datasets: [{
            label: 'Errors/Second',
            data: Array(60).fill(0),
            borderColor: '#e74c3c',
            backgroundColor: 'rgba(231, 76, 60, 0.1)',
            fill: true,
            tension: 0.4
        }]
    },
    options: chartOptions
});

const performanceCtx = document.getElementById('performanceChart').getContext('2d');
const performanceChart = new Chart(performanceCtx, {
    type: 'bar',
    data: {
        labels: ['Avg Response Time', 'Total Requests', 'Success Rate', 'Active Connections'],
        datasets: [{
            label: 'Performance Metrics',
            data: [0, 0, 100, 0],
            backgroundColor: [
                'rgba(52, 152, 219, 0.8)',
                'rgba(46, 204, 113, 0.8)',
                'rgba(241, 196, 15, 0.8)',
                'rgba(155, 89, 182, 0.8)'
            ],
            borderColor: [
                '#3498db',
                '#2ecc71',
                '#f1c40f',
                '#9b59b6'
            ],
            borderWidth: 2
        }]
    },
    options: {
        ...chartOptions,
        plugins: {
            legend: {
                display: false
            }
        }
    }
});

// Global variables
let stats = {};
let alertsShown = new Set();


function updateActiveIPs() {
    const container = document.getElementById('active-ips');
    if (!stats.active_ips || stats.active_ips.length === 0) {
        container.innerHTML = '<div class="loading">No active connections</div>';
        return;
    }

    container.innerHTML = '';
    stats.active_ips.forEach(ipInfo => {
        const ipDiv = document.createElement('div');
        let ipClass = 'ip-item';
        let statusBadge = '<span class="status-badge badge-normal">NORMAL</span>';

        if (ipInfo.is_blocked) {
            ipClass += ' blocked';
            statusBadge = '<span class="status-badge badge-blocked">BLOCKED</span>';
        } else if (ipInfo.is_suspicious) {
            ipClass += ' suspicious';
            statusBadge = '<span class="status-badge badge-suspicious">SUSPICIOUS</span>';
        }

        const lastSeen = new Date(ipInfo.last_seen);
        const firstSeen = new Date(ipInfo.first_seen);
        const timeDiff = Date.now() - lastSeen.getTime();
        const timeAgo = timeDiff < 60000 ? 'Just now' :
            timeDiff < 3600000 ? Math.floor(timeDiff / 60000) + 'm ago' :
                Math.floor(timeDiff / 3600000) + 'h ago';

        ipDiv.className = ipClass;
        ipDiv.innerHTML = `
            <div class="ip-main">
                <div class="ip-address">${ipInfo.ip}${statusBadge}</div>
                <div class="ip-details">
                    Last: ${ipInfo.last_endpoint} | 
                    UA: ${ipInfo.user_agent.substring(0, 50)}${ipInfo.user_agent.length > 50 ? '...' : ''}
                </div>
                <div class="ip-details">
                    First seen: ${firstSeen.toLocaleString()}
                </div>
            </div>
            <div class="ip-stats">
                <div class="ip-count">${ipInfo.request_count} requests</div>
                <div class="ip-time">${timeAgo}</div>
            </div>
        `;
        container.appendChild(ipDiv);
    });
}

function filterIPs() {
    const searchTerm = document.getElementById('ip-search').value.toLowerCase();
    const ipItems = document.querySelectorAll('.ip-item');

    ipItems.forEach(item => {
        const ipText = item.textContent.toLowerCase();
        if (ipText.includes(searchTerm)) {
            item.style.display = 'flex';
        } else {
            item.style.display = 'none';
        }
    });
}

// Utility functions
function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    if (days > 0) return `${days}d ${hours}h ${minutes}m`;
    if (hours > 0) return `${hours}h ${minutes}m ${secs}s`;
    if (minutes > 0) return `${minutes}m ${secs}s`;
    return `${secs}s`;
}

function showAlert(type, message, id = null) {
    if (id && alertsShown.has(id)) return;
    if (id) alertsShown.add(id);

    const alertsContainer = document.getElementById('alerts-container');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.innerHTML = `
                ${message}
                <button style="float: right; background: none; border: none; font-size: 18px; cursor: pointer;" onclick="this.parentElement.remove()">×</button>
            `;
    alertsContainer.appendChild(alert);

    // Auto-remove after 10 seconds
    setTimeout(() => {
        if (alert.parentElement) {
            alert.remove();
        }
    }, 10000);
}

function updateCharts() {
    // Update request chart
    const currentRps = stats.requests_per_second ? stats.requests_per_second[stats.requests_per_second.length - 1] : 0;
    requestChart.data.datasets[0].data = stats.requests_per_second || Array(60).fill(0);
    requestChart.update('none');

    // Update error chart
    errorChart.data.datasets[0].data = stats.errors_per_second || Array(60).fill(0);
    errorChart.update('none');

    // Update performance chart
    const errorRate = stats.total_requests > 0 ? ((stats.total_errors / stats.total_requests) * 100) : 0;
    const successRate = 100 - errorRate;
    performanceChart.data.datasets[0].data = [
        stats.avg_response_time || 0,
        stats.total_requests || 0,
        successRate,
        currentRps
    ];
    performanceChart.update('none');
}

function updateSecurityEvents() {
    const container = document.getElementById('security-events');
    if (!stats.recent_security_events || stats.recent_security_events.length === 0) {
        container.innerHTML = '<div class="loading">No security events</div>';
        return;
    }

    container.innerHTML = '';
    stats.recent_security_events.slice().reverse().forEach(event => {
        const eventDiv = document.createElement('div');
        const eventClass = event.type.toLowerCase().includes('ddos') ? 'event-ddos' :
            event.type.toLowerCase().includes('suspicious') ? 'event-suspicious' :
                event.type.toLowerCase().includes('block') ? 'event-blocked' : 'event-info';

        eventDiv.className = `event-item ${eventClass}`;
        eventDiv.innerHTML = `
                    <strong>${event.type}</strong> from ${event.ip}
                    <div class="event-timestamp">${new Date(event.timestamp).toLocaleTimeString()}</div>
                    <div style="margin-top: 5px; font-size: 0.9em;">${event.details}</div>
                `;
        container.appendChild(eventDiv);
    });
}

function updateUI() {
    // Update status indicators
    document.getElementById('uptime').textContent = formatUptime(stats.uptime || 0);
    document.getElementById('total-requests').textContent = stats.total_requests || 0;
    document.getElementById('total-predictions').textContent = stats.total_predictions || 0;

    // Update metrics
    const currentRps = stats.requests_per_second ? stats.requests_per_second[stats.requests_per_second.length - 1] : 0;
    document.getElementById('current-rps').textContent = currentRps;

    const errorRate = stats.total_requests > 0 ? ((stats.total_errors / stats.total_requests) * 100).toFixed(1) : 0;
    document.getElementById('error-rate').textContent = errorRate + '%';

    document.getElementById('suspicious-count').textContent = stats.suspicious_ips_count || 0;
    document.getElementById('blocked-count').textContent = stats.blocked_ips_count || 0;
    document.getElementById('unique-ips').textContent = stats.unique_ips_count || 0; // NEW

    // Show alerts based on thresholds
    if (currentRps > 50) {
        showAlert('warning', `High request rate detected: ${currentRps} requests/second`, 'high-rps');
    }

    if (stats.suspicious_ips_count > 0) {
        showAlert('warning', `${stats.suspicious_ips_count} suspicious IP(s) detected`, 'suspicious-ips');
    }

    if (errorRate > 10) {
        showAlert('danger', `High error rate: ${errorRate}%`, 'high-error-rate');
    }
}


// API functions
async function fetchStats() {
    try {
        const response = await fetch('/api/dashboard/stats');
        stats = await response.json();
        updateUI();
        updateCharts();
        updateSecurityEvents();
        updateActiveIPs(); // NEW: Update active IPs display
    } catch (error) {
        console.error('Error fetching stats:', error);
        document.getElementById('server-status').textContent = 'ERROR';
        document.getElementById('server-status').className = 'status-value status-danger';
    }
}

async function blockIP() {
    const ip = document.getElementById('ip-input').value.trim();
    if (!ip) {
        showAlert('warning', 'Please enter an IP address');
        return;
    }

    try {
        const response = await fetch('/api/dashboard/block-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });

        const result = await response.json();
        if (result.success) {
            showAlert('success', result.message);
            document.getElementById('ip-input').value = '';
            fetchStats(); // Refresh stats
        } else {
            showAlert('danger', result.message);
        }
    } catch (error) {
        showAlert('danger', 'Error blocking IP');
    }
}

async function unblockIP() {
    const ip = document.getElementById('ip-input').value.trim();
    if (!ip) {
        showAlert('warning', 'Please enter an IP address');
        return;
    }

    try {
        const response = await fetch('/api/dashboard/unblock-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });

        const result = await response.json();
        if (result.success) {
            showAlert('success', result.message);
            document.getElementById('ip-input').value = '';
            fetchStats(); // Refresh stats
        } else {
            showAlert('danger', result.message);
        }
    } catch (error) {
        showAlert('danger', 'Error unblocking IP');
    }
}


async function whitelistIP() {
    const ip = document.getElementById('ip-input').value.trim();
    if (!ip) {
        showAlert('warning', 'Please enter an IP address');
        return;
    }

    // Prompt for password
    const password = prompt("Enter password to whitelist IP:");
    if (password !== '3177') {
        showAlert('danger', 'Incorrect password. Access denied.');
        return;
    }

    try {
        const response = await fetch('/api/dashboard/whitelist-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });

        const result = await response.json();
        if (result.success) {
            showAlert('success', result.message);
            document.getElementById('ip-input').value = '';
            fetchStats(); // Refresh stats
        } else {
            showAlert('danger', result.message);
        }
    } catch (error) {
        showAlert('danger', 'Error adding IP to whitelist');
    }
}


async function remove_whitelistIP() {
    const ip = document.getElementById('ip-input').value.trim();
    if (!ip) {
        showAlert('warning', 'Please enter an IP address');
        return;
    }

    try {
        const response = await fetch('/api/dashboard/remove-whitelist-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });

        const result = await response.json();
        if (result.success) {
            showAlert('success', result.message);
            document.getElementById('ip-input').value = '';
            fetchStats(); // Refresh stats
        } else {
            showAlert('danger', result.message);
        }
    } catch (error) {
        showAlert('danger', 'Error unblocking IP');
    }
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function () {
    // Initial load
    fetchStats();



    // Add Enter key support for IP input
    document.getElementById('ip-input').addEventListener('keypress', function (e) {
        if (e.key === 'Enter') {
            blockIP();
        }
    });

    console.log('Security Dashboard initialized');


    // More complete keyboard blocking
    document.addEventListener('keydown', function (e) {
        const blockedKeys = [
            { key: 123 }, // F12
            { ctrl: true, shift: true, key: 73 }, // Ctrl+Shift+I
            { ctrl: true, shift: true, key: 74 }, // Ctrl+Shift+J  
            { ctrl: true, shift: true, key: 67 }, // Ctrl+Shift+C
            { ctrl: true, key: 85 }, // Ctrl+U
            { ctrl: true, key: 83 }, // Ctrl+S
            { key: 116 }, // F5 (refresh)
        ];

        for (let blocked of blockedKeys) {
            if ((!blocked.ctrl || e.ctrlKey) &&
                (!blocked.shift || e.shiftKey) &&
                e.keyCode === blocked.key) {
                e.preventDefault();
                e.stopPropagation();
                return false;
            }
        }
    });

    // Also block right-click context menu
    document.addEventListener('contextmenu', function (e) {
        e.preventDefault();
        return false;
    });
});


