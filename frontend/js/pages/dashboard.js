// Dashboard Page Logic

// State
let devices = [];
let currentScanId = null;

// DOM Elements
const logoutBtn = document.getElementById('logoutBtn');
const totalDevicesEl = document.getElementById('totalDevices');
const activeDevicesEl = document.getElementById('activeDevices');
const highRiskDevicesEl = document.getElementById('highRiskDevices');
const criticalFindingsEl = document.getElementById('criticalFindings');
const networkInput = document.getElementById('networkInput');
const scanProfile = document.getElementById('scanProfile');
const startScanBtn = document.getElementById('startScanBtn');
const scanProgressContainer = document.getElementById('scanProgressContainer');
const scanStatus = document.getElementById('scanStatus');
const scanProgress = document.getElementById('scanProgress');
const progressFill = document.getElementById('progressFill');
const devicesTableBody = document.getElementById('devicesTableBody');
const refreshBtn = document.getElementById('refreshBtn');
const searchInput = document.getElementById('searchInput');
const wsStatusDot = document.getElementById('wsStatusDot');
const wsStatusText = document.getElementById('wsStatusText');
const findingsSummary = document.getElementById('findingsSummary');
const findingsList = document.getElementById('findingsList');

// Initialize
async function init() {
    // Connect WebSocket
    connectWebSocket();

    // Load initial data
    await loadDevices();
    await loadStats();

    // Setup event listeners
    setupEventListeners();
}

// Connect WebSocket
function connectWebSocket() {
    wsClient.connect();

    // Subscribe to WebSocket events
    wsClient.subscribe('connection_established', (data) => {
        console.log('Connected to WebSocket:', data);
    });

    wsClient.subscribe('scan_progress', handleScanProgress);
    wsClient.subscribe('device_discovered', handleDeviceDiscovered);
    wsClient.subscribe('port_found', handlePortFound);
    wsClient.subscribe('scan_complete', handleScanComplete);
    wsClient.subscribe('finding_detected', handleFindingDetected);

    // Listen for connection status changes
    window.addEventListener('wsConnectionChange', (e) => {
        if (e.detail.isConnected) {
            wsStatusDot.className = 'status-dot status-up';
            wsStatusText.textContent = 'Live updates connected';
        } else {
            wsStatusDot.className = 'status-dot status-down';
            wsStatusText.textContent = 'Live updates disconnected - reconnecting...';
        }
    });
}

// Setup event listeners
function setupEventListeners() {
    startScanBtn.addEventListener('click', startScan);
    refreshBtn.addEventListener('click', () => loadDevices());
    searchInput.addEventListener('input', filterDevices);
}

// Load devices
async function loadDevices() {
    try {
        devices = await apiClient.getDevices();
        renderDevicesTable(devices);
    } catch (error) {
        console.error('Failed to load devices:', error);
    }
}

// Load stats
async function loadStats() {
    try {
        const [devicesList, findingsSummaryData] = await Promise.all([
            apiClient.getDevices(),
            apiClient.getFindingsSummary()
        ]);

        // Update device stats
        totalDevicesEl.textContent = devicesList.length;
        activeDevicesEl.textContent = devicesList.filter(d => d.status === 'up').length;
        highRiskDevicesEl.textContent = devicesList.filter(d => d.risk_level === 'high' || d.risk_level === 'critical').length;

        // Update findings stats
        if (findingsSummaryData) {
            criticalFindingsEl.textContent = findingsSummaryData.critical_findings || 0;
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

// Render devices table
function renderDevicesTable(devicesList) {
    if (!devicesList || devicesList.length === 0) {
        devicesTableBody.innerHTML = `
            <tr>
                <td colspan="9" style="text-align: center; padding: 3rem; color: var(--text-secondary);">
                    No devices found. Start a scan to discover devices.
                </td>
            </tr>
        `;
        return;
    }

    devicesTableBody.innerHTML = devicesList.map(device => `
        <tr>
            <td>
                <span class="status-dot status-${device.status === 'up' ? 'up' : device.status === 'down' ? 'down' : 'unknown'}"></span>
            </td>
            <td style="color: var(--neon-cyan); font-weight: 600;">${device.ip_address}</td>
            <td>${device.hostname || '-'}</td>
            <td style="font-size: 0.85rem;">${device.mac_address || '-'}</td>
            <td>${device.vendor || '-'}</td>
            <td style="text-align: center;">
                <button class="btn btn-primary" style="padding: 0.25rem 0.75rem; font-size: 0.85rem;" onclick="scanDevice(${device.id})">
                    Scan Ports
                </button>
            </td>
            <td>
                <span class="badge badge-${device.risk_level}">${device.risk_level.toUpperCase()}</span>
            </td>
            <td style="font-size: 0.85rem;">${formatDate(device.last_seen)}</td>
            <td>
                <button class="btn btn-primary" style="padding: 0.25rem 0.75rem; font-size: 0.85rem;" onclick="viewDevice(${device.id})">
                    View
                </button>
            </td>
        </tr>
    `).join('');
}

// Filter devices
function filterDevices() {
    const query = searchInput.value.toLowerCase();
    const filtered = devices.filter(device =>
        device.ip_address.toLowerCase().includes(query) ||
        (device.hostname && device.hostname.toLowerCase().includes(query)) ||
        (device.vendor && device.vendor.toLowerCase().includes(query))
    );
    renderDevicesTable(filtered);
}

// Start scan
async function startScan() {
    const network = networkInput.value;
    const profile = scanProfile.value;

    if (!network) {
        alert('Please enter a network CIDR');
        return;
    }

    try {
        startScanBtn.disabled = true;
        startScanBtn.textContent = 'Scanning...';
        scanProgressContainer.style.display = 'block';
        progressFill.style.width = '0%';
        scanProgress.textContent = '0%';
        scanStatus.textContent = 'Starting scan...';

        await apiClient.startDiscoveryScan(network, profile);

    } catch (error) {
        console.error('Failed to start scan:', error);
        alert('Failed to start scan: ' + error.message);
        startScanBtn.disabled = false;
        startScanBtn.textContent = 'Start Scan';
        scanProgressContainer.style.display = 'none';
    }
}

// Scan specific device
async function scanDevice(deviceId) {
    try {
        const profile = scanProfile.value;
        await apiClient.scanDevicePorts(deviceId, profile);
        alert('Port scan started for device. Check live updates.');
    } catch (error) {
        console.error('Failed to scan device:', error);
        alert('Failed to start port scan: ' + error.message);
    }
}

// View device details
function viewDevice(deviceId) {
    window.location.href = `/device-detail.html?id=${deviceId}`;
}

// WebSocket Handlers
function handleScanProgress(data) {
    console.log('Scan progress:', data);
    currentScanId = data.scan_id;

    if (data.progress !== undefined) {
        progressFill.style.width = `${data.progress}%`;
        scanProgress.textContent = `${data.progress}%`;
    }

    if (data.message) {
        scanStatus.textContent = data.message;
    }
}

function handleDeviceDiscovered(data) {
    console.log('Device discovered:', data);

    // Add device to list if not exists
    const existingIndex = devices.findIndex(d => d.id === data.device.id);
    if (existingIndex === -1) {
        devices.push(data.device);
        renderDevicesTable(devices);
    }

    // Update stats
    loadStats();
}

function handlePortFound(data) {
    console.log('Port found:', data);
}

function handleScanComplete(data) {
    console.log('Scan complete:', data);

    scanStatus.textContent = data.message || 'Scan complete!';
    progressFill.style.width = '100%';
    scanProgress.textContent = '100%';

    setTimeout(() => {
        scanProgressContainer.style.display = 'none';
        startScanBtn.disabled = false;
        startScanBtn.textContent = 'Start Scan';
    }, 2000);

    // Refresh devices and stats
    loadDevices();
    loadStats();

    // Analyze findings
    analyzeFindings();
}

function handleFindingDetected(data) {
    console.log('Finding detected:', data);
    loadStats();
    showFinding(data.finding);
}

// Analyze findings after scan
async function analyzeFindings() {
    try {
        const result = await apiClient.analyzeFindings();
        console.log('Findings analysis result:', result);

        if (result.findings_created > 0) {
            alert(`Found ${result.findings_created} new security findings!`);
            loadFindings();
        }
    } catch (error) {
        console.error('Failed to analyze findings:', error);
    }
}

// Load and show findings
async function loadFindings() {
    try {
        const findings = await apiClient.getFindings({ acknowledged: false, limit: 5 });

        if (findings && findings.length > 0) {
            findingsSummary.style.display = 'block';
            findingsList.innerHTML = findings.map(f => `
                <div style="padding: 0.75rem; background: var(--bg-tertiary); border-left: 3px solid var(--risk-${f.severity}); margin-bottom: 0.75rem; border-radius: 4px;">
                    <div style="display: flex; justify-content: space-between; align-items: start;">
                        <div>
                            <span class="badge badge-${f.severity}">${f.severity}</span>
                            <strong style="color: var(--neon-cyan); margin-left: 0.5rem;">${f.title}</strong>
                        </div>
                    </div>
                    <p style="color: var(--text-secondary); font-size: 0.85rem; margin-top: 0.5rem;">${f.description}</p>
                </div>
            `).join('');
        }
    } catch (error) {
        console.error('Failed to load findings:', error);
    }
}

function showFinding(finding) {
    // Show toast or notification
    console.log('New finding:', finding);
}

// Utility: Format date
function formatDate(dateStr) {
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now - date;

    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return date.toLocaleDateString();
}

// Make functions global for onclick handlers
window.scanDevice = scanDevice;
window.viewDevice = viewDevice;

// Initialize on load
init();
