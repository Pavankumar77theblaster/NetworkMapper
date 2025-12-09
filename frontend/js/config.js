// API Configuration
const CONFIG = {
    API_BASE_URL: 'http://localhost:8000',
    WS_URL: 'ws://localhost:8000/ws',

    ENDPOINTS: {
        // Auth
        LOGIN: '/api/auth/login',
        REGISTER: '/api/auth/register',
        ME: '/api/auth/me',

        // Devices
        DEVICES: '/api/devices',
        DEVICE_BY_ID: (id) => `/api/devices/${id}`,
        DEVICE_PORTS: (id) => `/api/devices/${id}/ports`,

        // Scans
        SCANS: '/api/scans',
        SCAN_DISCOVERY: '/api/scans/discovery',
        SCAN_DEVICE_PORTS: (id) => `/api/scans/device/${id}/ports`,
        SCAN_BY_ID: (id) => `/api/scans/${id}`,

        // Findings
        FINDINGS: '/api/findings',
        FINDING_BY_ID: (id) => `/api/findings/${id}`,
        ACKNOWLEDGE_FINDING: (id) => `/api/findings/${id}/acknowledge`,
        FINDINGS_SUMMARY: '/api/findings/stats/summary',
        ANALYZE_FINDINGS: '/api/findings/analyze',

        // Topology
        TOPOLOGY: '/api/topology',

        // Export
        EXPORT_JSON: '/api/export/devices/json',
        EXPORT_CSV: '/api/export/devices/csv',
        EXPORT_HTML: '/api/export/report/html',

        // Health
        HEALTH: '/api/health'
    },

    // Local Storage Keys
    STORAGE_KEYS: {
        ACCESS_TOKEN: 'access_token',
        REFRESH_TOKEN: 'refresh_token',
        USER: 'user'
    }
};
