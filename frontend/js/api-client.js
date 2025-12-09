// API Client with Authentication

class APIClient {
    constructor() {
        this.baseURL = CONFIG.API_BASE_URL;
    }

    // Get auth headers
    getHeaders(includeAuth = true) {
        const headers = {
            'Content-Type': 'application/json'
        };

        if (includeAuth && auth.accessToken) {
            headers['Authorization'] = `Bearer ${auth.accessToken}`;
        }

        return headers;
    }

    // Generic request method
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            ...options,
            headers: this.getHeaders(options.auth !== false)
        };

        try {
            const response = await fetch(url, config);

            // Handle 401 Unauthorized
            if (response.status === 401) {
                auth.logout();
                return null;
            }

            // Handle errors
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Request failed');
            }

            // Handle 204 No Content
            if (response.status === 204) {
                return null;
            }

            return await response.json();
        } catch (error) {
            console.error('API request error:', error);
            throw error;
        }
    }

    // GET request
    async get(endpoint, options = {}) {
        return this.request(endpoint, { method: 'GET', ...options });
    }

    // POST request
    async post(endpoint, data, options = {}) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data),
            ...options
        });
    }

    // PUT request
    async put(endpoint, data, options = {}) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data),
            ...options
        });
    }

    // DELETE request
    async delete(endpoint, options = {}) {
        return this.request(endpoint, { method: 'DELETE', ...options });
    }

    // --- Device Methods ---
    async getDevices(filters = {}) {
        const params = new URLSearchParams(filters);
        return this.get(`${CONFIG.ENDPOINTS.DEVICES}?${params}`);
    }

    async getDevice(id) {
        return this.get(CONFIG.ENDPOINTS.DEVICE_BY_ID(id));
    }

    async updateDevice(id, data) {
        return this.put(CONFIG.ENDPOINTS.DEVICE_BY_ID(id), data);
    }

    async deleteDevice(id) {
        return this.delete(CONFIG.ENDPOINTS.DEVICE_BY_ID(id));
    }

    async getDevicePorts(id) {
        return this.get(CONFIG.ENDPOINTS.DEVICE_PORTS(id));
    }

    // --- Scan Methods ---
    async startDiscoveryScan(network, profile = 'standard', methods = ['arp', 'nmap']) {
        return this.post(CONFIG.ENDPOINTS.SCAN_DISCOVERY, { network, profile, methods });
    }

    async scanDevicePorts(deviceId, profile = 'standard') {
        return this.post(CONFIG.ENDPOINTS.SCAN_DEVICE_PORTS(deviceId), { profile });
    }

    async getScan(scanId) {
        return this.get(CONFIG.ENDPOINTS.SCAN_BY_ID(scanId));
    }

    async getScans() {
        return this.get(CONFIG.ENDPOINTS.SCANS);
    }

    // --- Findings Methods ---
    async getFindings(filters = {}) {
        const params = new URLSearchParams(filters);
        return this.get(`${CONFIG.ENDPOINTS.FINDINGS}?${params}`);
    }

    async getFinding(id) {
        return this.get(CONFIG.ENDPOINTS.FINDING_BY_ID(id));
    }

    async acknowledgeFinding(id, isAcknowledged = true) {
        return this.put(CONFIG.ENDPOINTS.ACKNOWLEDGE_FINDING(id), { is_acknowledged: isAcknowledged });
    }

    async getFindingsSummary() {
        return this.get(CONFIG.ENDPOINTS.FINDINGS_SUMMARY);
    }

    async analyzeFindings() {
        return this.post(CONFIG.ENDPOINTS.ANALYZE_FINDINGS);
    }

    // --- Health Check ---
    async healthCheck() {
        return this.get(CONFIG.ENDPOINTS.HEALTH, { auth: false });
    }
}

// Create global API client instance
const apiClient = new APIClient();
