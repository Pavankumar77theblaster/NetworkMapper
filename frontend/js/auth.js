// Authentication Module

class Auth {
    constructor() {
        this.accessToken = this.getAccessToken();
        this.refreshToken = this.getRefreshToken();
        this.user = this.getUser();
    }

    // Store tokens in localStorage
    setTokens(accessToken, refreshToken) {
        localStorage.setItem(CONFIG.STORAGE_KEYS.ACCESS_TOKEN, accessToken);
        localStorage.setItem(CONFIG.STORAGE_KEYS.REFRESH_TOKEN, refreshToken);
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    // Get access token
    getAccessToken() {
        return localStorage.getItem(CONFIG.STORAGE_KEYS.ACCESS_TOKEN);
    }

    // Get refresh token
    getRefreshToken() {
        return localStorage.getItem(CONFIG.STORAGE_KEYS.REFRESH_TOKEN);
    }

    // Store user info
    setUser(user) {
        localStorage.setItem(CONFIG.STORAGE_KEYS.USER, JSON.stringify(user));
        this.user = user;
    }

    // Get user info
    getUser() {
        const userStr = localStorage.setItem(CONFIG.STORAGE_KEYS.USER);
        return userStr ? JSON.parse(userStr) : null;
    }

    // Check if user is authenticated
    isAuthenticated() {
        return !!this.accessToken;
    }

    // Login
    async login(username, password) {
        try {
            const response = await fetch(`${CONFIG.API_BASE_URL}${CONFIG.ENDPOINTS.LOGIN}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Login failed');
            }

            const data = await response.json();
            this.setTokens(data.access_token, data.refresh_token);

            // Fetch user info
            await this.fetchUserInfo();

            return { success: true };
        } catch (error) {
            console.error('Login error:', error);
            return { success: false, error: error.message };
        }
    }

    // Register
    async register(username, email, password) {
        try {
            const response = await fetch(`${CONFIG.API_BASE_URL}${CONFIG.ENDPOINTS.REGISTER}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, email, password })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Registration failed');
            }

            const user = await response.json();
            return { success: true, user };
        } catch (error) {
            console.error('Registration error:', error);
            return { success: false, error: error.message };
        }
    }

    // Fetch user info
    async fetchUserInfo() {
        try {
            const response = await fetch(`${CONFIG.API_BASE_URL}${CONFIG.ENDPOINTS.ME}`, {
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to fetch user info');
            }

            const user = await response.json();
            this.setUser(user);
            return user;
        } catch (error) {
            console.error('Fetch user info error:', error);
            return null;
        }
    }

    // Logout
    logout() {
        localStorage.removeItem(CONFIG.STORAGE_KEYS.ACCESS_TOKEN);
        localStorage.removeItem(CONFIG.STORAGE_KEYS.REFRESH_TOKEN);
        localStorage.removeItem(CONFIG.STORAGE_KEYS.USER);
        this.accessToken = null;
        this.refreshToken = null;
        this.user = null;
        window.location.href = '/index.html';
    }

    // Redirect to login if not authenticated
    redirectIfNotAuth() {
        if (!this.isAuthenticated()) {
            window.location.href = '/index.html';
            return true;
        }
        return false;
    }

    // Redirect to dashboard if authenticated
    redirectIfAuth() {
        if (this.isAuthenticated()) {
            window.location.href = '/dashboard.html';
            return true;
        }
        return false;
    }
}

// Create global auth instance
const auth = new Auth();
