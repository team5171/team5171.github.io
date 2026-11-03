/**
 * Team 5171 Accounts — OAuth & Sandboxed Data Gateway Client SDK
 * FRC Team 5171 — Deus Ex Machina
 */

export class Team5171Client {
    /**
     * @param {Object} options
     * @param {string} [options.accountsUrl] - Accounts Portal URL (default: https://accounts.team5171.com)
     * @param {string} [options.gatewayUrl] - Cloudflare Worker Gateway URL
     * @param {string} options.clientId - Registered app client ID (e.g., 'go_dashboard', 'scouting_app')
     * @param {string} [options.clientSecret] - Registered client secret
     * @param {string} [options.redirectUri] - OAuth callback redirect URL
     * @param {string} [options.storageKey] - localStorage key prefix
     */
    constructor(options = {}) {
        this.accountsUrl = (options.accountsUrl || 'https://accounts.team5171.com').replace(/\/+$/, '');
        this.gatewayUrl = (options.gatewayUrl || 'https://team5171-auth-gateway.yorkroboticsfrc.workers.dev').replace(/\/+$/, '');
        this.clientId = options.clientId || 'app';
        this.clientSecret = options.clientSecret || '';
        this.redirectUri = options.redirectUri || (typeof window !== 'undefined' ? `${window.location.origin}${window.location.pathname}` : '');
        this.storageKey = options.storageKey || 'team5171_auth';
    }

    /**
     * Store auth data in localStorage
     */
    _saveSession(session) {
        if (typeof window === 'undefined') return;
        localStorage.setItem(this.storageKey, JSON.stringify(session));
    }

    /**
     * Get stored auth session
     * @returns {Object|null}
     */
    getSession() {
        if (typeof window === 'undefined') return null;
        try {
            const raw = localStorage.getItem(this.storageKey);
            if (!raw) return null;
            const session = JSON.parse(raw);
            if (session.expires_at && Date.now() > session.expires_at) {
                this.logout();
                return null;
            }
            return session;
        } catch {
            return null;
        }
    }

    /**
     * Check if currently authenticated
     * @returns {boolean}
     */
    isAuthenticated() {
        return !!this.getSession()?.access_token;
    }

    /**
     * Get current user details
     * @returns {Object|null}
     */
    getUser() {
        const session = this.getSession();
        if (!session) return null;
        return {
            userId: session.user_id,
            appId: session.app_id,
            name: session.user_name || session.name || session.displayName || '',
            email: session.user_email || session.email || ''
        };
    }

    /**
     * Get current access token
     * @returns {string|null}
     */
    getAccessToken() {
        return this.getSession()?.access_token || null;
    }

    /**
     * Redirect to the Team 5171 Accounts portal for sign in
     * @param {Object} [params]
     * @param {string} [params.state] - Optional CSRF/route state
     * @param {string} [params.redirectUri] - Custom redirect URI
     */
    login(params = {}) {
        if (typeof window === 'undefined') return;

        const redirectUri = params.redirectUri || this.redirectUri;
        const state = params.state || Math.random().toString(36).substring(2, 15);
        sessionStorage.setItem(`${this.storageKey}_oauth_state`, state);

        const url = new URL(this.accountsUrl);
        url.searchParams.set('client_id', this.clientId);
        url.searchParams.set('redirect_uri', redirectUri);
        url.searchParams.set('state', state);

        window.location.href = url.toString();
    }

    /**
     * Handle the OAuth redirect callback with authorization code
     * @param {string} [code] - Optional manual code string
     * @returns {Promise<Object>} The session object
     */
    async handleCallback(code = null) {
        if (typeof window === 'undefined') throw new Error('Browser environment required');

        const params = new URLSearchParams(window.location.search);
        const authCode = code || params.get('code');
        const state = params.get('state');

        if (!authCode) {
            throw new Error('No authorization code found in URL query parameters.');
        }

        const savedState = sessionStorage.getItem(`${this.storageKey}_oauth_state`);
        if (savedState && state && savedState !== state) {
            console.warn('[Team5171Auth] OAuth state mismatch. Continuing cautiously.');
        }
        sessionStorage.removeItem(`${this.storageKey}_oauth_state`);

        // Exchange code for token with Worker Gateway
        const res = await fetch(`${this.gatewayUrl}/oauth/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                client_id: this.clientId,
                client_secret: this.clientSecret,
                code: authCode
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({ message: res.statusText }));
            throw new Error(err.message || 'Token exchange failed');
        }

        const data = await res.json();
        const session = {
            access_token: data.access_token,
            token_type: data.token_type || 'Bearer',
            expires_at: Date.now() + (data.expires_in || 3600) * 1000,
            user_id: data.user_id,
            app_id: data.app_id || this.clientId,
            user_name: data.user_name || data.name || '',
            user_email: data.user_email || data.email || ''
        };

        // Try extracting info from JWT if name/email weren't in top level response
        if (!session.user_name && data.access_token) {
            try {
                const payloadPart = data.access_token.split('.')[1];
                if (payloadPart) {
                    const payload = JSON.parse(atob(payloadPart));
                    session.user_name = payload.name || payload.user_name || '';
                    session.user_email = payload.email || payload.user_email || '';
                    if (!session.user_id && payload.sub) session.user_id = payload.sub;
                }
            } catch (_) { }
        }

        this._saveSession(session);
        return session;
    }

    /**
     * Load sandboxed data for current app and user
     * @returns {Promise<Object>} Firestore document response
     */
    async loadUserData() {
        const token = this.getAccessToken();
        if (!token) throw new Error('User is not authenticated.');

        const res = await fetch(`${this.gatewayUrl}/api/load`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({ message: res.statusText }));
            throw new Error(err.message || 'Failed to load user data');
        }

        return await res.json();
    }

    /**
     * Save sandboxed data for current app and user
     * @param {Object} documentPayload - e.g. { fields: { ... } }
     * @returns {Promise<Object>}
     */
    async saveUserData(documentPayload) {
        const token = this.getAccessToken();
        if (!token) throw new Error('User is not authenticated.');

        const res = await fetch(`${this.gatewayUrl}/api/save`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(documentPayload)
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({ message: res.statusText }));
            throw new Error(err.message || 'Failed to save user data');
        }

        return await res.json();
    }

    /**
     * Logout and remove stored credentials
     */
    logout() {
        if (typeof window === 'undefined') return;
        localStorage.removeItem(this.storageKey);
    }
}

if (typeof window !== 'undefined') {
    window.Team5171Client = Team5171Client;
}

