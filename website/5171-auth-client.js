// Team 5171 Accounts — OAuth & Sandboxed Data Gateway Client SDK
class Team5171Client {
    /**
     * @param {Object} options
     * @param {string} [options.accountsUrl] - Accounts Portal URL
     * @param {string} [options.gatewayUrl] - Cloudflare Worker Gateway URL
     * @param {string} options.clientId - Registered app client ID
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

    _saveSession(session) {
        if (typeof window === 'undefined') return;
        try {
            localStorage.setItem(this.storageKey, JSON.stringify(session));
        } catch (e) {
            console.warn('[Team5171Auth] Failed to write localStorage:', e);
        }
    }

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

    isAuthenticated() {
        return !!this.getSession()?.access_token;
    }

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

    getAccessToken() {
        return this.getSession()?.access_token || null;
    }

    login(params = {}) {
        if (typeof window === 'undefined') return;

        const redirectUri = params.redirectUri || this.redirectUri;
        const state = params.state || Math.random().toString(36).substring(2, 15);
        try {
            sessionStorage.setItem(`${this.storageKey}_oauth_state`, state);
        } catch (_) {}

        const url = new URL(this.accountsUrl);
        url.searchParams.set('client_id', this.clientId);
        url.searchParams.set('redirect_uri', redirectUri);
        url.searchParams.set('state', state);

        window.location.href = url.toString();
    }

    async handleCallback(code = null) {
        if (typeof window === 'undefined') throw new Error('Browser environment required');

        const params = new URLSearchParams(window.location.search);
        const authCode = code || params.get('code');
        const state = params.get('state');

        if (!authCode) {
            throw new Error('No authorization code found');
        }

        try {
            const savedState = sessionStorage.getItem(`${this.storageKey}_oauth_state`);
            sessionStorage.removeItem(`${this.storageKey}_oauth_state`);
        } catch (_) {}

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

        if (!session.user_name && data.access_token) {
            try {
                const payloadPart = data.access_token.split('.')[1];
                if (payloadPart) {
                    const payload = JSON.parse(atob(payloadPart));
                    session.user_name = payload.name || payload.user_name || '';
                    session.user_email = payload.email || payload.user_email || '';
                    if (!session.user_id && payload.sub) session.user_id = payload.sub;
                }
            } catch (_) {}
        }

        this._saveSession(session);
        return session;
    }

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

    logout() {
        if (typeof window === 'undefined') return;
        try {
            localStorage.removeItem(this.storageKey);
        } catch (_) {}
    }
}

if (typeof window !== 'undefined') {
    window.Team5171Client = Team5171Client;
}
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { Team5171Client };
}

