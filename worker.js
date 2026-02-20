const ALLOWED_DOMAIN = "team5171.com";

function getCorsHeaders(origin) {
    if (!origin) return { "Access-Control-Allow-Origin": "*" };

    const allow =
        origin === `https://${ALLOWED_DOMAIN}` ||
        origin.endsWith(`.${ALLOWED_DOMAIN}`) ||
        origin.startsWith("http://localhost") ||
        origin.startsWith("http://127.0.0.1") ||
        origin.startsWith("http://[::]");

    return {
        "Access-Control-Allow-Origin": allow ? origin : `https://${ALLOWED_DOMAIN}`,
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };
}

export default {
    async fetch(request) {
        const origin = request.headers.get("Origin");
        const corsHeaders = getCorsHeaders(origin);

        // Always handle OPTIONS first
        if (request.method === "OPTIONS") {
            return new Response(null, { headers: corsHeaders });
        }

        const url = new URL(request.url);

        // Calendar endpoint
        if (url.pathname === "/calendar") {
            try {
                const icalUrl = "https://api2.luma.com/ics/get?entity=calendar&id=cal-TNDo0jyDZ2iF1yJ";
                const res = await fetch(icalUrl);
                const text = await res.text();

                return new Response(text, {
                    headers: {
                        ...corsHeaders,
                        "Content-Type": "text/calendar; charset=utf-8",
                        "Cache-Control": "public, max-age=300",
                    },
                });
            } catch {
                return new Response("Failed to fetch calendar", { status: 500, headers: corsHeaders });
            }
        }

        // Check-in endpoint
        if (url.pathname === "/checkin") {
            const slug = url.searchParams.get("slug");
            if (!slug) return new Response("Missing slug", { status: 400, headers: corsHeaders });

            try {
                const res = await fetch(`https://luma.com/${slug}`, {
                    headers: { "User-Agent": "Mozilla/5.0" },
                    cf: { cacheTtl: 300 },
                });
                const html = await res.text();
                const match = html.match(/evt-[A-Za-z0-9]{10,}/);

                if (!match) return new Response("Event ID not found", { status: 404, headers: corsHeaders });

                const checkInUrl = `https://luma.com/check-in/${match[0]}`;
                return new Response(JSON.stringify({ checkInUrl }), {
                    headers: { ...corsHeaders, "Content-Type": "application/json" },
                });
            } catch {
                return new Response("Error resolving event", { status: 500, headers: corsHeaders });
            }
        }

        // Default
        return new Response("OK", { headers: corsHeaders });
    },
};