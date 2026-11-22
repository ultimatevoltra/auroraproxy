// ============================================================================
// /api/health — health check
// ----------------------------------------------------------------------------
// FIX (FUNCTION_INVOCATION_TIMEOUT): the previous version used
//   export default function handler(req,res){ return new Response(...) }
// whose return value Vercel ignores, so the request hung for 60s and aborted.
// Now we export a Web-standard `GET` that returns a real Response, add an 8s
// AbortController on the upstream call, and set maxDuration so the function
// never exceeds the platform budget.
// ============================================================================

export const maxDuration = 60;

const UPSTREAM_TIMEOUT_MS = 8000;

async function fetchJson(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "auroraproxy-health" },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    return undefined; // timeout or network error -> mark upstream as down
  } finally {
    clearTimeout(timer);
  }
}

export async function GET(request) {
  const uptime = process.uptime?.() ?? null;

  let upstream = null;
  try {
    const j = await fetchJson("https://api.ipify.org?format=json");
    upstream = j && typeof j === "object" && j.ip ? j.ip : null;
  } catch {
    upstream = null;
  }

  const body = {
    status: "ok",
    service: "auroraproxy",
    version: "1.0.0",
    uptime_seconds: uptime ? Math.round(uptime) : null,
    upstream: upstream ? { ip: upstream } : { reachable: false },
    timestamp: new Date().toISOString(),
  };

  const isDown = upstream === undefined || upstream === null;
  return new Response(JSON.stringify(body), {
    status: isDown ? 503 : 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "*",
    },
  });
}

export function OPTIONS() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "*",
    },
  });
}
