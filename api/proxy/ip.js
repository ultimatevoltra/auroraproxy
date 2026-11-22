// ============================================================================
// /api/proxy/ip — current egress IP (fresh rotating exit)
// ----------------------------------------------------------------------------
// FIX (FUNCTION_INVOCATION_TIMEOUT): the previous version used
//   export default function handler(req,res){ return new Response(...) }
// whose return value Vercel ignores, so the request hung for 60s and aborted.
// Now we export a Web-standard `GET` returning a proper Response, add an 8s
// AbortController on the upstream fetch with a 504 on timeout, and set
// maxDuration.
// ============================================================================

export const maxDuration = 60;

const UPSTREAM_TIMEOUT_MS = 8000;

async function fetchWithTimeout(url, init = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

export async function GET(request) {
  try {
    const res = await fetchWithTimeout("https://api.ipify.org?format=json", {
      headers: { "User-Agent": "auroraproxy-ip" },
    });
    if (!res.ok) {
      return jsonError(`upstream HTTP ${res.status}`, 502);
    }
    const data = await res.json();
    return new Response(JSON.stringify({ ok: true, ip: data.ip }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "*",
      },
    });
  } catch (e) {
    // AbortError (timeout) or network failure -> 504 as requested
    const aborted = e && (e.name === "AbortError");
    return jsonError(aborted ? "upstream timed out" : "upstream unreachable", 504);
  }
}

function jsonError(message, status) {
  return new Response(JSON.stringify({ ok: false, error: message }), {
    status,
    headers: {
      "Content-Type": "application/json",
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
