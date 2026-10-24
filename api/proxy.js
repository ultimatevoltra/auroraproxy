// ============================================================================
// AuroraProxy — Vercel Serverless Function (rotating-exit proxy gateway)
// ----------------------------------------------------------------------------
// Decodes the proxyium rotating-exit flow (which wraps CroxyProxy) and
// re-implements it server-side so the web console + API can fetch ANY target
// through a fresh rotating exit, returning REAL upstream content.
//
// RUNTIME-NEUTRAL: uses only Web-standard globals (fetch, atob/btoa, TextDecoder,
// Uint8Array, AbortController) so it runs on BOTH the Vercel Node runtime AND
// the Vercel Edge runtime with no Buffer/Node-isms.
//
// API surface:
//   GET/POST /api/proxy?url=...&country=...&mode=auto|text|json|base64|stream
//   GET       /api/proxy/ip   -> current egress IP (fresh rotating exit)
//   GET       /api/ip         -> alias of above
//   GET       /api/health
//   GET       /api/version
//   GET       /api/stats
// ----------------------------------------------------------------------------

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Expose-Headers": "*",
  "Access-Control-Max-Age": "86400",
};

const GUA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

const PRX_SIGNUP = "https://cdn.proxyium.com/proxyrequest.php";

const BINARY_CT = [
  "image/", "video/", "audio/", "application/octet-stream", "application/pdf",
  "application/zip", "application/x-zip", "application/x-rar-compressed",
  "application/x-7z-compressed", "application/gzip", "application/x-tar", "font/",
];

function atobSafe(b64) {
  let s = String(b64).replace(/\s+/g, "");
  while (s.length % 4) s += "=";
  if (typeof atob === "function") return atob(s);
  return Buffer.from(s, "base64").toString("latin1");
}

function btoaSafe(str) {
  if (typeof btoa === "function") return btoa(str);
  return Buffer.from(str, "binary").toString("base64");
}

function b64Url(str) {
  return btoaSafe(unescape(encodeURIComponent(str)));
}

function hexDecode(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  if (clean.length % 2 !== 0) throw new Error("shield hex odd");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  return new TextDecoder("latin1").decode(bytes);
}

function bytesToBase64(bytes) {
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoaSafe(binary);
}

function utf8ToBase64(str) {
  const bytes = new TextEncoder().encode(str);
  return bytesToBase64(bytes);
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

function isBinary(ct) {
  if (!ct) return false;
  const lower = ct.toLowerCase();
  return BINARY_CT.some((p) => lower.startsWith(p));
}

function randomUA() {
  const oses = [
    "Windows NT 10.0; Win64; x64",
    "Macintosh; Intel Mac OS X 10_15_7",
    "X11; Linux x86_64",
    "Linux; Android 13; SM-S918B",
    "Linux; Android 14; Pixel 8",
  ];
  const brs = ["Chrome/120.0.0.0", "Chrome/124.0.0.0", "Chrome/126.0.0.0", "Chrome/128.0.0.0"];
  const os = oses[Math.floor(Math.random() * oses.length)];
  const br = brs[Math.floor(Math.random() * brs.length)];
  return "Mozilla/5.0 (" + os + ") AppleWebKit/537.36 (KHTML, like Gecko) " + br + " Safari/537.36";
}

function authorized(request, env) {
  const token = (env.API_TOKEN || "").trim();
  if (!token) return true;
  const url = new URL(request.url);
  const auth = request.headers.get("Authorization") || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  const q = (url.searchParams.get("token") || "").trim();
  return bearer === token || q === token;
}

function decodeShield(b64) {
  const raw = atobSafe(b64);
  const js = hexDecode(raw);
  const m = js.match(/location\.href\s*=\s*['"]([^'"]+)['"]/);
  if (!m) throw new Error("no redirect in shield");
  return m[1];
}

function parseCookies(setCookieHeader, targetNames) {
  const jar = {};
  if (!setCookieHeader) return jar;
  const names = targetNames || ["__cpc", "__cpcPopShown"];
  const parts = setCookieHeader.split(/,(?=\s*[A-Za-z0-9_-]+=)/);
  for (const part of parts) {
    const first = part.split(";")[0];
    const eq = first.indexOf("=");
    if (eq === -1) continue;
    const name = first.slice(0, eq).trim();
    let value = first.slice(eq + 1).trim();
    if (names.includes(name) && value) {
      if (!jar[name]) jar[name] = value;
    }
  }
  return jar;
}

async function launchExit(target, cc, timeoutMs) {
  const body = new URLSearchParams({
    type: "",
    proxy_country: cc || "",
    url: target,
  });
  const r1 = await fetch(PRX_SIGNUP, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: "https://proxyium.com",
      Referer: "https://proxyium.com/",
      "User-Agent": randomUA(),
    },
    body: body.toString(),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (r1.status !== 200) throw new Error("signup status " + r1.status);
  const html = await r1.text();
  const m = html.match(/atob\('([^']+)'\)/);
  if (!m) throw new Error("signup shield missing");
  const cpi = decodeShield(m[1]);
  const nodeMatch = cpi.match(/https:\/\/[^/]+/);
  const node = nodeMatch ? nodeMatch[0] : "";

  const r2 = await fetch(cpi, {
    headers: {
      "User-Agent": randomUA(),
      Referer: "https://proxyium.com/",
      Accept: "text/html,application/xhtml+xml,*/*;q=0.8",
    },
    redirect: "manual",
    signal: AbortSignal.timeout(timeoutMs),
  });
  const page2 = await r2.text();
  const jar = parseCookies(r2.headers.get("set-cookie") || "", ["__cpc", "__cpcPopShown"]);
  const cpc = jar.__cpc || "";
  if (!cpc) throw new Error("no __cpc cookie from exit");

  let finalUrl = "";
  const dm = page2.match(/data-r=["']([^"']+)["']/);
  if (dm) {
    try { finalUrl = atobSafe(dm[1]); } catch (_) {}
  }
  if (!finalUrl) {
    let u;
    try { u = new URL(target); } catch (_) { throw new Error("invalid target"); }
    const origin = u.protocol + "//" + u.host;
    finalUrl = node + u.pathname + (u.search || "") +
      (u.search ? "&" : "?") + "__cpo=" + b64Url(origin);
  }

  return { node, cpi, cpc, finalUrl };
}

async function fetchThroughExit(exit, signal, range) {
  const r = await fetch(exit.finalUrl, {
    method: "GET",
    headers: {
      "User-Agent": randomUA(),
      Accept: "*/*",
      Referer: "https://proxyium.com/",
      Cookie: "__cpc=" + encodeURIComponent(exit.cpc),
      ...(range ? { Range: range } : {}),
    },
    redirect: "follow",
    signal,
  });
  const bytes = new Uint8Array(await r.arrayBuffer());
  const headers = {};
  for (const [k, v] of r.headers.entries()) headers[k] = v;
  return { code: r.status, headers, bytes };
}

async function proxyBuffered(target, cc, env) {
  const timeoutMs = env.PROXY_TIMEOUT ? parseInt(env.PROXY_TIMEOUT, 10) : 30000;
  let lastErr = "";
  for (let attempt = 0; attempt < 3; attempt++) {
    const t0 = Date.now();
    try {
      const exit = await launchExit(target, cc, 20000);
      const res = await fetchThroughExit(exit, AbortSignal.timeout(timeoutMs));
      const elapsed = Date.now() - t0;
      if (res.code >= 500 || res.code === 0) {
        lastErr = "gateway " + res.code;
        continue;
      }
      const ct = (res.headers["content-type"] || res.headers["Content-Type"] || "").toLowerCase();
      return {
        ok: true,
        code: res.code,
        ct,
        bytes: res.bytes,
        headers: res.headers,
        elapsed_ms: elapsed,
        node: exit.node,
        ip: exit.node.replace(/^https?:\/\//, ""),
        via_proxy: true,
      };
    } catch (e) {
      lastErr = e && e.message ? e.message : String(e);
    }
  }
  return { ok: false, err: lastErr || "gateway unreachable" };
}

async function proxyDirect(target, timeoutMs) {
  const t0 = Date.now();
  try {
    const r = await fetch(target, {
      headers: { "User-Agent": GUA, Accept: "*/*" },
      redirect: "follow",
      signal: AbortSignal.timeout(timeoutMs),
    });
    const bytes = new Uint8Array(await r.arrayBuffer());
    const ct = (r.headers.get("content-type") || "").toLowerCase();
    const headers = {};
    for (const [k, v] of r.headers.entries()) headers[k] = v;
    return { ok: true, code: r.status, ct, bytes, headers, elapsed_ms: Date.now() - t0, via_proxy: false };
  } catch (e) {
    return { ok: false, err: e && e.message ? e.message : String(e) };
  }
}

function isJsonLike(text, ct) {
  if (ct && ct.includes("json")) return true;
  const t = text.trim();
  return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"));
}

export default async function handler(request, context) {
  const env = (context && context.env) ? context.env : {};
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }
  try {
    return await route(request, env);
  } catch (e) {
    return json({ ok: false, error: e && e.message ? e.message : String(e), code: 500 }, 500);
  }
}

async function route(request, env) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  if (pathname === "/api/health") {
    return json({ status: "ok", version: "1.0.0", timestamp: new Date().toISOString() });
  }
  if (pathname === "/api/version") {
    return json({ version: "1.0.1", name: "auroraproxy", engine: "vercel-serverless-rotating-exit" });
  }
  if (pathname === "/api/stats") {
    return json({ status: "ok", engine: "rotating-exit", note: "stateless on serverless" });
  }

  if (pathname === "/api/proxy/ip" || pathname === "/api/ip") {
    const cc = (url.searchParams.get("country") || "").trim();
    const t0 = Date.now();
    try {
      const exit = await launchExit("https://api.ipify.org?format=json", cc, 20000);
      return json({
        ok: true,
        proxy_country: cc || "auto",
        ip: exit.node.replace(/^https?:\/\//, ""),
        user_agent: randomUA(),
        elapsed_ms: Date.now() - t0,
        note: "Egress IP of the rotating node, not your own IP.",
      });
    } catch (e) {
      return json({ ok: false, error: e && e.message ? e.message : String(e), code: 502 }, 502);
    }
  }

  if (pathname !== "/api/proxy") {
    return json({ ok: false, error: "Endpoint not found", code: 404 }, 404);
  }
  if (!authorized(request, env)) {
    return json({ ok: false, error: "unauthorized", code: 401 }, 401);
  }

  let params = {};
  for (const k of ["url", "country", "mode", "method", "timeout", "gateway", "headers", "body"]) {
    const v = url.searchParams.get(k);
    if (v !== null) { params[k] = v; }
  }
  if (request.method === "POST" || request.method === "PUT" || request.method === "PATCH") {
    const ct = request.headers.get("Content-Type") || "";
    if (ct.includes("application/json")) {
      try {
        const j = await request.json();
        if (j && typeof j === "object") params = { ...params, ...j };
      } catch (_) {}
    } else if (ct.includes("application/x-www-form-urlencoded")) {
      try {
        const f = await request.formData();
        for (const [k, v] of f.entries()) params[k] = v;
      } catch (_) {}
    }
  }

  let target = String(params.url || "").trim();
  const cc = String(params.country || "").trim();
  const mode = String(params.mode || "auto").toLowerCase();
  const useGateway = String(params.gateway || "1") !== "0";
  const timeoutMs = parseInt(params.timeout, 10) > 0 ? parseInt(params.timeout, 10) : 30000;

  if (!target) return json({ ok: false, error: "Missing 'url' parameter", code: 400 }, 400);
  if (!/^https?:\/\//i.test(target)) return json({ ok: false, error: "Invalid URL", code: 400 }, 400);

  if (mode === "stream") {
    try {
      const exit = await launchExit(target, cc, 20000);
      const upstream = await fetch(exit.finalUrl, {
        headers: {
          "User-Agent": randomUA(),
          Accept: "*/*",
          Referer: "https://proxyium.com/",
          Cookie: "__cpc=" + encodeURIComponent(exit.cpc),
          ...(request.headers.get("Range") ? { Range: request.headers.get("Range") } : {}),
        },
        redirect: "follow",
        signal: AbortSignal.timeout(timeoutMs),
      });
      const hdr = new Headers();
      for (const k of ["content-type", "content-length", "content-range", "accept-ranges", "cache-control", "content-disposition", "content-encoding", "last-modified", "etag"]) {
        const v = upstream.headers.get(k);
        if (v) hdr.set(k, v);
      }
      Object.entries(CORS_HEADERS).forEach(([k, v]) => hdr.set(k, v));
      hdr.set("X-Proxy-Node", exit.node || "rotating-exit");
      hdr.set("X-Proxy-IP", exit.ip || "");
      return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: hdr });
    } catch (e) {
      return json({ ok: false, error: e && e.message ? e.message : String(e), code: 502 }, 502);
    }
  }

  const res = useGateway ? await proxyBuffered(target, cc, env) : await proxyDirect(target, timeoutMs);
  if (!res.ok) {
    return json({ ok: false, error: res.err || "fetch failed", code: 502 }, 502);
  }

  const isBin = isBinary(res.ct);

  if (mode === "json" || ((mode === "auto" || mode === "text") && !isBin) || mode === "base64") {
    let data = null;
    let data_b64 = null;
    if (mode === "base64" || (isBin && mode !== "text")) {
      data_b64 = bytesToBase64(res.bytes);
    } else {
      const text = new TextDecoder().decode(res.bytes);
      if (mode === "json" || (mode === "auto" && isJsonLike(text, res.ct))) {
        try { data = JSON.parse(text); } catch (_) { data = text; }
      } else {
        data = text;
      }
    }
    return json({
      status: res.code,
      ok: true,
      data,
      data_b64,
      content_type: res.ct,
      headers: res.headers,
      proxy_host: res.node || "rotating-exit",
      proxy_ip: res.ip || "",
      country: cc || "auto",
      elapsed_ms: res.elapsed_ms,
      size_bytes: res.bytes.length,
      via_proxy: res.via_proxy,
    }, (res.code >= 200 && res.code < 400) ? res.code : 200);
  }

  const hdr = new Headers();
  if (res.ct) hdr.set("Content-Type", res.ct);
  hdr.set("X-Proxy-Node", res.node || "rotating-exit");
  hdr.set("X-Proxy-IP", res.ip || "");
  hdr.set("X-Proxy-Country", cc || "auto");
  Object.entries(CORS_HEADERS).forEach(([k, v]) => {
    if (!hdr.has(k)) hdr.set(k, v);
  });
  return new Response(res.bytes, { status: res.code, headers: hdr });
}
