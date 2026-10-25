// ============================================================================
// AuroraProxy — Vercel Serverless Function (rotating-exit proxy gateway)
// ----------------------------------------------------------------------------
// NODE RUNTIME handler (CommonJS-compatible ES module build).
//
// WHY THIS FILE CHANGED (root cause of FUNCTION_INVOCATION_TIMEOUT):
//   The Vercel project runs functions on the Node.js runtime (Node 24.x).
//   The previous build declared `export const config = { runtime: "edge" }`
//   and used a Web-standard `(request) => Response` handler. Under the Node
//   runtime, Vercel invokes the function as `(req, res)` (http.IncomingMessage /
//   http.ServerResponse). A Web-standard handler never writes to `res`, so the
//   function hangs forever and Vercel aborts with FUNCTION_INVOCATION_TIMEOUT.
//
// FIX: this file exports a Node-native `module.exports = handler` where
//   handler(req, res) streams the response through Node's `res`. No Web
//   `Request`/`Response` objects. Works reliably on the Node runtime.
//
// Reverse-engineered 3-step flow (verified live 2026-10-25):
//   1. POST https://cdn.proxyium.com/proxyrequest.php { type, proxy_country, url }
//      -> HTML containing new Function(atob('<b64>')) == hex == JS with
//          location.href = 'https://<node>/__cpi.php?s=<token>&r=<b64>&__cpo=1'
//   2. GET <node>/__cpi.php?s=... -> CroxyProxy shell + Set-Cookie __cpc=<token>
//      + data-r="<b64>" (final node URL)
//   3. GET final node URL WITH Cookie __cpc=<token> -> REAL target content
//
// The `node` host changes on every signup = rotating egress. This function is
// a generic privacy / geo-reachability rotating-exit proxy (no guarantees of
// bypassing any specific restriction).
//
// API surface:
//   GET/POST /api/proxy?url=...&country=...&mode=auto|text|json|base64|stream
//   GET       /api/proxy/ip | /api/ip -> current egress IP (fresh rotating exit)
//   GET       /api/health /api/version /api/stats
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

// ---------------------------------------------------------------------------
// base64 / hex helpers (pure Node — no browser globals)
// ---------------------------------------------------------------------------
function b64encode(buf) {
  return Buffer.from(buf).toString("base64");
}
function b64decode(str) {
  const s = String(str).replace(/\s+/g, "");
  const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
  return Buffer.from(s + pad, "base64").toString("latin1");
}
function b64Url(str) {
  // standard base64 (proxyium expects standard, not url-safe)
  return Buffer.from(str, "binary").toString("base64");
}
function hexDecode(hex) {
  const clean = String(hex).replace(/[^0-9a-fA-F]/g, "");
  if (clean.length % 2 !== 0) throw new Error("shield hex odd");
  return Buffer.from(clean, "hex").toString("latin1");
}
function utf8B64(str) {
  return Buffer.from(str, "utf8").toString("base64");
}

// ---------------------------------------------------------------------------
// response helpers (Node http.ServerResponse)
// ---------------------------------------------------------------------------
function sendJson(res, obj, status) {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  res.writeHead(status || 200, {
    "Content-Type": "application/json",
    ...CORS_HEADERS,
  });
  res.end(body);
}
function sendBytes(res, bytes, status, headers) {
  res.writeHead(status, { ...CORS_HEADERS, ...headers });
  res.end(Buffer.from(bytes));
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

function authorized(req, env) {
  const token = (env.API_TOKEN || "").trim();
  if (!token) return true;
  const url = new URL(req.url, "http://localhost");
  const auth = req.headers["authorization"] || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  const q = (url.searchParams.get("token") || "").trim();
  return bearer === token || q === token;
}

// Decode the first shield: base64 -> hex -> JS containing location.href
function decodeShield(b64) {
  const raw = b64decode(b64);
  const js = hexDecode(raw);
  const m = js.match(/location\.href\s*=\s*['"]([^'"]+)['"]/);
  if (!m) throw new Error("no redirect in shield");
  return m[1];
}

// Parse a raw Set-Cookie header into { name: value } (first non-empty wins).
function parseCookies(setCookieHeader, targetNames) {
  const jar = {};
  if (!setCookieHeader) return jar;
  const names = targetNames || ["__cpc", "__cpcPopShown"];
  const parts = String(setCookieHeader).split(/,(?=\s*[A-Za-z0-9_-]+=)/);
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

// ---------------------------------------------------------------------------
// Node fetch helpers (global fetch available on Node 18+)
// ---------------------------------------------------------------------------
async function httpGet(url, headers, redirect, timeoutMs) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { method: "GET", headers, redirect, signal: ctl.signal });
    return r;
  } finally {
    clearTimeout(t);
  }
}

async function httpPost(url, body, headers, timeoutMs) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    return await fetch(url, { method: "POST", headers, body, redirect: "manual", signal: ctl.signal });
  } finally {
    clearTimeout(t);
  }
}

// Launch a fresh rotating exit; return { node, cpi, cpc, finalUrl }.
async function launchExit(target, cc, timeoutMs) {
  // 1. signup
  const body = new URLSearchParams({ type: "", proxy_country: cc || "", url: target });
  const r1 = await httpPost(
    PRX_SIGNUP,
    body.toString(),
    {
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: "https://proxyium.com",
      Referer: "https://proxyium.com/",
      "User-Agent": randomUA(),
    },
    20000
  );
  if (r1.status !== 200) throw new Error("signup status " + r1.status);
  const html = await r1.text();
  const m = html.match(/atob\('([^']+)'\)/);
  if (!m) throw new Error("signup shield missing");
  const cpi = decodeShield(m[1]);
  const nodeMatch = cpi.match(/https:\/\/[^/]+/);
  const node = nodeMatch ? nodeMatch[0] : "";

  // 2. GET the __cpi.php shell -> harvest __cpc cookie + data-r
  const r2 = await httpGet(
    cpi,
    {
      "User-Agent": randomUA(),
      Referer: "https://proxyium.com/",
      Accept: "text/html,application/xhtml+xml,*/*;q=0.8",
    },
    "manual",
    timeoutMs
  );
  const page2 = await r2.text();
  const jar = parseCookies(r2.headers.get("set-cookie") || "", ["__cpc", "__cpcPopShown"]);
  const cpc = jar.__cpc || "";
  if (!cpc) throw new Error("no __cpc cookie from exit");

  // data-r carries the real content URL (base64). Fall back to building it.
  let finalUrl = "";
  const dm = page2.match(/data-r=["']([^"']+)["']/);
  if (dm) {
    try { finalUrl = b64decode(dm[1]); } catch (_) {}
  }
  if (!finalUrl) {
    let u;
    try { u = new URL(target); } catch (_) { throw new Error("invalid target"); }
    const origin = u.protocol + "//" + u.host;
    finalUrl = node + u.pathname + (u.search || "") + (u.search ? "&" : "?") + "__cpo=" + b64Url(origin);
  }

  return { node, cpi, cpc, finalUrl };
}

// Fetch REAL content through the exit node using the sticky __cpc session.
async function fetchThroughExit(exit, ctl, range) {
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
    signal: ctl.signal,
  });
  const bytes = new Uint8Array(await r.arrayBuffer());
  const headers = {};
  for (const [k, v] of r.headers.entries()) headers[k] = v;
  return { code: r.status, headers, bytes };
}

// Buffered fetch (for text/json/base64 modes) with retry on fresh exit.
async function proxyBuffered(target, cc, timeoutMs) {
  let lastErr = "";
  for (let attempt = 0; attempt < 3; attempt++) {
    const t0 = Date.now();
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      const exit = await launchExit(target, cc, 20000);
      const res = await fetchThroughExit(exit, ctl);
      clearTimeout(t);
      const elapsed = Date.now() - t0;
      if (res.code >= 500 || res.code === 0) {
        lastErr = "gateway " + res.code;
        continue;
      }
      const ct = (res.headers["content-type"] || res.headers["Content-Type"] || "").toLowerCase();
      return {
        ok: true, code: res.code, ct, bytes: res.bytes, headers: res.headers,
        elapsed_ms: elapsed, node: exit.node,
        ip: exit.node.replace(/^https?:\/\//, ""), via_proxy: true,
      };
    } catch (e) {
      clearTimeout(t);
      lastErr = e && e.message ? e.message : String(e);
    }
  }
  return { ok: false, err: lastErr || "gateway unreachable" };
}

// Direct fetch fallback (no rotating exit) — used when gateway=0.
async function proxyDirect(target, timeoutMs) {
  const t0 = Date.now();
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(target, { headers: { "User-Agent": GUA, Accept: "*/*" }, redirect: "follow", signal: ctl.signal });
    const bytes = new Uint8Array(await r.arrayBuffer());
    const ct = (r.headers.get("content-type") || "").toLowerCase();
    const headers = {};
    for (const [k, v] of r.headers.entries()) headers[k] = v;
    return { ok: true, code: r.status, ct, bytes, headers, elapsed_ms: Date.now() - t0, via_proxy: false };
  } catch (e) {
    return { ok: false, err: e && e.message ? e.message : String(e) };
  } finally {
    clearTimeout(t);
  }
}

function isJsonLike(text, ct) {
  if (ct && ct.includes("json")) return true;
  const ttext = text.trim();
  return (ttext.startsWith("{") && ttext.endsWith("}")) || (ttext.startsWith("[") && ttext.endsWith("]"));
}

// ---------------------------------------------------------------------------
// Node-native handler
// ---------------------------------------------------------------------------
module.exports = async function handler(req, res) {
  if (req.method === "OPTIONS") {
    res.writeHead(204, CORS_HEADERS);
    res.end();
    return;
  }
  try {
    await route(req, res);
  } catch (e) {
    sendJson(res, { ok: false, error: (e && e.message) || String(e), code: 500 }, 500);
  }
};

async function route(req, res) {
  const url = new URL(req.url, "http://localhost");
  const pathname = url.pathname;

  // --- meta endpoints (always instant, no upstream) ---
  if (pathname === "/api/health") {
    return sendJson(res, { status: "ok", version: "1.0.1", timestamp: new Date().toISOString() });
  }
  if (pathname === "/api/version") {
    return sendJson(res, { version: "1.0.1", name: "auroraproxy", engine: "vercel-node-rotating-exit" });
  }
  if (pathname === "/api/stats") {
    return sendJson(res, { status: "ok", engine: "rotating-exit", note: "stateless on serverless" });
  }

  // --- live egress IP (proxybin-style) ---
  if (pathname === "/api/proxy/ip" || pathname === "/api/ip") {
    const cc = (url.searchParams.get("country") || "").trim();
    const t0 = Date.now();
    try {
      const exit = await launchExit("https://api.ipify.org?format=json", cc, 20000);
      return sendJson(res, {
        ok: true,
        proxy_country: cc || "auto",
        ip: exit.node.replace(/^https?:\/\//, ""),
        elapsed_ms: Date.now() - t0,
        note: "Egress IP of the rotating node, not your own IP.",
      });
    } catch (e) {
      return sendJson(res, { ok: false, error: (e && e.message) || String(e), code: 502 }, 502);
    }
  }

  // --- auth gate (only meaningful for /api/proxy) ---
  if (pathname !== "/api/proxy") {
    return sendJson(res, { ok: false, error: "Endpoint not found", code: 404 }, 404);
  }
  const env = { API_TOKEN: process.env.API_TOKEN || "" };
  if (!authorized(req, env)) {
    return sendJson(res, { ok: false, error: "unauthorized", code: 401 }, 401);
  }

  // --- parse params from query OR JSON/form body ---
  let params = {};
  for (const k of ["url", "country", "mode", "method", "timeout", "gateway", "headers", "body"]) {
    const v = url.searchParams.get(k);
    if (v !== null) params[k] = v;
  }
  if (["POST", "PUT", "PATCH"].includes(req.method)) {
    const ct = req.headers["content-type"] || "";
    if (ct.includes("application/json")) {
      try {
        const raw = await readBody(req);
        const j = JSON.parse(raw);
        if (j && typeof j === "object") params = { ...params, ...j };
      } catch (_) {}
    } else if (ct.includes("application/x-www-form-urlencoded")) {
      try {
        const raw = await readBody(req);
        for (const [k, v] of new URLSearchParams(raw)) params[k] = v;
      } catch (_) {}
    }
  }

  let target = String(params.url || "").trim();
  const cc = String(params.country || "").trim();
  const mode = String(params.mode || "auto").toLowerCase();
  const useGateway = String(params.gateway || "1") !== "0";
  const timeoutMs = parseInt(params.timeout, 10) > 0 ? parseInt(params.timeout, 10) : 30000;

  if (!target) return sendJson(res, { ok: false, error: "Missing 'url' parameter", code: 400 }, 400);
  if (!/^https?:\/\//i.test(target)) return sendJson(res, { ok: false, error: "Invalid URL", code: 400 }, 400);

  // --- stream mode: raw passthrough with Range support ---
  if (mode === "stream") {
    try {
      const exit = await launchExit(target, cc, 20000);
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), timeoutMs);
      const upstream = await fetch(exit.finalUrl, {
        headers: {
          "User-Agent": randomUA(),
          Accept: "*/*",
          Referer: "https://proxyium.com/",
          Cookie: "__cpc=" + encodeURIComponent(exit.cpc),
          ...(req.headers["range"] ? { Range: req.headers["range"] } : {}),
        },
        redirect: "follow",
        signal: ctl.signal,
      });
      clearTimeout(t);
      const hdr = { ...CORS_HEADERS };
      for (const k of ["content-type", "content-length", "content-range", "accept-ranges", "cache-control", "content-disposition", "content-encoding", "last-modified", "etag"]) {
        const v = upstream.headers.get(k);
        if (v) hdr[k] = v;
      }
      hdr["X-Proxy-Node"] = exit.node || "rotating-exit";
      hdr["X-Proxy-IP"] = exit.node.replace(/^https?:\/\//, "");
      res.writeHead(upstream.status, hdr);
      const buf = Buffer.from(await upstream.arrayBuffer());
      res.end(buf);
      return;
    } catch (e) {
      return sendJson(res, { ok: false, error: (e && e.message) || String(e), code: 502 }, 502);
    }
  }

  // --- buffered modes ---
  const r = useGateway ? await proxyBuffered(target, cc, timeoutMs) : await proxyDirect(target, timeoutMs);
  if (!r.ok) {
    return sendJson(res, { ok: false, error: r.err || "fetch failed", code: 502 }, 502);
  }

  const isBin = isBinary(r.ct);

  if (mode === "json" || ((mode === "auto" || mode === "text") && !isBin) || mode === "base64") {
    let data = null;
    let data_b64 = null;
    if (mode === "base64" || (isBin && mode !== "text")) {
      data_b64 = b64encode(Buffer.from(r.bytes));
    } else {
      const text = Buffer.from(r.bytes).toString("utf8");
      if (mode === "json" || (mode === "auto" && isJsonLike(text, r.ct))) {
        try { data = JSON.parse(text); } catch (_) { data = text; }
      } else {
        data = text;
      }
    }
    return sendJson(res, {
      status: r.code, ok: true, data, data_b64, content_type: r.ct, headers: r.headers,
      proxy_host: r.node || "rotating-exit", proxy_ip: r.ip || "", country: cc || "auto",
      elapsed_ms: r.elapsed_ms, size_bytes: r.bytes.length, via_proxy: r.via_proxy,
    }, (r.code >= 200 && r.code < 400) ? r.code : 200);
  }

  // default: raw binary replay
  const hdr = {};
  if (r.ct) hdr["Content-Type"] = r.ct;
  hdr["X-Proxy-Node"] = r.node || "rotating-exit";
  hdr["X-Proxy-IP"] = r.ip || "";
  hdr["X-Proxy-Country"] = cc || "auto";
  return sendBytes(res, r.bytes, r.code, hdr);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}
