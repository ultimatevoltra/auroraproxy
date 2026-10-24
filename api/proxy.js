// ============================================================================
// AuroraProxy — Vercel Serverless Function (rotating-exit proxy gateway)
// Decodes the proxyium rotating-exit flow and re-implements it server-side.
//
// Flow:
//   1. POST https://cdn.proxyium.com/proxyrequest.php {type, proxy_country, url}
//   2. HTML has atob('...') -> base64 -> hex -> JS location.href = 'https://<node>/__cpi.php?s=<token>&r=<b64(target)>&__cpo=1'
//   3. Fetch <node>/__cpi.php?s=<token>&r=<b64(target)>&__cpo=1 -> proxied content
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

function authorized(request, env) {
  const token = (env.API_TOKEN || "").trim();
  if (!token) return true;
  const url = new URL(request.url);
  const bearer = (request.headers.get("Authorization") || "").startsWith("Bearer ")
    ? request.headers.get("Authorization").slice(7).trim() : "";
  const q = (url.searchParams.get("token") || "").trim();
  return bearer === token || q === token;
}

function isBinary(ct) {
  if (!ct) return false;
  const lower = ct.toLowerCase();
  return BINARY_CT.some((p) => lower.startsWith(p));
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

function randomUA() {
  const oses = [
    "Windows NT 10.0; Win64; x64", "Macintosh; Intel Mac OS X 10_15_7",
    "X11; Linux x86_64", "Linux; Android 13; SM-S918B", "Linux; Android 14; Pixel 8",
  ];
  const brs = ["Chrome/120.0.0.0", "Chrome/124.0.0.0", "Chrome/126.0.0.0", "Chrome/128.0.0.0"];
  const os = oses[Math.floor(Math.random() * oses.length)];
  const br = brs[Math.floor(Math.random() * brs.length)];
  return `Mozilla/5.0 (${os}) AppleWebKit/537.36 (KHTML, like Gecko) ${br} Safari/537.36`;
}

function decodeShield(b64) {
  let raw;
  try { raw = Buffer.from(b64, "base64").toString("latin1"); }
  catch { throw new Error("shield base64"); }
  const hex = raw.replace(/[^0-9a-fA-F]/g, "");
  if (hex.length % 2 !== 0) throw new Error("shield hex");
  const buf = Buffer.from(hex, "hex").toString("latin1");
  const m = buf.match(/location\.href\s*=\s*['"]([^'"]+)['"]/);
  if (!m) throw new Error("no redirect");
  return m[1];
}

async function launchExit(target, cc, timeoutMs) {
  const body = new URLSearchParams({ type: "", proxy_country: cc || "", url: target });
  const r1 = await fetch(PRX_SIGNUP, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: "https://proxyium.com", Referer: "https://proxyium.com/", "User-Agent": randomUA(),
    },
    body: body.toString(), signal: AbortSignal.timeout(timeoutMs), redirect: "manual",
  });
  if (r1.status !== 200) throw new Error("signup status " + r1.status);
  const html = await r1.text();
  const m = html.match(/atob\('([^']+)'\)/);
  if (!m) throw new Error("signup shield");
  const redirect = decodeShield(m[1]);
  let node = "";
  const nm = redirect.match(/https:\/\/[^/]+/);
  if (nm) node = nm[0];
  return { redirect, node, target };
}

async function fetchThroughExit(exit, signal) {
  const r = await fetch(exit.redirect, {
    method: "GET",
    headers: { "User-Agent": randomUA(), Accept: "*/*", Referer: "https://proxyium.com/" },
    redirect: "follow", signal,
  });
  const buf = Buffer.from(await r.arrayBuffer());
  const headers = {};
  for (const [k, v] of r.headers.entries()) headers[k] = v;
  return { code: r.status, headers, body: buf };
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
      if (res.code >= 500 || res.code === 0) { lastErr = "gateway " + res.code; continue; }
      const ct = (res.headers["content-type"] || res.headers["Content-Type"] || "").toLowerCase();
      return { ok: true, code: res.code, ct, body: res.body, headers: res.headers, elapsed_ms: elapsed, node: exit.node, via_proxy: true };
    } catch (e) { lastErr = e && e.message ? e.message : String(e); }
  }
  return { ok: false, err: lastErr || "gateway unreachable" };
}

async function proxyDirect(target, timeoutMs) {
  const t0 = Date.now();
  try {
    const r = await fetch(target, {
      headers: { "User-Agent": GUA, Accept: "*/*" }, redirect: "follow", signal: AbortSignal.timeout(timeoutMs),
    });
    const buf = Buffer.from(await r.arrayBuffer());
    const ct = (r.headers.get("content-type") || "").toLowerCase();
    const headers = {};
    for (const [k, v] of r.headers.entries()) headers[k] = v;
    return { ok: true, code: r.status, ct, body: buf, headers, elapsed_ms: Date.now() - t0, via_proxy: false };
  } catch (e) { return { ok: false, err: e && e.message ? e.message : String(e) }; }
}

async function parseParams(request) {
  const url = new URL(request.url);
  let params = {};
  for (const k of ["url", "country", "mode", "method", "timeout", "gateway", "headers", "body"]) {
    const v = url.searchParams.get(k);
    if (v !== null) params[k] = v;
  }
  if (request.method === "POST" || request.method === "PUT" || request.method === "PATCH") {
    const ct = request.headers.get("Content-Type") || "";
    if (ct.includes("application/json")) {
      try { const j = await request.json(); if (j && typeof j === "object") params = { ...params, ...j }; } catch {}
    } else if (ct.includes("application/x-www-form-urlencoded")) {
      try { const f = await request.formData(); for (const [k, v] of f.entries()) params[k] = v; } catch {}
    }
  }
  return { params, url };
}

export default async function handler(request, context) {
  const env = context && context.env ? context.env : {};
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });
  const { params, url } = await parseParams(request);
  const pathname = url.pathname;

  if (/\/(health|version|stats)(\/)?$/.test(pathname)) {
    if (pathname.includes("health")) return json({ status: "ok", version: "1.0.0", timestamp: new Date().toISOString() });
    if (pathname.includes("version")) return json({ version: "1.0.0", name: "auroraproxy", engine: "vercel-serverless-rotating-exit" });
    if (pathname.includes("stats")) return json({ status: "ok", engine: "rotating-exit", note: "stateless on serverless" });
    return json({ status: "ok", version: "1.0.0" });
  }

  if (!authorized(request, env)) {
    return json({ ok: false, error: "unauthorized", suggestion: "Provide X-Api-Token or Authorization Bearer" }, 401);
  }

  const target = String(params.url || "").trim();
  const cc = String(params.country || "").trim();
  const mode = String(params.mode || "auto").toLowerCase();
  const useGateway = String(params.gateway || "1") !== "0";
  const timeoutMs = parseInt(params.timeout, 10) > 0 ? parseInt(params.timeout, 10) : 30000;

  if (!target) return json({ ok: false, error: "Missing 'url' parameter", code: 400 }, 400);
  if (!/^https?:\/\//i.test(target)) return json({ ok: false, error: "Invalid URL", code: 400 }, 400);

  if (mode === "stream") {
    try {
      const exit = await launchExit(target, cc, 20000);
      const upstream = await fetch(exit.redirect, {
        headers: {
          "User-Agent": randomUA(), Accept: "*/*", Referer: "https://proxyium.com/",
          ...(request.headers.get("Range") ? { Range: request.headers.get("Range") } : {}),
        },
        redirect: "follow", signal: AbortSignal.timeout(timeoutMs),
      });
      const hdr = new Headers();
      for (const k of ["content-type", "content-length", "content-range", "accept-ranges", "cache-control", "content-disposition", "content-encoding", "last-modified", "etag"]) {
        const v = upstream.headers.get(k);
        if (v) hdr.set(k, v);
      }
      Object.entries(CORS_HEADERS).forEach(([k, v]) => hdr.set(k, v));
      hdr.set("X-Proxy-Node", exit.node || "rotating-exit");
      return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: hdr });
    } catch (e) {
      return json({ ok: false, error: e && e.message ? e.message : String(e), code: 502 }, 502);
    }
  }

  const res = useGateway ? await proxyBuffered(target, cc, env) : await proxyDirect(target, timeoutMs);
  if (!res.ok) return json({ ok: false, error: res.err || "fetch failed", code: 502 }, 502);

  const isBin = isBinary(res.ct);
  if (mode === "json" || ((mode === "auto" || mode === "text") && !isBin) || mode === "base64") {
    let data = null;
    let data_b64 = null;
    if (mode === "base64" || (isBin && mode !== "text")) {
      data_b64 = res.body.toString("base64");
    } else {
      const text = res.body.toString("utf-8");
      if (mode === "json" || (mode === "auto" && isJsonLike(text, res.ct))) {
        try { data = JSON.parse(text); } catch { data = text; }
      } else { data = text; }
    }
    return json({
      status: res.code, ok: true, data, data_b64, content_type: res.ct, headers: res.headers,
      proxy_host: res.node || "rotating-exit", country: cc || "auto",
      elapsed_ms: res.elapsed_ms, size_bytes: res.body.length, via_proxy: res.via_proxy,
    }, res.code >= 200 && res.code < 400 ? res.code : 200);
  }

  const hdr = new Headers();
  if (res.ct) hdr.set("Content-Type", res.ct);
  hdr.set("X-Proxy-Node", res.node || "rotating-exit");
  hdr.set("X-Proxy-Country", cc || "auto");
  Object.entries(CORS_HEADERS).forEach(([k, v]) => hdr.set(k, v));
  return new Response(new Uint8Array(res.body), { status: res.code, headers: hdr });
}

function isJsonLike(text, ct) {
  if (ct && ct.includes("json")) return true;
  const t = text.trim();
  return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"));
}
