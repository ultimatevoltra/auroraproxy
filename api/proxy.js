// ============================================================================
// AuroraProxy — Vercel Serverless Function (rotating-exit proxy gateway)
// ----------------------------------------------------------------------------
// Decodes the proxyium rotating-exit flow (which wraps CroxyProxy) and
// re-implements it server-side so the web console + API can fetch ANY target
// through a fresh rotating exit, returning REAL upstream content.
//
// RUNTIME-NEUTRAL: uses only Web-standard globals (fetch, atob/btoa, TextDecoder,
// Uint8Array, AbortController) so it runs on BOTH the Vercel Node runtime AND
// the Vercel Edge runtime with no Buffer/Node-isms. This fixes the earlier
// "FUNCTION_INVOCATION_FAILED" crash caused by Node-only APIs.
//
// API surface:
//   GET/POST /api/proxy?url=...&country=...&mode=auto|text|json|base64|stream
//   GET       /api/proxy/ip   -> current egress IP (fresh rotating exit)
//   GET       /api/ip
//   GET       /api/health
//   GET       /api/version
//   GET       /api/stats
// ----------------------------------------------------------------------------

export default async function handler(request, context) {
  return (await import("./_impl.js")).handler(request, context);
}
