// No-op build step for Vercel.
// AuroraProxy ships a static index.html front-end plus serverless functions
// under /api. There is nothing to compile; this file simply gives Vercel a
// deterministic, successful "build" so it does not fall back to an ambiguous
// auto-detection that can mis-handle the /api functions.
console.log("auroraproxy: static frontend + /api serverless functions (no build needed)");
