# ✦ AuroraProxy — Rotating-Exit Proxy (Vercel)

A rotating-exit proxy web app + API. Each request is routed through a fresh rotating exit node (reverse-engineered proxyium flow), with single & batch requests, media streaming, and a full NebulaProxy-style REST API.

## Architecture
- **`api/proxy.js`** — Vercel serverless function that decodes the proxyium rotating-exit flow. Runs on Vercel; no PHP needed.
- **`index.html`** — the web app: 5-bar bottom nav (Home / Playground / Docs / History / Settings), single + batch, media gallery, i18n (en/bn), 5 themes.

## Features
- Rotating exits · geo diversity (US/EU/SG/JP/IN/BR) · media streaming (Range seek)
- Single + Batch requests with progress + JSON/CSV export
- Full API (auto/text/json/base64/stream) · 5 deep themes

## Deploy (Vercel)
```bash
vercel
```
`api/proxy.js` auto-registers as `/api/proxy`.

## API
- `GET/POST /api/proxy?url=<target>&country=us&mode=json|auto|text|base64|stream`
- `GET /api/health` → `{ status:"ok", version:"1.0.0" }`
- `GET /api/version` → `{ version, name, engine }`

### Modes
| mode | behaviour |
|------|-----------|
| auto | streams binaries; envelopes text/json |
| text | raw text |
| json | parsed JSON envelope |
| base64 | `data_b64` for binary |
| stream | raw passthrough with Range (video/audio seek) |

### Params
| field | req | description |
|-------|-----|-------------|
| url | yes | target URL |
| country | no | us/eu/sg/jp/in/br |
| mode | no | auto/text/json/base64/stream |
| method | no | HTTP method (default GET) |
| timeout | no | ms, default 30000 |
| gateway | no | set 0 to bypass exit |

## Optional gate
Set `API_TOKEN` env var on Vercel to require `Authorization: Bearer <token>`.

## Optional self-host (PHP)
`engine.php` + `proxy.php` retained for PHP hosts.

## Disclaimer
General rotating-exit web proxy for privacy/geo-reachability. Not a circumvention tool.
