# ✦ AuroraProxy — Rotating-Exit Proxy Gateway

A self-hosted, rotating-exit proxy gateway with a sleek multi-theme web console.
Built from a generalized proxyium-style rotating-exit engine (pure PHP + curl, no external dependencies).

## Features
- **Rotating exits** — every fetch binds a fresh sticky exit session, so your origin never leaks.
- **Geo diversity** — exits across US / EU / SG / JP / IN / BR.
- **5 deep themes** — Midnight Indigo, Deep Forest, Royal Amethyst, Ocean Abyss, Obsidian Noir.
- **No API keys** — no sign-up, no third-party SDK.
- **JSON or raw proxy modes** — return clean JSON metadata, or replay the original content-type/body.

## Requirements
- PHP 7.4+ with the `curl` extension.
- A writable `data/` directory.

## Quick start
```bash
php -S 0.0.0.0:8080
# open http://localhost:8080
```

## API
- `GET /proxy.php?url=<encoded target>&country=us&mode=json`
  - `mode=raw` → replays the target content-type + body.
  - `mode=json` → returns `{ ok, status, content_type, data, data_b64, proxy_host, country, elapsed_ms, via_proxy }`.
- `GET /proxy.php?action=stats` → live pool stats (active sessions, countries, available exits).
- `GET /proxy.php?action=health` → `{ status, version, timestamp }`.

## Config
`data/config.json` (optional):
```json
{ "proxy": "", "api_token": "" }
```
- `proxy` — a clean-exit HTTP proxy (ip:port). Leave empty to use the built-in rotating-exit gateway only.
- `api_token` — if set, requests must send `X-Api-Token: <token>` (or `?api_token=`).

`data/proxy.txt` — one proxy per line (`ip:port` or `ip:port:user:pass`), alternative to `config.json`.

## Directory layout
```
auroraproxy/
├── engine.php      # rotating-exit engine (curl, stdlib only)
├── proxy.php       # API endpoint
├── index.html      # web console (5 themes, en/bn i18n)
└── data/           # sessions + config (git-ignored)
```

## Disclaimer
AuroraProxy is a general rotating-exit web proxy for privacy and geo-reachability.
It is not a circumvention tool and makes no guarantee of bypassing any specific
network restriction.
