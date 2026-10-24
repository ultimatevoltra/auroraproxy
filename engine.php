<?php
/**
 * AuroraProxy — Rotating-Exit Proxy Engine (pure curl, stdlib only)
 * ==================================================================
 * Extracted from the GlitchVid engine. Generalized so the target URL
 * can be ANY site (not hardcoded to giz.ai). Uses two egress lanes:
 *
 *   1. Rotating-exit gateway (proxyium-style) : launch a sticky exit session
 *      per origin, then route fetches through that node while rebuilding
 *      browser headers / cookies so the upstream sees a "fresh browser".
 *   2. Optional clean-exit proxy (config.json "proxy" / proxy.txt) : a plain
 *      HTTP proxy for direct egress.
 *
 * No API keys. No secrets in code (config lives in data/config.json or env).
 */

define('GUA', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36');
define('GD', __DIR__ . '/data');
foreach ([GD, GD . '/sessions', GD . '/tmp'] as $d_) {
    if (!is_dir($d_)) @mkdir($d_, 0775, true);
}

define('PRX_SIGNUP', 'https://cdn.proxyium.com/proxyrequest.php');

/* ---------------------------------------------------------------------------
 * Config
 * ------------------------------------------------------------------------ */
function cfg(): array {
    static $c = null;
    if ($c === null) {
        $c = [];
        $f = GD . '/config.json';
        if (is_file($f)) {
            $j = @json_decode((string)@file_get_contents($f), true);
            if (is_array($j)) $c = $j;
        }
    }
    return $c;
}

/* Optional clean-exit proxy: data/config.json {"proxy":"ip:port"} or proxy.txt */
function out_proxy(string $url = ''): string {
    static $p = null;
    if ($p === null) {
        $p = '';
        $c = cfg();
        if (is_string($c['proxy'] ?? null) && trim($c['proxy']) !== '') $p = trim($c['proxy']);
        elseif (is_file(GD . '/proxy.txt')) $p = trim((string)@file_get_contents(GD . '/proxy.txt'));
    }
    return $p;
}

/* ---------------------------------------------------------------------------
 * Random browser fingerprint / UA
 * ------------------------------------------------------------------------ */
function prx_ua(): string {
    $oses = ['Windows NT 10.0; Win64; x64', 'Macintosh; Intel Mac OS X 10_15_7', 'X11; Linux x86_64', 'Linux; Android 13; SM-S918B', 'Linux; Android 14; Pixel 8'];
    $brs = ['Chrome/120.0.0.0', 'Chrome/124.0.0.0', 'Chrome/126.0.0.0', 'Chrome/128.0.0.0'];
    return 'Mozilla/5.0 (' . $oses[array_rand($oses)] . ') AppleWebKit/537.36 (KHTML, like Gecko) ' . $brs[array_rand($brs)] . ' Safari/537.36';
}

function prx_hget(string $raw, string $name): array {
    $out = [];
    foreach (preg_split('~\r?\n~', $raw) as $ln) {
        if (stripos($ln, $name . ':') === 0) $out[] = trim(substr($ln, strlen($name) + 1));
    }
    return $out;
}

/* ---------------------------------------------------------------------------
 * Rotating-exit session (sticky per origin)
 * ------------------------------------------------------------------------ */
function sess_path(string $key): string {
    return GD . '/sessions/' . substr(md5($key), 0, 16) . '.json';
}

function sess_get(string $key): ?array {
    $f = sess_path($key);
    if (!is_file($f)) return null;
    $s = @json_decode((string)@file_get_contents($f), true);
    return is_array($s) ? $s : null;
}

function sess_put(string $key, array $s): void {
    $s['ts'] = time();
    @file_put_contents(sess_path($key), json_encode($s), LOCK_EX);
}

function sess_drop(string $key): void {
    @unlink(sess_path($key));
}

/* Launch a freshly-bound exit session for a target url (returns node+cookies). */
function prx_launch(string $target, string $cc): array {
    $q = http_build_query(['type' => '', 'proxy_country' => $cc, 'url' => $target]);
    $r1 = curl_post(PRX_SIGNUP, $q, [
        'Content-Type: application/x-www-form-urlencoded',
        'Origin: https://proxyium.com',
        'Referer: https://proxyium.com/',
        'User-Agent: ' . prx_ua(),
    ], 20);

    $st = (int)$r1['code']; $body = (string)$r1['body'];
    if ($st !== 200 || !preg_match("~atob\('([^']+)'\)~", $body, $m)) throw new Exception('signup shield');
    $js = @base64_decode($m[1]);
    if (!$js || !preg_match("~location\.href\s*=\s*'([^']+)'~", (string)$js, $m2)) throw new Exception('no redirect');
    $cpi = $m2[1];
    $node = (preg_match('~(https://[^/]+)~', $cpi, $m3)) ? $m3[1] : '';

    $r2 = curl_get($cpi, ['Referer: https://proxyium.com/', 'User-Agent: ' . prx_ua()], 25);
    $h2 = (string)$r2['headers']; $body2 = (string)$r2['body'];
    $jar = [];
    foreach (prx_hget($h2, 'Set-Cookie') as $c) {
        $p = explode('=', $c, 2);
        if (count($p) === 2 && trim($p[0]) !== '') $jar[trim($p[0])] = trim(explode(';', $p[1])[0]);
    }
    if (!preg_match('~data-r=["\']([^"\']+)["\']~', $body2, $m4) || !isset($jar['__cpc'])) throw new Exception('launch shield');
    return ['cpi' => $cpi, 'node' => $node, 'final' => (string)base64_decode($m4[1]), 'jar' => $jar];
}

/* Get or create a sticky exit session keyed by the target origin. */
function exit_get(string $seedTarget): array {
    $key = 'exit:' . ($seedTarget ?: 'default');
    $s = sess_get($key);
    if (is_array($s) && ($s['node'] ?? '') !== '' && (time() - (int)($s['ts'] ?? 0)) < 1500) return $s;

    $err = null;
    foreach (['us', 'eu', 'sg', 'jp', 'in', 'br'] as $cc) {
        try { $w = prx_launch($seedTarget, $cc); }
        catch (Throwable $e) { $err = $e; continue; }
        $s = ['node' => $w['node'], 'cpi' => $w['cpi'], 'final' => $w['final'],
              'jar' => $w['jar'], 'ua' => prx_ua(), 'ts' => time(), 'cc' => $cc];
        sess_put($key, $s);
        return $s;
    }
    throw $err ?: new Exception('no exit lanes');
}

function exit_put(string $seedTarget, array $s): void {
    $key = 'exit:' . ($seedTarget ?: 'default');
    sess_put($key, $s);
}

function exit_drop(string $seedTarget): void {
    $key = 'exit:' . ($seedTarget ?: 'default');
    sess_drop($key);
}

/* ---------------------------------------------------------------------------
 * Low-level curl helpers (return header + body split)
 * ------------------------------------------------------------------------ */
function curl_split(string $resp, int $headerSize): array {
    return [substr($resp, 0, $headerSize), substr($resp, $headerSize)];
}

function curl_get(string $url, array $headers = [], int $timeout = 30, bool $follow = false): array {
    return do_curl('GET', $url, null, $headers, $timeout, $follow);
}

function curl_post(string $url, $body, array $headers = [], int $timeout = 30): array {
    return do_curl('POST', $url, $body, $headers, $timeout, false);
}

function do_curl(string $method, string $url, $body = null, array $headers = [], int $timeout = 30, bool $follow = false): array {
    $ch = curl_init($url);
    $h = ['User-Agent: ' . GUA, 'Accept: */*'];
    if ($body !== null) $h[] = 'Content-Type: application/x-www-form-urlencoded';
    foreach ($headers as $hv) $h[] = $hv;
    $opt = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_HTTPHEADER => $h,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => 15,
        CURLOPT_FOLLOWLOCATION => $follow,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_CUSTOMREQUEST => $method,
    ];
    if ($body !== null) $opt[CURLOPT_POSTFIELDS] = $body;
    curl_setopt_array($ch, $opt);
    $resp = curl_exec($ch);
    if ($resp === false) { $e = curl_error($ch); curl_close($ch); return ['code' => 0, 'body' => '', 'headers' => '', 'err' => $e]; }
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hlen = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    list($hh, $bd) = curl_split((string)$resp, $hlen);
    return ['code' => $code, 'body' => $bd, 'headers' => $hh, 'err' => ''];
}

/* ---------------------------------------------------------------------------
 * Public API — fetch a URL through a rotating exit (or clean proxy).
 *
 * Returns: [
 *   'ok'        => bool,
 *   'code'      => int        http status,
 *   'body'      => string     response body,
 *   'ctype'     => string     content-type,
 *   'final_url' => string     the exit node url actually fetched,
 *   'country'   => string     exit country picked,
 *   'elapsed_ms'=> int,
 *   'err'       => string,
 *   'via_proxy' => bool,
 * ]
 * ------------------------------------------------------------------------ */
function proxy_fetch(string $url, string $country = '', bool $use_gateway = true): array {
    $t0 = microtime(true);

    if (!$use_gateway) {
        $ch = curl_init($url);
        $px = out_proxy($url);
        if ($px !== '') {
            curl_setopt($ch, CURLOPT_PROXY, $px);
            curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_HTTPHEADER => ['User-Agent: ' . GUA, 'Accept: */*'],
            CURLOPT_TIMEOUT => 60,
            CURLOPT_CONNECTTIMEOUT => 20,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => true,
        ]);
        $resp = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $hlen = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $final = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        $ctype = (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        curl_close($ch);
        if ($resp === false) return ['ok' => false, 'code' => 0, 'err' => 'curl error', 'elapsed_ms' => (int)((microtime(true) - $t0) * 1000)];
        list($hh, $bd) = curl_split((string)$resp, $hlen);
        return ['ok' => true, 'code' => $code, 'body' => $bd, 'headers' => $hh, 'ctype' => $ctype,
                'final_url' => $final, 'country' => '', 'elapsed_ms' => (int)((microtime(true) - $t0) * 1000), 'via_proxy' => $px !== ''];
    }

    // Rotating gateway lane
    $u = parse_url($url);
    $origin = ($u['scheme'] ?? 'https') . '://' . ($u['host'] ?? '');
    $out = ['ok' => false, 'code' => 0, 'err' => 'gateway unreachable', 'elapsed_ms' => 0];

    for ($t = 0; $t < 3; $t++) {
        try {
            $s = exit_get($origin . '/');
        } catch (Throwable $e) {
            $out = ['ok' => false, 'code' => 0, 'err' => 'gateway: ' . $e->getMessage(), 'elapsed_ms' => (int)((microtime(true) - $t0) * 1000)];
            continue;
        }

        // opener: bind the fresh session to origin once, harvest cookies
        if (empty($s['opened'])) {
            $ack = [];
            foreach ($s['jar'] as $k => $v) $ack[] = $k . '=' . $v;
            $oresp = do_curl('GET', $s['final'], null, ['Cookie: ' . implode('; ', $ack), 'Referer: ' . $s['cpi'], 'User-Agent: ' . $s['ua']], 30, false);
            if (is_string($oresp['headers']) && $oresp['headers'] !== '') {
                foreach (prx_hget($oresp['headers'], 'Set-Cookie') as $sc) {
                    $p = explode('=', $sc, 2);
                    if (count($p) === 2 && trim($p[0]) !== '') $s['jar'][trim($p[0])] = trim(explode(';', $p[1])[0]);
                }
            }
            $s['opened'] = 1;
            exit_put($origin . '/', $s);
        }

        // build the node url for the target
        $path = ($u['path'] ?? '/') . (isset($u['query']) ? '?' . $u['query'] : '');
        $nu = $s['node'] . $path . (strpos($path, '?') !== false ? '&' : '?') . '__cpo=' . base64_encode($origin);

        $ck = [];
        foreach ($s['jar'] as $k => $v) $ck[] = $k . '=' . $v;
        $send = [
            'Cookie: ' . implode('; ', $ck),
            'User-Agent: ' . $s['ua'],
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language: en-US,en;q=0.9',
            'Sec-Fetch-Dest: document',
            'Sec-Fetch-Mode: navigate',
            'Sec-Fetch-Site: same-origin',
            'Upgrade-Insecure-Requests: 1',
        ];

        $ch = curl_init($nu);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_HTTPHEADER => $send,
            CURLOPT_TIMEOUT => 90,
            CURLOPT_CONNECTTIMEOUT => 20,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_FOLLOWLOCATION => true,
        ]);
        $resp = curl_exec($ch);
        if ($resp === false) {
            $e = curl_error($ch);
            curl_close($ch);
            exit_drop($origin . '/');
            $out = ['ok' => false, 'code' => 0, 'err' => 'gateway curl: ' . $e, 'elapsed_ms' => (int)((microtime(true) - $t0) * 1000)];
            continue;
        }
        $st = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $hlen = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $ctype = (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        curl_close($ch);
        list($hh, $bd) = curl_split((string)$resp, $hlen);

        // harvest any new cookies
        $changed = false;
        foreach (prx_hget($hh, 'Set-Cookie') as $sc) {
            $p = explode('=', $sc, 2);
            if (count($p) === 2 && trim($p[0]) !== '') { $s['jar'][trim($p[0])] = trim(explode(';', $p[1])[0]); $changed = true; }
        }
        $s['final'] = $nu;
        exit_put($origin . '/', $s);

        $dirty = ($st >= 500) || $st === 0 || stripos($bd, 'Cannot POST') !== false;
        if (!$dirty) {
            return ['ok' => true, 'code' => $st, 'body' => $bd, 'headers' => $hh, 'ctype' => $ctype,
                    'final_url' => $nu, 'country' => $s['cc'] ?? '', 'elapsed_ms' => (int)((microtime(true) - $t0) * 1000), 'via_proxy' => true];
        }
        exit_drop($origin . '/'); // never reuse a failed exit
    }

    return $out;
}

/* ---------------------------------------------------------------------------
 * Live pool stats
 * ------------------------------------------------------------------------ */
function pool_stats(): array {
    $sessDir = GD . '/sessions';
    $files = glob($sessDir . '/*.json') ?: [];
    $now = time();
    $active = 0; $countries = [];
    foreach ($files as $f) {
        $s = @json_decode((string)@file_get_contents($f), true);
        if (is_array($s) && ($now - (int)($s['ts'] ?? 0)) < 1500) {
            $active++;
            if (!empty($s['cc'])) $countries[$s['cc']] = true;
        }
    }
    return ['active_sessions' => $active, 'countries' => count($countries), 'available_exits' => count(glob($sessDir . '/*.json') ?: [])];
}
