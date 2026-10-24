<?php
/**
 * AuroraProxy — API endpoint
 * ========================
 * GET  /proxy.php?url=<encoded target>&country=<optional>&mode=json|raw
 *      -> fetch target through a rotating exit and return it.
 * GET  /proxy.php?action=stats  -> live pool stats (JSON).
 *
 * Optional gate: if data/config.json has "api_token", require header
 * X-Api-Token (or ?api_token=) to match.
 */

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type, X-Api-Token');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

require __DIR__ . '/engine.php';

/* ---- token gate ---- */
$c = cfg();
$token = $c['api_token'] ?? '';
if ($token !== '') {
    $given = $_SERVER['HTTP_X_API_TOKEN'] ?? ($_GET['api_token'] ?? '');
    if (!hash_equals($token, (string)$given)) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'error' => 'unauthorized', 'suggestion' => 'Provide X-Api-Token header']);
        exit;
    }
}

$action = $_GET['action'] ?? 'proxy';

if ($action === 'stats') {
    header('Content-Type: application/json');
    echo json_encode(['ok' => true, 'stats' => pool_stats(), 'engine' => 'auroraproxy-rotating-exit', 'version' => '1.0.0']);
    exit;
}

if ($action === 'health') {
    header('Content-Type: application/json');
    echo json_encode(['status' => 'ok', 'version' => '1.0.0', 'timestamp' => gmdate('c')]);
    exit;
}

/* ---- proxy ---- */
$url = $_GET['url'] ?? ($_POST['url'] ?? '');
$country = $_GET['country'] ?? '';
$mode = $_GET['mode'] ?? 'raw';
$use_gateway = ($_GET['gateway'] ?? '1') !== '0';

if ($url === '' || !preg_match('~^https?://~i', $url)) {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['ok' => false, 'error' => 'A valid http(s) url is required']);
    exit;
}

$res = proxy_fetch($url, $country, $use_gateway);

if ($mode === 'json') {
    header('Content-Type: application/json');
    $b64 = null;
    // base64-encode binary so JSON is always valid
    if ($res['ok'] && (!is_utf8($res['body']) || preg_match('~image/|video/|audio/~i', $res['ctype']))) {
        $b64 = base64_encode($res['body']);
    }
    echo json_encode([
        'ok' => $res['ok'],
        'status' => $res['code'],
        'content_type' => $res['ctype'],
        'data' => $b64 === null ? ($res['ok'] ? $res['body'] : null) : null,
        'data_b64' => $b64,
        'proxy_host' => $res['final_url'] ?? '',
        'country' => $res['country'] ?? '',
        'elapsed_ms' => $res['elapsed_ms'],
        'via_proxy' => $res['via_proxy'],
        'err' => $res['err'],
    ]);
    exit;
}

/* raw mode — replay content type */
if ($res['ok']) {
    http_response_code($res['code'] ?: 200);
    if ($res['ctype']) header('Content-Type: ' . $res['ctype']);
    header('X-Proxy-Host: ' . $res['final_url']);
    header('X-Proxy-Country: ' . $res['country']);
    echo $res['body'];
} else {
    http_response_code(502);
    header('Content-Type: application/json');
    echo json_encode(['ok' => false, 'error' => $res['err']]);
}

function is_utf8(string $s): bool {
    return (bool) preg_match('//u', $s);
}
