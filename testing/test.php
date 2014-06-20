<?php
function p0f_client($ip, $socket)
{
    if ($socket = @fsockopen('unix://'.$socket))
    {
        $query = pack('Lha*@24',0x50304601, 4, inet_pton($ip));
 
        fwrite($socket, $query);
        $resp = fread($socket, 233);
        fclose($socket);
 
        $resp = unpack( 'Lmagic_number/Lstatus/Lfirst_seen/Llast_seen'.
                        '/Ltotal_conn/Luptime_min/Lup_mod_days/Llast_nat'.
                        '/Llast_chg/cdistance/Cbad_sw/Cos_match_q'.
                        '/a32os_name/a32os_flavor/a32http_name/a32http_flavor'.
                        '/a32link_type/a32language', $resp);
 
        if (!is_array($resp)) {
            return false;
        }
 
        return $resp;
    }
 
    return false;
}
echo '<html><body>';
foreach(p0f_client($_SERVER['REMOTE_ADDR'],"/var/run/p0f.sock") as $key=>$value){
	echo "<div data-id=\"",$key,"\">",$value,"</div>\r\n";
}
var_dump($_SERVER);
echo '</body></html>';