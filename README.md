# SelfStrike
SelfStrike é um scanner de vulnerabilidade, portas, ips, brute force e muito mais.

*Scanner SQL Injection
*Scanner Port
*Ip Info
*Brute Force FTP
*Brute Force SSH
*Brute Force Request
*Search IP
*FootPrint URL


		 .___        ,__ ,__          ___/_     
		 /   `   ___ /  `/  `,    . .'  /\/     
		 |    |.'   `|__ |__ |    ` |  / ||,---.
		 |    ||----'|   |   |    | |,'  ||'   `
		 /---/ `.___,|   |    `---|./`---'/    |
					 /   /    \___/             
		
		
	-====================================================-
	-                 SelfStrike
	*-	        	Create By Deffy0h		                 -0
	*-----------------------------------------------------



use:
SelfStrike.pl

 -t|type SqlScanner -u|url 'site' -p|port 80 -timeout 5 -re|request 'q=1&s=1' -m|method 'GET|POST'    *Scanner Sql Injection Vulnerability*

 -t|type PortScanner -i|ip 'ip' -p|port 80
 -t|type PortScanner -i|ip 'ip' -p|port 80 -timeout 5 -w|proto 'tcp'    *Scanner Port*
 -t|type PortScanner -i|ip 'ip|wordlist' -p|port '0|00|000' -timeout 5 -w|proto 'tcp'     *scans all standard doors*


 -t|type InfoIp -i|ip 'ip'  *Get Info IP*

 -t|type BruteForce-ftp -user 'admin' -pass 'wordlist.txt' -u 'site' *Brute Force in FTP*


 -t|type SelfStrike-Ip -i|ip '192.168.0.c' -p|port '80' -timeout 5 -s|save 'output.txt'  *Search IP*


 -t|type SelfStrike-Url -u|url 'deffy0h.tk' *Get Info WebSite*
