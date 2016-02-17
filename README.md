#SelfStrike

SelfStrike is a vulnerability scanner , doors, ips, brute force and more.
SelfStrike é um scanner de vulnerabilidade, portas, ips, brute force e muito mais.

*Scanner SQL Injection
*Scanner Joomla - SQL Injection
*Scanner XSS
*CSRF
*Scanner Port
*Scanner IP
*FingerPrint in IP
*FingerPrint in URL
*Brute Force in FTP
*Brute Force in SSH
*Brute Force in Login Painel
*Brute Force in MD5
*Encrypt TEXT to MD5
*Encrypt TEXT to Deffy0h-Crypt
*Descrypt Deffy0h-Crypt to TEXT
*Create SHELL


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
		*-	        	Create By Deffy0h	    -0
		*-----------------------------------------------------



		use:
		SelfStrike.pl
		
		 Scanner Sql Injection Vulnerability:
		 -t|type SqlScanner -u|url 'site' -p|port 80 -timeout 5 -re|request 'q=1&s=1' -m|method 'GET|POST'
		 
		 Joomla Vulnerability:
		 -t|type SelfStrike-Joomla -u|url 'deffy0h.tk'
		
		 FingerPrint in IP:
		 -t|type InfoIp -i|ip 'ip'
		
		 Brute Force in FTP:
		 -t|type BruteForce-ftp -user 'admin' -pass 'wordlist.txt' -u 'site'
		
		 Brute Force in Md5:
		 -t|type BruteForce-MD5 -re 'MD5' -pass 'wordlist.txt'
		
		 Scanner IP:
		 -t|type SelfStrike-Ip -i|ip '192.168.0.c' -p|port '80' -timeout 5 -s|save 'output.txt'
		
		 FingerPrint in URL
		 -t|type SelfStrike-Url -u|url 'deffy0h.tk'
		 
		  Scanner XSS Vulnerability
		 -t|type SelfStrike-XSS -u|url 'deffy0h.tk'
		 
		  Cross Site Request Fogery:
		 -t|type SelfStrike-CSRF -re|request 'q=1&s=1' -m|method 'GET|POST' -n|number '25'
		 
		  Encrypt MD5 HEX:
		 -t|type SelfStrike-MD5 -pass 'text'
		
		  Encrypt Deffy0h-Crypt:
		 -t|type SelfStrike-Encrypt -k|key 'opcional' -pass 'mensage' -s 'file.txt'
		
		 Descrypt Deffy0h-Crypt:
		 -t|type SelfStrike-Descrypt -k|key 'key public' -pass 'text_deffy0h_encrypt' -s 'file.txt'
		 
		 Create Shell .PHP:
		 -t|type SelfStrike-SHELL -s|save 'shell.php'
