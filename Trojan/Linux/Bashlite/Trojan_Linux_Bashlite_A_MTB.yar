
rule Trojan_Linux_Bashlite_A_MTB{
	meta:
		description = "Trojan:Linux/Bashlite.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 63 72 6f 6e 74 61 62 20 2d 6c 20 3b 20 65 63 68 6f 20 22 40 72 65 62 6f 6f 74 20 25 73 22 29 20 7c 20 63 72 6f 6e 74 61 62 20 2d } //2 (crontab -l ; echo "@reboot %s") | crontab -
		$a_01_1 = {2f 62 69 6e 2f 63 75 72 6c 20 2d 6b 20 2d 4c 20 2d 2d 6f 75 74 70 75 74 } //2 /bin/curl -k -L --output
		$a_01_2 = {2f 77 61 74 63 68 64 6f 67 } //1 /watchdog
		$a_01_3 = {57 61 6e 74 65 64 42 79 3d 6d 75 6c 74 69 2d 75 73 65 72 2e 74 61 72 67 65 74 } //1 WantedBy=multi-user.target
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}