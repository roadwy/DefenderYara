
rule Backdoor_Linux_Gafgyt_ba_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.ba!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 72 61 77 6c 65 72 2e 61 73 70 } //1 crawler.asp
		$a_00_1 = {44 6f 6e 74 20 55 73 65 20 74 68 65 20 54 65 6c 6e 65 74 20 53 63 61 6e 6e 65 72 } //1 Dont Use the Telnet Scanner
		$a_00_2 = {62 6f 74 6e 65 74 54 53 63 61 6e } //1 botnetTScan
		$a_00_3 = {72 6d 20 2d 72 66 20 2f 74 6d 70 2f 2a 20 2f 76 61 72 2f 2a 20 2f 76 61 72 2f 72 75 6e 2f 2a 20 2f 76 61 72 2f 74 6d 70 2f 2a } //1 rm -rf /tmp/* /var/* /var/run/* /var/tmp/*
		$a_00_4 = {73 65 6e 64 53 54 44 48 45 58 20 } //1 sendSTDHEX 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}
rule Backdoor_Linux_Gafgyt_ba_MTB_2{
	meta:
		description = "Backdoor:Linux/Gafgyt.ba!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {2f 78 35 34 2f 78 35 33 2f 78 36 66 2f 78 37 35 2f 78 37 32 2f 78 36 33 2f 78 36 35 2f 78 32 30 2f 78 34 35 2f 78 36 65 2f 78 36 37 2f 78 36 39 2f 78 36 65 2f 78 36 35 2f 78 32 30 2f 78 35 31 2f 78 37 35 2f 78 36 35 2f 78 37 32 2f 78 37 39 } //1 /x54/x53/x6f/x75/x72/x63/x65/x20/x45/x6e/x67/x69/x6e/x65/x20/x51/x75/x65/x72/x79
		$a_00_1 = {34 36 2e 31 37 2e 34 36 2e 32 32 3a 39 38 33 } //1 46.17.46.22:983
		$a_00_2 = {73 65 72 76 69 63 65 20 69 70 74 61 62 6c 65 73 20 73 74 6f 70 } //1 service iptables stop
		$a_00_3 = {4b 69 6c 6c 44 65 76 69 63 65 } //1 KillDevice
		$a_00_4 = {76 73 65 61 74 74 61 63 6b } //1 vseattack
		$a_00_5 = {53 65 6e 64 48 54 54 50 48 45 58 } //1 SendHTTPHEX
		$a_00_6 = {53 6f 6d 65 6f 6e 65 20 74 72 69 65 64 20 74 6f 20 6b 69 6c 6c 20 74 68 65 20 62 6f 74 73 21 20 43 68 65 63 6b 20 6c 6f 67 73 } //1 Someone tried to kill the bots! Check logs
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}