
rule Trojan_Linux_Prometei_A_MTB{
	meta:
		description = "Trojan:Linux/Prometei.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 74 61 72 74 5f 6d 69 6e 69 6e 67 } //2 start_mining
		$a_00_1 = {73 74 6f 70 5f 6d 69 6e 69 6e 67 } //2 stop_mining
		$a_00_2 = {67 62 37 6e 69 35 72 67 65 65 78 64 63 6e 63 6a 2e 6f 6e 69 6f 6e 2f 63 67 69 2d 62 69 6e 2f 70 72 6f 6d 65 74 65 69 2e 63 67 69 20 } //1 gb7ni5rgeexdcncj.onion/cgi-bin/prometei.cgi 
		$a_00_3 = {2f 2f 6d 6b 68 6b 6a 78 67 63 68 74 66 67 75 37 75 68 6f 66 78 7a 67 6f 61 77 6e 74 66 7a 72 6b 64 63 63 79 6d 76 65 65 6b 74 71 67 70 78 72 70 6a 62 37 32 6f 71 2e 62 33 32 2e 69 32 70 2f 63 67 69 2d 62 69 6e 2f 70 72 6f 6d 65 74 65 69 2e 63 67 69 } //1 //mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.b32.i2p/cgi-bin/prometei.cgi
		$a_00_4 = {63 72 6f 6e 74 61 62 20 74 61 73 6b 2e 63 72 6f 6e } //1 crontab task.cron
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}