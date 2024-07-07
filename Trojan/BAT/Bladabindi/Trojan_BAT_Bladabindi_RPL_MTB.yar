
rule Trojan_BAT_Bladabindi_RPL_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6d 72 52 6f 62 6f 74 6f } //1 mrRoboto
		$a_01_1 = {42 6f 74 6e 65 74 } //1 Botnet
		$a_01_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 } //1 download
		$a_01_4 = {65 00 78 00 65 00 63 00 75 00 74 00 65 00 } //1 execute
		$a_01_5 = {64 00 65 00 73 00 74 00 72 00 6f 00 79 00 } //1 destroy
		$a_01_6 = {69 00 72 00 63 00 2e 00 66 00 72 00 65 00 65 00 6e 00 6f 00 64 00 65 00 2e 00 6e 00 65 00 74 00 } //1 irc.freenode.net
		$a_01_7 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_8 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_9 = {53 70 65 63 69 61 6c 46 6f 6c 64 65 72 } //1 SpecialFolder
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}