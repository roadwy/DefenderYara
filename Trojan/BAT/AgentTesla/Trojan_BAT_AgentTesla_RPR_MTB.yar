
rule Trojan_BAT_AgentTesla_RPR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 00 74 00 75 00 64 00 69 00 6f 00 61 00 72 00 63 00 2e 00 63 00 6f 00 2e 00 69 00 6e 00 } //1 studioarc.co.in
		$a_01_1 = {56 00 69 00 64 00 65 00 6f 00 73 00 2f 00 61 00 61 00 25 00 64 00 2e 00 65 00 78 00 65 00 } //1 Videos/aa%d.exe
		$a_01_2 = {32 00 72 00 75 00 6e 00 61 00 73 00 } //1 2runas
		$a_01_3 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 explorer.exe
		$a_01_4 = {48 54 54 50 2f 31 2e 31 20 32 30 30 } //1 HTTP/1.1 200
		$a_01_5 = {48 6f 73 74 3a 20 25 73 } //1 Host: %s
		$a_01_6 = {57 69 6e 48 74 74 70 43 6f 6e 6e 65 63 74 } //1 WinHttpConnect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}