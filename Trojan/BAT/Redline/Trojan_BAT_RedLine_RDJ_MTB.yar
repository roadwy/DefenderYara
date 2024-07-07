
rule Trojan_BAT_RedLine_RDJ_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 6b 69 61 20 44 65 73 6b 74 6f 70 20 43 6c 69 65 6e 74 } //1 Nokia Desktop Client
		$a_01_1 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
		$a_01_2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_3 = {47 65 74 53 79 73 74 65 6d 4d 65 74 72 69 63 73 } //1 GetSystemMetrics
		$a_01_4 = {75 73 65 72 33 32 } //1 user32
		$a_01_5 = {6b 65 72 6e 65 6c 33 32 } //1 kernel32
		$a_01_6 = {06 07 06 07 93 20 7e 00 00 00 61 02 61 d1 9d } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2) >=8
 
}