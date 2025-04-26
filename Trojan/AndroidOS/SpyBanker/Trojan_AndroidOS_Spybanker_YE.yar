
rule Trojan_AndroidOS_Spybanker_YE{
	meta:
		description = "Trojan:AndroidOS/Spybanker.YE,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 6a 45 30 57 31 30 6e 64 41 4a 43 54 7a 74 30 74 72 4b 70 30 67 3d 3d } //1 BjE0W10ndAJCTzt0trKp0g==
		$a_01_1 = {5a 6d 74 4b 4f 6a 6c 6d 5a 56 30 6e 4d 57 62 64 70 38 37 31 71 5a 57 33 } //1 ZmtKOjlmZV0nMWbdp871qZW3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}