
rule Trojan_BAT_Bladabindi_MBHK_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 6c 22 29 0d 0a 73 68 65 6c 6c 2e 52 75 6e 20 47 62 6b 6a 6b 73 6b 62 6e 6d 62 73 73 73 } //1
		$a_01_1 = {64 00 66 00 64 00 66 00 64 00 66 00 67 00 64 00 6a 00 66 00 69 00 64 00 66 00 67 00 69 00 66 00 67 00 64 00 68 00 66 00 67 00 64 00 64 00 66 00 64 00 66 00 } //1 dfdfdfgdjfidfgifgdhfgddfdf
		$a_01_2 = {73 53 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 sS.Resources.resource
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}