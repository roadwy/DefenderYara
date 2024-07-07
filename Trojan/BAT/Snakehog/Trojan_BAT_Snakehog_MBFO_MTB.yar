
rule Trojan_BAT_Snakehog_MBFO_MTB{
	meta:
		description = "Trojan:BAT/Snakehog.MBFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {13 04 08 8e 69 17 da 13 06 16 13 05 2b 21 11 04 08 11 05 8f 6e 00 00 01 28 d5 01 } //1
		$a_01_1 = {6c 66 77 68 55 57 5a 6c 6d 46 6e 47 68 44 59 50 75 64 41 4a 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 lfwhUWZlmFnGhDYPudAJ.Resources.resource
		$a_01_2 = {64 65 34 66 75 63 6b 79 6f 75 } //1 de4fuckyou
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}