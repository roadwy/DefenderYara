
rule Trojan_BAT_Spynoon_ASCV_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ASCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 8e 69 17 da 13 0e 16 13 0f 2b 1b 11 06 11 05 11 0f 9a 1f 10 28 ?? 01 00 0a b4 6f ?? 01 00 0a 00 11 0f 17 d6 13 0f 11 0f 11 0e 31 df } //1
		$a_81_1 = {46 69 6e 61 6c 50 72 6f 6a 65 63 74 2e 52 65 73 6f 75 72 63 65 73 } //1 FinalProject.Resources
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}