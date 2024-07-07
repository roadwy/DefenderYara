
rule Trojan_BAT_Formbook_MBJZ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MBJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0c 12 02 28 90 01 01 00 00 06 26 07 08 8f 90 01 01 00 00 01 25 4a 17 58 54 12 06 28 90 01 01 00 00 0a 2d da 90 00 } //1
		$a_01_1 = {65 37 32 31 61 63 38 61 62 65 34 34 } //1 e721ac8abe44
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}