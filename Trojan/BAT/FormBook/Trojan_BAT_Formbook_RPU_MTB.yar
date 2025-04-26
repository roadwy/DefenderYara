
rule Trojan_BAT_Formbook_RPU_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 31 00 34 00 32 00 2f 00 [0-30] 2e 00 70 00 6e 00 67 00 } //1
		$a_03_1 = {09 08 11 04 08 8e 69 5d 91 06 11 04 91 61 d2 6f ?? 00 00 0a 11 04 17 58 13 04 11 04 06 8e 69 32 df } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}