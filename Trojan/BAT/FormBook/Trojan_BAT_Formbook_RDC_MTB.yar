
rule Trojan_BAT_Formbook_RDC_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 16 13 04 2b 32 00 08 09 11 04 28 ?? ?? ?? ?? 13 05 08 09 11 04 6f 6e 00 00 0a 13 06 11 06 28 6f 00 00 0a 13 07 17 13 08 00 07 06 11 07 d2 9c 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 09 11 09 } //2
		$a_03_1 = {07 28 70 00 00 0a 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 6f 71 00 00 0a 80 ?? ?? ?? ?? 02 13 0b } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}