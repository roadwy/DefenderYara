
rule Trojan_BAT_Formbook_SIBA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 16 0b 72 90 01 04 0c 00 2b 90 01 01 90 02 06 08 13 90 01 01 16 13 90 01 01 2b 34 11 90 1b 03 11 90 1b 04 6f 90 01 04 13 90 01 01 00 12 90 01 01 28 90 01 04 13 90 01 01 07 17 58 0b 12 90 1b 08 28 90 01 04 13 90 01 01 06 11 90 1b 0e 11 90 1b 0b 6f 90 01 04 0a 00 11 90 1b 04 17 58 13 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}