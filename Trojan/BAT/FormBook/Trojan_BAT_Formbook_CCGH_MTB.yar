
rule Trojan_BAT_Formbook_CCGH_MTB{
	meta:
		description = "Trojan:BAT/Formbook.CCGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0e 04 28 06 00 00 06 00 7e 90 01 04 6f 90 01 01 00 00 0a 05 16 03 8e 69 6f 90 01 01 00 00 0a 0a 06 28 90 01 01 00 00 0a 00 06 0b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}