
rule Trojan_BAT_Formbook_LKIN_MTB{
	meta:
		description = "Trojan:BAT/Formbook.LKIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {07 1a 5a 09 58 08 09 91 9c 00 09 17 58 0d 09 08 8e 69 fe 04 13 04 11 04 2d e0 00 07 17 58 0b 07 06 8e 69 fe 04 13 05 11 05 2d c1 } //00 00 
	condition:
		any of ($a_*)
 
}