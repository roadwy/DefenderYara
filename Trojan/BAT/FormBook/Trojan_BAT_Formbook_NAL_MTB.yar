
rule Trojan_BAT_Formbook_NAL_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {00 06 08 06 08 91 07 08 07 8e 69 5d 93 61 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d e1 } //00 00 
	condition:
		any of ($a_*)
 
}