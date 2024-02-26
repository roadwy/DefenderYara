
rule Trojan_BAT_Formbook_XZ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {12 01 28 63 00 00 0a 0c 08 6f 56 00 00 06 00 12 01 28 64 00 00 0a 2d e8 } //00 00 
	condition:
		any of ($a_*)
 
}