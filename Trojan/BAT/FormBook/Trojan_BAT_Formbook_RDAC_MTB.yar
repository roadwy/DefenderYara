
rule Trojan_BAT_Formbook_RDAC_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 1f 16 5d 91 13 07 07 06 07 06 91 11 07 61 11 06 59 20 00 01 00 00 58 d2 9c 06 17 58 0a } //00 00 
	condition:
		any of ($a_*)
 
}