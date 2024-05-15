
rule Trojan_BAT_Formbook_KAL_MTB{
	meta:
		description = "Trojan:BAT/Formbook.KAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 06 08 03 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c } //00 00 
	condition:
		any of ($a_*)
 
}