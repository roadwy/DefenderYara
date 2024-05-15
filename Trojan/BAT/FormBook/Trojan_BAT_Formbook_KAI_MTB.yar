
rule Trojan_BAT_Formbook_KAI_MTB{
	meta:
		description = "Trojan:BAT/Formbook.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 61 07 11 90 01 01 17 6a 58 07 8e 69 6a 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}