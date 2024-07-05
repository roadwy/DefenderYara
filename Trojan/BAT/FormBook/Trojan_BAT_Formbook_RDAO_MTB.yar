
rule Trojan_BAT_Formbook_RDAO_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {02 07 06 91 11 90 01 01 61 07 06 17 58 09 5d 91 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}