
rule Trojan_BAT_Formbook_MBFC_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MBFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 00 6a 00 71 00 6a 00 69 00 70 00 61 00 65 00 69 00 61 00 73 00 64 00 70 00 61 00 77 00 61 00 66 00 66 00 65 00 61 00 66 00 61 00 } //00 00  pjqjipaeiasdpawaffeafa
	condition:
		any of ($a_*)
 
}