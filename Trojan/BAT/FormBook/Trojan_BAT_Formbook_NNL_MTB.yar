
rule Trojan_BAT_Formbook_NNL_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0e 04 11 02 0e 05 58 03 11 02 04 58 91 02 28 9c 90 01 03 11 03 11 00 5d 91 61 d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}