
rule Trojan_BAT_Formbook_RDY_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {13 0e 11 0e 61 11 0d 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0f 07 11 07 11 0f d2 9c 11 07 17 58 13 07 11 0c 17 58 13 0c } //00 00 
	condition:
		any of ($a_*)
 
}