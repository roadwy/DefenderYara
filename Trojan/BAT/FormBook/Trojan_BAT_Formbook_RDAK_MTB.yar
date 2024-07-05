
rule Trojan_BAT_Formbook_RDAK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {08 5d 13 0f 07 11 0c 02 07 11 0c 91 11 0e 61 07 11 0f 91 59 } //00 00 
	condition:
		any of ($a_*)
 
}