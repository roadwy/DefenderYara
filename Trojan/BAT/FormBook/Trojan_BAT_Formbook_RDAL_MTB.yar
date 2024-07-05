
rule Trojan_BAT_Formbook_RDAL_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 5b 00 00 0a 13 04 73 5c 00 00 0a 0c 08 11 04 17 } //00 00 
	condition:
		any of ($a_*)
 
}