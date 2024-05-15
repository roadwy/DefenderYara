
rule Trojan_BAT_Formbook_RDZ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 09 11 0b 61 11 0a 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0c 07 11 04 11 0c d2 9c 11 04 17 58 13 04 } //00 00 
	condition:
		any of ($a_*)
 
}