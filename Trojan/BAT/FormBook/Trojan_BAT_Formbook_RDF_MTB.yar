
rule Trojan_BAT_Formbook_RDF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 11 06 07 8e 69 5d 07 11 06 07 8e 69 5d 91 08 11 06 1f 90 01 01 5d 91 61 28 90 01 04 07 11 06 17 58 07 8e 69 5d 91 28 90 01 04 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 90 00 } //01 00 
		$a_01_1 = {4d 6f 6e 74 65 43 61 72 6c 6f 43 61 72 64 73 } //00 00 
	condition:
		any of ($a_*)
 
}