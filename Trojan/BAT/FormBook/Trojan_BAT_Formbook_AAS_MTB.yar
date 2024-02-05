
rule Trojan_BAT_Formbook_AAS_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 5d 01 00 70 28 90 01 03 0a 0b 06 07 6f 90 01 03 0a 0c 02 8e 69 8d 90 01 03 01 0d 08 02 16 02 8e 69 09 16 6f 90 01 03 0a 13 04 09 11 04 90 00 } //01 00 
		$a_01_1 = {50 00 61 00 72 00 74 00 30 00 38 00 63 00 30 00 38 00 70 00 61 00 74 00 30 00 38 00 6f 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}