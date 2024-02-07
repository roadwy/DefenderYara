
rule Trojan_BAT_Formbook_AKF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 06 2b 27 00 07 11 05 11 06 6f 90 01 03 0a 13 07 08 12 07 28 90 01 03 0a 8c 5a 00 00 01 6f 90 01 03 0a 26 00 11 06 17 58 13 06 11 06 07 6f 90 01 03 0a fe 04 13 08 11 08 2d c9 00 11 05 17 58 13 05 11 05 07 6f 90 01 03 0a fe 04 13 09 11 09 2d ac 90 00 } //01 00 
		$a_01_1 = {53 00 61 00 6c 00 65 00 73 00 49 00 6e 00 76 00 65 00 6e 00 74 00 6f 00 72 00 79 00 } //00 00  SalesInventory
	condition:
		any of ($a_*)
 
}