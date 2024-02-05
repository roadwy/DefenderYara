
rule Trojan_BAT_Formbook_AWM_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 28 00 08 09 11 04 6f 90 01 03 0a 13 0f 12 0f 28 90 01 03 0a 13 10 07 11 05 11 10 9c 11 05 17 58 13 05 00 11 04 17 58 13 04 11 04 08 6f 90 01 03 0a fe 04 13 11 11 11 2d c8 00 09 17 58 0d 09 08 6f 90 01 03 0a fe 04 13 12 11 12 2d ae 90 00 } //01 00 
		$a_01_1 = {54 00 75 00 72 00 69 00 6e 00 67 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}