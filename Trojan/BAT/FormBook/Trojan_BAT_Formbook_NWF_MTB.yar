
rule Trojan_BAT_Formbook_NWF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NWF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 13 05 07 06 11 05 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 06 11 06 2d cc 90 00 } //01 00 
		$a_81_1 = {72 65 77 6a 6e 67 66 67 72 66 71 65 } //01 00  rewjngfgrfqe
		$a_81_2 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_81_3 = {57 32 33 35 32 35 33 35 33 34 35 } //01 00  W2352535345
		$a_81_4 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //00 00  ColorTranslator
	condition:
		any of ($a_*)
 
}