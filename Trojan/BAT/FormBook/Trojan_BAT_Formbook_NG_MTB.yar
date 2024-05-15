
rule Trojan_BAT_Formbook_NG_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {5d 91 61 07 11 90 01 01 17 58 07 8e 69 5d 91 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Formbook_NG_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 02 26 16 00 0f 00 28 90 01 01 00 00 06 25 26 0f 01 28 90 01 01 00 00 06 25 26 d0 01 00 00 1b 28 90 01 01 00 00 0a 25 26 28 90 01 01 00 00 0a 25 26 a5 01 00 00 1b 0a 38 00 00 00 00 06 2a 90 00 } //01 00 
		$a_01_1 = {57 b5 a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 01 } //01 00 
		$a_01_2 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //00 00  GetDelegateForFunctionPointer
	condition:
		any of ($a_*)
 
}