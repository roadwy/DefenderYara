
rule TrojanDropper_Win32_Sirefef_I{
	meta:
		description = "TrojanDropper:Win32/Sirefef.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 53 77 41 70 e8 90 01 04 3b c3 90 00 } //01 00 
		$a_03_1 = {83 c4 24 89 45 f8 3b c3 74 90 01 01 8b 45 08 8b 00 89 45 90 01 01 8b 06 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_Win32_Sirefef_I_2{
	meta:
		description = "TrojanDropper:Win32/Sirefef.I,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 53 77 41 70 e8 90 01 04 3b c3 90 00 } //01 00 
		$a_03_1 = {83 c4 24 89 45 f8 3b c3 74 90 01 01 8b 45 08 8b 00 89 45 90 01 01 8b 06 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}