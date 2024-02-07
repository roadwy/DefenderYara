
rule Trojan_Win32_Sirefef_AB{
	meta:
		description = "Trojan:Win32/Sirefef.AB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4b 54 f3 a4 0f b7 43 14 0f b7 53 06 } //01 00 
		$a_00_1 = {49 4e 42 52 36 34 2e 64 6c 6c 00 41 63 63 65 70 } //00 00  义剂㐶搮汬䄀捣灥
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Sirefef_AB_2{
	meta:
		description = "Trojan:Win32/Sirefef.AB,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4b 54 f3 a4 0f b7 43 14 0f b7 53 06 } //01 00 
		$a_00_1 = {49 4e 42 52 36 34 2e 64 6c 6c 00 41 63 63 65 70 } //00 00  义剂㐶搮汬䄀捣灥
	condition:
		any of ($a_*)
 
}