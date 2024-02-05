
rule VirTool_Win32_Obfuscator_AKK{
	meta:
		description = "VirTool:Win32/Obfuscator.AKK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 80 94 01 00 00 8b 00 8b 89 94 01 00 00 8b 09 8b 40 3c 0f b7 44 01 06 } //01 00 
		$a_03_1 = {8b 8f 8c 01 00 00 53 eb 13 35 90 01 04 05 90 01 04 66 89 01 83 c1 02 83 c2 02 0f b7 02 bb 90 01 04 66 3b c3 75 e0 33 c0 66 89 01 8b 87 8c 01 00 00 90 00 } //01 00 
		$a_03_2 = {8b 86 8c 01 00 00 c1 e7 90 01 01 03 c7 eb 0a 80 f1 90 01 01 80 c1 90 01 01 88 08 40 42 8a 0a 80 f9 90 01 01 75 ef c6 00 00 8b 86 8c 01 00 00 03 c7 90 00 } //01 00 
		$a_00_3 = {e7 } //49 00 
	condition:
		any of ($a_*)
 
}