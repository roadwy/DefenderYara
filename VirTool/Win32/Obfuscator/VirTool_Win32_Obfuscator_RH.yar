
rule VirTool_Win32_Obfuscator_RH{
	meta:
		description = "VirTool:Win32/Obfuscator.RH,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 3a 5c 4a 48 46 48 47 46 48 47 46 5c 47 48 4a 47 4a 48 47 48 5c 64 67 66 6a 67 68 67 2e 65 78 65 20 2f 6b 73 64 67 66 68 67 68 73 00 } //01 00 
		$a_01_1 = {57 00 48 00 47 00 46 00 4a 00 48 00 47 00 48 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_RH_2{
	meta:
		description = "VirTool:Win32/Obfuscator.RH,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 00 48 00 47 00 46 00 4a 00 48 00 47 00 48 00 00 00 } //01 00 
		$a_01_1 = {8b 44 24 14 33 c6 03 c7 89 44 24 20 89 4c 24 } //01 00 
		$a_03_2 = {8b 4c 24 1c 33 c6 03 c7 3b c8 0f 84 90 01 01 00 00 00 ff 74 24 1c 90 00 } //01 00 
		$a_01_3 = {2d 90 03 01 01 3a 38 31 02 41 83 f9 09 0f 82 } //00 00 
	condition:
		any of ($a_*)
 
}