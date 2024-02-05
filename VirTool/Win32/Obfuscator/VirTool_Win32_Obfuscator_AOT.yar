
rule VirTool_Win32_Obfuscator_AOT{
	meta:
		description = "VirTool:Win32/Obfuscator.AOT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 4d f8 81 c1 90 01 04 88 0d 90 01 04 0f b6 15 90 00 } //01 00 
		$a_03_1 = {03 55 f8 81 ea 90 01 04 88 15 90 01 04 0f b6 05 90 01 04 03 45 f8 90 00 } //01 00 
		$a_03_2 = {2b 45 f8 05 90 01 04 a2 90 01 04 c6 05 90 01 05 0f b6 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_AOT_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AOT,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {85 d2 74 01 46 49 75 f8 90 02 14 8b 1d 90 01 02 90 04 01 03 40 2d 47 00 50 52 ff d3 90 00 } //01 00 
		$a_01_1 = {85 f6 74 01 42 49 75 f8 f8 90 02 14 8b 1d 90 01 02 90 04 01 03 40 2d 47 00 50 56 ff d7 90 00 } //01 00 
		$a_03_2 = {7e 07 03 f1 41 3b ca 7c f9 90 02 30 81 e2 ff 01 00 00 03 c2 90 02 30 ff 15 90 01 04 50 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}