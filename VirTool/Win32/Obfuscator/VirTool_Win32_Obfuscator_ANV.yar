
rule VirTool_Win32_Obfuscator_ANV{
	meta:
		description = "VirTool:Win32/Obfuscator.ANV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {32 d3 80 fa 90 01 01 88 94 34 90 01 02 00 00 73 09 fe ca 88 94 34 90 01 02 00 00 46 90 00 } //01 00 
		$a_03_1 = {df e0 f6 c4 41 75 16 68 90 01 04 6a 00 8d 94 24 90 01 02 00 00 ff d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_ANV_2{
	meta:
		description = "VirTool:Win32/Obfuscator.ANV,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 88 00 a0 02 10 80 f1 90 01 01 80 e9 90 01 01 88 88 00 a0 02 10 40 3d 00 2c 00 00 72 e6 90 00 } //01 00 
		$a_03_1 = {b8 4d 5a 00 00 d9 1d 90 01 03 10 66 39 45 00 74 17 81 3d 90 01 03 10 00 36 00 00 75 07 c6 05 90 01 03 10 4a 90 00 } //00 00 
		$a_00_2 = {7e } //15 00 
	condition:
		any of ($a_*)
 
}