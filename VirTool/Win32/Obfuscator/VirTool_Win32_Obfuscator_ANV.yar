
rule VirTool_Win32_Obfuscator_ANV{
	meta:
		description = "VirTool:Win32/Obfuscator.ANV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 d3 80 fa ?? 88 94 34 ?? ?? 00 00 73 09 fe ca 88 94 34 ?? ?? 00 00 46 } //1
		$a_03_1 = {df e0 f6 c4 41 75 16 68 ?? ?? ?? ?? 6a 00 8d 94 24 ?? ?? 00 00 ff d2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_ANV_2{
	meta:
		description = "VirTool:Win32/Obfuscator.ANV,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 88 00 a0 02 10 80 f1 ?? 80 e9 ?? 88 88 00 a0 02 10 40 3d 00 2c 00 00 72 e6 } //1
		$a_03_1 = {b8 4d 5a 00 00 d9 1d ?? ?? ?? 10 66 39 45 00 74 17 81 3d ?? ?? ?? 10 00 36 00 00 75 07 c6 05 ?? ?? ?? 10 4a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}