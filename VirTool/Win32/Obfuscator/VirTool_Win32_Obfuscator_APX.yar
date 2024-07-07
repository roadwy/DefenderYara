
rule VirTool_Win32_Obfuscator_APX{
	meta:
		description = "VirTool:Win32/Obfuscator.APX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 3f 2b d2 81 c2 90 01 04 2b d2 81 c2 90 1b 00 90 02 10 89 7d fc 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_Obfuscator_APX_2{
	meta:
		description = "VirTool:Win32/Obfuscator.APX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 5c 0a 05 83 c1 06 88 58 05 83 c0 06 81 f9 90 01 04 0f 8c 90 00 } //1
		$a_01_1 = {84 c9 74 0c fe c1 88 08 8a 48 01 40 84 c9 75 f4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_APX_3{
	meta:
		description = "VirTool:Win32/Obfuscator.APX,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 54 24 0c 52 6a 40 90 02 18 51 c7 44 24 1c 40 00 00 00 ff d0 90 00 } //9
		$a_03_1 = {2b f6 81 c6 90 01 02 00 00 81 ef 90 1b 00 00 00 46 90 00 } //1
	condition:
		((#a_03_0  & 1)*9+(#a_03_1  & 1)*1) >=10
 
}
rule VirTool_Win32_Obfuscator_APX_4{
	meta:
		description = "VirTool:Win32/Obfuscator.APX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {e8 8b 45 ec 03 45 f0 89 45 ec 90 02 ff 68 90 01 01 34 00 00 e8 90 01 03 ff 90 02 03 8b 90 04 01 02 75 7d ec 90 02 08 81 90 04 01 03 c0 2d c7 90 01 04 90 04 01 02 56 57 90 02 03 90 1b 07 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}