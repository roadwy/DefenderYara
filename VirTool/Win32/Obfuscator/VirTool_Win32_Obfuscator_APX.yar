
rule VirTool_Win32_Obfuscator_APX{
	meta:
		description = "VirTool:Win32/Obfuscator.APX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 3f 2b d2 81 c2 ?? ?? ?? ?? 2b d2 81 c2 90 1b 00 [0-10] 89 7d fc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_Obfuscator_APX_2{
	meta:
		description = "VirTool:Win32/Obfuscator.APX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 5c 0a 05 83 c1 06 88 58 05 83 c0 06 81 f9 ?? ?? ?? ?? 0f 8c } //1
		$a_01_1 = {84 c9 74 0c fe c1 88 08 8a 48 01 40 84 c9 75 f4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_APX_3{
	meta:
		description = "VirTool:Win32/Obfuscator.APX,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 54 24 0c 52 6a 40 [0-18] 51 c7 44 24 1c 40 00 00 00 ff d0 } //9
		$a_03_1 = {2b f6 81 c6 ?? ?? 00 00 81 ef 90 1b 00 00 00 46 } //1
	condition:
		((#a_03_0  & 1)*9+(#a_03_1  & 1)*1) >=10
 
}
rule VirTool_Win32_Obfuscator_APX_4{
	meta:
		description = "VirTool:Win32/Obfuscator.APX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {e8 8b 45 ec 03 45 f0 89 45 ec [0-ff] 68 ?? 34 00 00 e8 ?? ?? ?? ff [0-03] 8b 90 04 01 02 75 7d ec [0-08] 81 [c0-c7] ?? ?? ?? ?? 90 04 01 02 56 57 [0-03] 90 1b 07 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}