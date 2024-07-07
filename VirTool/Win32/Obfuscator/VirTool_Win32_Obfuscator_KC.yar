
rule VirTool_Win32_Obfuscator_KC{
	meta:
		description = "VirTool:Win32/Obfuscator.KC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 03 00 00 "
		
	strings :
		$a_05_0 = {b8 61 c4 74 e7 } //1
		$a_05_1 = {66 81 fa 4d 5a } //1
		$a_05_2 = {3d 04 d0 17 00 } //1
	condition:
		((#a_05_0  & 1)*1+(#a_05_1  & 1)*1+(#a_05_2  & 1)*1) >=1
 
}
rule VirTool_Win32_Obfuscator_KC_2{
	meta:
		description = "VirTool:Win32/Obfuscator.KC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 5c 18 ff 89 1c 28 8b 7c 28 04 8b 74 28 08 8b 4c 28 0c 8b 54 28 10 c1 e9 02 41 ad 03 c2 ab e2 fa } //1
		$a_01_1 = {03 ea 01 2c 24 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}