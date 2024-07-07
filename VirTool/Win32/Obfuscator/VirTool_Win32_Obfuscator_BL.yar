
rule VirTool_Win32_Obfuscator_BL{
	meta:
		description = "VirTool:Win32/Obfuscator.BL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f be c1 8a 4a 01 33 c6 42 84 c9 75 90 01 01 5e c2 04 00 90 00 } //1
		$a_00_1 = {68 34 33 32 31 54 } //1 h4321T
		$a_00_2 = {6a 01 68 44 33 22 11 b8 dd cc bb aa ff d0 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule VirTool_Win32_Obfuscator_BL_2{
	meta:
		description = "VirTool:Win32/Obfuscator.BL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 8b 04 24 66 33 c0 68 90 01 04 68 90 01 04 68 90 01 04 68 90 01 04 68 90 01 04 8b fc 66 81 38 4d 5a 75 13 8b 50 90 01 01 81 fa 00 10 00 00 77 08 66 81 3c 10 50 45 74 07 2d 00 00 01 00 eb df 50 8b 74 10 90 01 01 03 f0 83 c6 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule VirTool_Win32_Obfuscator_BL_3{
	meta:
		description = "VirTool:Win32/Obfuscator.BL,SIGNATURE_TYPE_PEHSTR,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 8b 05 30 00 00 00 89 45 fc 8b 45 fc 83 c0 0c 8b 00 83 c0 0c 8b 00 83 c0 18 8b 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}