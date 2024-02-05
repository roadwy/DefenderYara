
rule VirTool_Win32_Obfuscator_BZP{
	meta:
		description = "VirTool:Win32/Obfuscator.BZP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c1 0b 04 04 f6 e9 8a d3 02 d2 02 c2 30 04 3b a1 } //01 00 
		$a_01_1 = {b8 00 f4 12 00 e9 e6 11 00 00 } //01 00 
		$a_00_2 = {78 } //3f 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_BZP_2{
	meta:
		description = "VirTool:Win32/Obfuscator.BZP,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 ea 00 eb 02 03 fe eb 02 2b f9 68 90 01 04 c3 33 d5 c1 e8 00 8b c0 68 90 01 04 c3 90 00 } //01 00 
		$a_01_1 = {8b 55 f8 33 0a 8b 45 f8 89 08 5f 5e 8b e5 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}