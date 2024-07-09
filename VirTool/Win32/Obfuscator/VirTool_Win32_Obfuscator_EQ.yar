
rule VirTool_Win32_Obfuscator_EQ{
	meta:
		description = "VirTool:Win32/Obfuscator.EQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ba 24 d6 01 00 01 11 2b 1d ?? ?? ?? ?? 83 c1 48 83 e9 44 } //1
		$a_03_1 = {b8 28 78 00 00 03 3d ?? ?? 40 00 2b 1d ?? ?? 40 00 03 3d ?? ?? 40 00 81 c0 c9 27 00 00 03 3d ?? ?? 40 00 29 01 03 5c 24 20 77 0e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}