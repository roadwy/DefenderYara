
rule VirTool_Win32_Obfuscator_WE{
	meta:
		description = "VirTool:Win32/Obfuscator.WE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ba 8c 00 00 00 56 8b 34 d5 ?? ?? ?? ?? 33 f2 8b ca 83 e1 1f c1 c6 04 81 f6 ?? ?? ?? ?? 03 f2 d3 c6 81 f6 ?? ?? ?? ?? d3 c6 81 c6 ?? ?? ?? ?? c1 c6 0e 2b f2 c1 c6 09 89 34 90 90 4a 79 c9 68 ?? ?? ?? ?? ff d0 } //1
		$a_03_1 = {8a 08 33 d2 40 84 c9 74 75 81 f2 ?? ?? ?? ?? 0f b6 c9 c1 c2 0f 33 d1 8a 08 40 84 c9 75 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}