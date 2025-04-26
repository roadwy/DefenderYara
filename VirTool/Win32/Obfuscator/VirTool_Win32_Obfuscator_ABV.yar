
rule VirTool_Win32_Obfuscator_ABV{
	meta:
		description = "VirTool:Win32/Obfuscator.ABV,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 e8 02 33 c2 c1 e8 0a 33 c2 33 c1 } //1
		$a_03_1 = {41 8b c1 99 bb ?? ?? 00 00 f7 fb 81 fa ?? ?? 00 00 75 02 33 c9 45 8b c5 99 bb ?? ?? 00 00 ?? ?? 81 fa ?? ?? 00 00 75 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}