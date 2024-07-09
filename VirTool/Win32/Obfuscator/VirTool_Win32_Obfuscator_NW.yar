
rule VirTool_Win32_Obfuscator_NW{
	meta:
		description = "VirTool:Win32/Obfuscator.NW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 78 02 52 75 06 80 78 01 45 74 } //1
		$a_03_1 = {8b 44 24 14 8d ?? ?? e8 ?? ff ff ff 03 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}