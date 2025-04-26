
rule VirTool_Win32_Obfuscator_JZ{
	meta:
		description = "VirTool:Win32/Obfuscator.JZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c7 02 46 eb 90 14 81 fe ?? ?? ?? ?? 74 90 14 03 7d f8 } //1
		$a_03_1 = {83 c7 02 46 e9 90 16 81 fe ?? ?? ?? ?? 0f 84 90 16 03 7d f8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}