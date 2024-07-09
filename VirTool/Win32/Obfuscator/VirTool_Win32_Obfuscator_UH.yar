
rule VirTool_Win32_Obfuscator_UH{
	meta:
		description = "VirTool:Win32/Obfuscator.UH,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 c6 66 8b 08 41 31 db bb 02 00 00 00 4b 83 fb 06 75 06 } //1
		$a_03_1 = {29 d9 29 f3 89 5c 24 fc 40 8a 48 ff 3a 0d ?? ?? ?? ?? 75 d3 8a 48 01 3a 0d ?? ?? ?? ?? 75 c8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}