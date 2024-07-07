
rule VirTool_Win32_Obfuscator_XB{
	meta:
		description = "VirTool:Win32/Obfuscator.XB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b f8 83 c4 08 6a 00 68 31 3a 5c 43 89 65 dc 8b 55 dc e8 00 00 00 00 } //1
		$a_01_1 = {89 45 e8 6a 00 68 2e 44 4c 4c 68 45 4c 33 32 68 4b 45 52 4e 54 8b c8 ff d1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}