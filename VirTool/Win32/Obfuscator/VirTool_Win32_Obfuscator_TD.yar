
rule VirTool_Win32_Obfuscator_TD{
	meta:
		description = "VirTool:Win32/Obfuscator.TD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 90 01 04 50 ff 15 90 01 04 89 45 e0 83 7d e0 00 90 00 } //1
		$a_01_1 = {8b 4d f4 8b 91 a4 00 00 00 89 55 fc 8b 45 f4 8b 4d 08 03 88 a0 00 00 00 89 4d e8 8b 55 e8 89 55 e0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}