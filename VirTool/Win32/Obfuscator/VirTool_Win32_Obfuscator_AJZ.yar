
rule VirTool_Win32_Obfuscator_AJZ{
	meta:
		description = "VirTool:Win32/Obfuscator.AJZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 45 14 ab 83 e9 04 75 f3 6a 04 68 00 30 00 00 ff 75 18 6a 00 ff 93 90 01 04 09 c0 0f 84 90 01 04 89 45 f0 90 00 } //1
		$a_03_1 = {66 8b 48 06 89 c2 81 c2 f8 00 00 00 ff 72 10 8b 42 14 03 45 f0 50 8b 42 0c 03 45 08 50 e8 90 01 01 00 00 00 83 c2 28 66 49 75 e3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}