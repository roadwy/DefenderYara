
rule VirTool_Win32_Obfuscator_ADH{
	meta:
		description = "VirTool:Win32/Obfuscator.ADH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 50 01 b2 c3 88 50 05 5d c3 90 09 09 00 c6 00 68 8b 15 } //1
		$a_01_1 = {03 51 3c 89 55 e4 8b 45 e4 8b 48 78 03 4d 08 89 4d f8 8b 55 f8 8b 42 24 03 45 08 } //1
		$a_03_2 = {03 48 28 89 0d ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}