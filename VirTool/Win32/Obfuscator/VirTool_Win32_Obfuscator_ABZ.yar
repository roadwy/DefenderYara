
rule VirTool_Win32_Obfuscator_ABZ{
	meta:
		description = "VirTool:Win32/Obfuscator.ABZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 0a 8d 58 01 0f af de 30 1c 02 40 3b c1 7c f2 } //1
		$a_01_1 = {75 f1 68 3f 20 00 00 68 c3 06 00 00 68 28 91 40 00 e8 90 ff ff ff 83 c4 0c b8 28 91 40 00 ff d0 33 c0 5b 8b e5 5d c2 10 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_ABZ_2{
	meta:
		description = "VirTool:Win32/Obfuscator.ABZ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {60 33 c0 f7 f0 61 } //1
		$a_03_1 = {51 ff 75 dc c7 85 ?? fc ff ff 07 00 01 00 ff d0 85 c0 0f 88 } //1
		$a_03_2 = {8b 41 3c 03 45 fc 8d ?? 08 f8 00 00 00 8b ?? 0c 03 45 f8 89 45 cc 8b ?? 08 } //1
		$a_03_3 = {2a 16 30 14 08 ?? 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}