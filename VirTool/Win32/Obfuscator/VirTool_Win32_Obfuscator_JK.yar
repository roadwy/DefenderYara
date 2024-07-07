
rule VirTool_Win32_Obfuscator_JK{
	meta:
		description = "VirTool:Win32/Obfuscator.JK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 04 ff b5 70 ff ff ff ff b5 64 ff ff ff ff 15 } //1
		$a_01_1 = {b8 00 04 00 00 31 d2 b9 36 07 03 00 f3 ab 8b 45 0c } //1
		$a_01_2 = {89 79 04 8d 8c 0e 08 02 00 00 c7 45 dc 08 00 00 } //1
		$a_01_3 = {0f b6 3f c1 e1 08 09 f9 c1 e0 08 ff 45 f8 89 4d 0c e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}
rule VirTool_Win32_Obfuscator_JK_2{
	meta:
		description = "VirTool:Win32/Obfuscator.JK,SIGNATURE_TYPE_PEHSTR_EXT,64 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 f2 79 36 18 } //1
		$a_01_1 = {68 33 00 32 00 } //1
		$a_01_2 = {68 23 f9 35 9d } //1
		$a_01_3 = {68 ee 13 4c b6 } //1
		$a_01_4 = {8b 54 01 50 } //1
		$a_01_5 = {81 c4 00 01 00 00 } //1
		$a_01_6 = {66 81 3e 4d 5a } //1
		$a_03_7 = {5f 83 ef 05 55 8b ec 81 c4 90 01 01 ff ff ff 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1) >=8
 
}