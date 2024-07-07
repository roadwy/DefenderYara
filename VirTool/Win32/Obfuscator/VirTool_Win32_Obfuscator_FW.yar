
rule VirTool_Win32_Obfuscator_FW{
	meta:
		description = "VirTool:Win32/Obfuscator.FW,SIGNATURE_TYPE_PEHSTR_EXT,07 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {0f c5 ca 04 } //1
		$a_01_1 = {81 f9 2a a0 00 00 0f 85 4b f9 ff ff } //1
		$a_01_2 = {64 8b 05 18 00 00 00 } //1
		$a_01_3 = {64 8b 0d 30 00 00 00 } //1
		$a_01_4 = {8a 42 ff eb } //1
		$a_01_5 = {81 f8 2e 00 00 c0 0f 84 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}
rule VirTool_Win32_Obfuscator_FW_2{
	meta:
		description = "VirTool:Win32/Obfuscator.FW,SIGNATURE_TYPE_PEHSTR_EXT,07 00 03 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 1b 56 ad f6 } //1
		$a_01_1 = {68 c1 09 69 c7 } //1
		$a_01_2 = {66 81 38 4d 5a } //1
		$a_03_3 = {8d 9b 80 00 00 00 90 18 8b 1b 90 00 } //1
		$a_01_4 = {66 8e e8 66 8c e8 } //1
		$a_03_5 = {66 8f 40 16 90 18 0f b7 4b 06 90 00 } //1
		$a_01_6 = {35 da 8c a9 89 } //1
		$a_01_7 = {35 82 fa 50 4b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=3
 
}