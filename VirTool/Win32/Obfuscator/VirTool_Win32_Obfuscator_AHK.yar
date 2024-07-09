
rule VirTool_Win32_Obfuscator_AHK{
	meta:
		description = "VirTool:Win32/Obfuscator.AHK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 08 00 00 "
		
	strings :
		$a_01_0 = {30 10 40 c1 ca 08 e2 } //1
		$a_01_1 = {c6 02 68 89 42 01 c6 42 05 c3 83 c7 04 e2 } //1
		$a_03_2 = {59 5e 89 c7 f3 a4 8b 75 ?? 8d bb ?? ?? ?? ?? 29 f7 01 f8 ff e0 } //1
		$a_03_3 = {30 c0 fc f3 aa 8b 75 ?? 89 f2 03 56 3c 8d 82 f8 00 00 00 0f b7 4a 06 } //1
		$a_01_4 = {8a 10 80 ca 60 01 d3 d1 e3 03 45 10 8a 08 84 c9 e0 ee } //1
		$a_01_5 = {0f b7 0b 0f b7 6b 02 0f b7 d1 01 f2 66 83 f9 ff 89 6c 24 28 75 08 } //1
		$a_01_6 = {66 01 da 6b d2 03 66 f7 d2 c1 ca 02 89 55 10 30 10 40 c1 ca 08 e2 df } //1
		$a_01_7 = {0f b6 4c 24 13 8b 54 24 30 01 d1 80 79 01 00 8a 11 75 0e 0f b6 ca } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=3
 
}