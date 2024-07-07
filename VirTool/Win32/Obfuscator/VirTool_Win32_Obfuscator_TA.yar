
rule VirTool_Win32_Obfuscator_TA{
	meta:
		description = "VirTool:Win32/Obfuscator.TA,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {b9 03 00 00 00 ad 03 c3 ab e2 fa 8b 74 } //1
		$a_01_1 = {8b 4c 24 20 3b c8 75 0a 8b fa ae 75 fd 4f } //1
		$a_01_2 = {33 d2 4a 42 ad 03 c3 6a 00 50 e8 } //1
		$a_01_3 = {6b 65 72 6e 75 d9 81 } //1
		$a_01_4 = {eb 7f b2 08 2a d7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}