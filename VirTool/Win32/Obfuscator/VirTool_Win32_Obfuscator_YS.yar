
rule VirTool_Win32_Obfuscator_YS{
	meta:
		description = "VirTool:Win32/Obfuscator.YS,SIGNATURE_TYPE_PEHSTR_EXT,05 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {03 48 08 ad c1 c8 08 31 d0 ab 83 e9 04 75 f4 6a 04 } //1
		$a_01_1 = {57 8b 72 0c 8b 45 08 03 30 56 e8 5d 00 00 00 83 c2 28 66 49 75 e1 } //1
		$a_01_2 = {8b 4d 10 ad c1 c0 0a 33 45 14 ab 83 e9 04 75 f3 } //1
		$a_01_3 = {50 8b 42 0c 03 45 08 50 e8 57 00 00 00 83 c2 28 66 49 75 e3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}