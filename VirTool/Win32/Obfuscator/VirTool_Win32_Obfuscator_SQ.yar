
rule VirTool_Win32_Obfuscator_SQ{
	meta:
		description = "VirTool:Win32/Obfuscator.SQ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8d 8c 11 5c 4a 00 00 83 c4 2c 3b c1 } //1
		$a_01_1 = {8b 0e 3b cf 0f 86 08 00 00 00 49 89 0e e9 } //1
		$a_01_2 = {05 67 06 76 00 3b c1 0f 85 } //1
		$a_01_3 = {c7 45 b6 fa fe 11 fd } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}