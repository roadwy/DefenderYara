
rule VirTool_Win32_Obfuscator_TK{
	meta:
		description = "VirTool:Win32/Obfuscator.TK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 02 89 45 f8 8b 4d 08 03 4d fc 8a 55 f8 88 11 } //1
		$a_03_1 = {8b 46 08 89 45 fc 8b 7e 20 8b 36 80 3f 6b 74 90 01 01 80 3f 4b 74 90 00 } //1
		$a_01_2 = {8b 51 04 83 ea 08 d1 ea 89 55 f4 8b 45 08 83 c0 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}