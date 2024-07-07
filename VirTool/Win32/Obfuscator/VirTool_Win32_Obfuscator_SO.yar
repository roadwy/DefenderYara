
rule VirTool_Win32_Obfuscator_SO{
	meta:
		description = "VirTool:Win32/Obfuscator.SO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 ea 51 81 fa fc 01 00 00 76 22 8b 45 e4 25 ff ff 00 00 b9 06 00 00 00 2b c8 8b c1 99 8b 4d e8 23 c8 8b 45 ec 23 c2 89 0d 14 30 41 00 c7 45 cc 20 0d 01 00 eb } //1
		$a_03_1 = {8b 4d cc 83 e9 01 89 4d cc 83 7d cc 00 0f 90 01 02 00 00 00 8b 4d e8 83 c1 19 8b 75 ec 83 d6 00 8b 45 e4 25 ff 00 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}