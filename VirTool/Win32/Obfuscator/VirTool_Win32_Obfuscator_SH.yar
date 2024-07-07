
rule VirTool_Win32_Obfuscator_SH{
	meta:
		description = "VirTool:Win32/Obfuscator.SH,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb c2 8b 45 08 03 45 f8 8a 08 2a 4d f4 8b 55 08 03 55 f8 88 0a 8b 45 fc } //1
		$a_01_1 = {8a 00 32 04 11 8b 4d 08 03 4d f8 88 01 e9 } //1
		$a_01_2 = {33 d2 f7 f1 39 55 f0 73 23 8b 45 f0 03 45 fc 33 d2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}