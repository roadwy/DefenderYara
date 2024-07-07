
rule VirTool_Win32_Obfuscator_APA{
	meta:
		description = "VirTool:Win32/Obfuscator.APA,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff d2 ab e2 90 04 01 03 a0 2d c0 61 c9 c2 10 00 55 89 e5 56 51 57 90 00 } //1
		$a_03_1 = {e8 00 00 00 00 5b 90 02 40 90 04 01 03 70 2d 7f 06 90 04 01 03 70 2d 7f 04 90 02 40 90 04 01 03 70 2d 7f 06 90 04 01 03 70 2d 7f 04 90 02 7f 64 a1 30 00 00 00 90 02 ff 8b 83 90 01 02 00 00 50 ff 93 90 01 02 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}