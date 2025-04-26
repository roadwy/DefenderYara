
rule VirTool_Win32_Obfuscator_YG{
	meta:
		description = "VirTool:Win32/Obfuscator.YG,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c1 be 03 00 00 00 f7 f6 85 d2 74 0e 8a 04 19 32 05 f0 c0 43 00 34 77 88 04 19 f6 c1 01 74 0f 8a 14 19 32 15 f0 c0 43 00 80 f2 74 88 14 19 41 81 f9 00 d0 07 00 7c b2 } //1
		$a_01_1 = {b9 89 d0 00 00 be 30 80 40 00 8b fb f3 a5 66 a5 a4 33 c9 8d 9b 00 00 00 00 f6 c1 03 74 0f 8a 14 19 32 15 c0 c5 43 00 80 f2 76 88 14 19 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}