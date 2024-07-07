
rule VirTool_Win32_Obfuscator_GI{
	meta:
		description = "VirTool:Win32/Obfuscator.GI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 d2 b9 e8 03 00 00 f7 f1 a3 90 01 02 40 00 90 00 } //1
		$a_03_1 = {8b 55 f0 81 3a 50 45 00 00 74 07 33 c0 e9 90 01 02 00 00 6a 04 68 00 20 00 00 90 00 } //1
		$a_01_2 = {83 7d ec 08 73 39 83 7d ec 04 75 06 83 7d f4 7f 76 2d 83 7d ec 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}