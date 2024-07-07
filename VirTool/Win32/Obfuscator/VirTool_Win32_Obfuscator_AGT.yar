
rule VirTool_Win32_Obfuscator_AGT{
	meta:
		description = "VirTool:Win32/Obfuscator.AGT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {f0 03 00 00 e8 24 00 00 8b 90 01 03 40 00 c7 90 01 01 f4 03 00 00 00 68 88 3f 90 00 } //1
		$a_03_1 = {55 89 e5 60 8b 90 01 02 c7 90 01 01 04 ff 75 18 ff 8b 90 01 02 c7 90 01 01 08 75 14 ff 75 8b 90 01 02 c7 90 01 01 0c 10 ff 75 0c 8b 90 01 02 c7 90 01 01 10 ff 55 08 c9 8b 90 01 02 c7 90 01 01 14 c3 00 00 00 e8 90 01 02 ff ff 90 00 } //1
		$a_03_2 = {c8 03 00 00 00 00 68 d3 8b 90 01 04 00 c7 90 01 01 cc 03 00 00 c7 a7 e8 51 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}