
rule VirTool_Win32_Obfuscator_ZX{
	meta:
		description = "VirTool:Win32/Obfuscator.ZX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 d2 f7 f7 0f b6 04 2a 0f b6 d1 03 d6 03 c2 25 ff 00 00 00 a3 90 01 04 88 0d 90 00 } //1
		$a_02_1 = {03 cb 81 e1 ff 00 00 00 8a 91 90 01 04 30 14 30 83 c6 01 81 fe 60 ae 0a 00 0f 82 13 ff ff ff 8b 9d f0 fe ff ff 81 c3 00 c0 00 00 ff d3 90 00 } //1
		$a_00_2 = {c6 44 24 0b 6e c6 44 24 0e 33 c6 44 24 0f 32 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}